import os
import time
import copy
import uuid
import asyncio
from typing import Optional, Dict, Any, List, Set
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel
import requests

from core.config import load_config, get_active_api_key, RUNNINGHUB_API_URL
from core.security import is_key_fatal_error, decrypt_key
from core.http_client import HTTP_SESSION
from core.database import (
    db_get_task, db_save_task, db_update_task,
    db_deduct_user_points, db_refund_user_points, db_load_tasks,
    db_count_user_active_tasks, db_atomic_cancel_and_refund
)
from core.auth import (
    get_current_user_optional, get_user_by_id, update_user_fields
)
from services.key_pool import KEY_POOL_MANAGER
from services.runninghub import (
    ACTIVE_POLL_TASKS, CANCELLED_TASKS, ACTIVE_TASK_PREVIEWS,
    submit_proxy_prompt_async, poll_task_status, listen_websocket_stream, dispatch_queued_task
)

router = APIRouter(tags=["Tasks"])

class GenerateRequest(BaseModel):
    workflowId: Optional[str] = ""
    workflowName: Optional[str] = ""
    positivePrompt: Optional[str] = ""
    negativePrompt: Optional[str] = ""
    nodeInfoList: Optional[List[Dict[str, Any]]] = []
    taskType: Optional[str] = "Standard"
    customPrompt: Optional[Dict[str, Any]] = None


@router.post("/api/generate")
async def generate_task(
    req: GenerateRequest, 
    background_tasks: BackgroundTasks,
    current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    cfg = load_config()
    
    sys_settings = cfg.get("system", {})
    if sys_settings.get("maintenanceMode"):
        if not (current_user and current_user.get("role") == "admin"):
            reason = sys_settings.get("maintenanceReason") or "系统正在例行升级维护中，请稍后再试"
            raise HTTPException(status_code=503, detail=f"【系统维护公告】{reason}")

    # 1. 单用户并发保护：非管理员普通用户同时只允许跑最多 2 个任务，防止霸占全池通道
    if current_user and current_user.get("role") != "admin":
        active_cnt = db_count_user_active_tasks(str(current_user["id"]))
        if active_cnt >= 2:
            raise HTTPException(
                status_code=429,
                detail="您已有 2 个进行中的生成任务，请等待其完成后再提交新任务，保持算力通道畅通"
            )

    is_custom_proxy = bool(req.customPrompt)

    if not is_custom_proxy and not req.workflowId:
        raise HTTPException(status_code=400, detail="缺少必填参数：workflowId")

    # 2. 算力计费与工作流合法性校验（堵死 0 元白嫖漏洞）
    task_cost = 0
    if not is_custom_proxy:
        wf_found = False
        for wf in cfg.get("workflows", []):
            if str(wf.get("id")) == str(req.workflowId):
                task_cost = int(wf.get("pointsCost", 0) or wf.get("cost", 0) or 5)
                if not wf.get("isOfficial"):
                    task_cost = max(5, task_cost)
                elif task_cost < 0:
                    task_cost = 5
                wf_found = True
                break
        if not wf_found:
            raise HTTPException(status_code=400, detail="未配置或不存在的官方工作流，禁止非法提交")
    else:
        # customPrompt 模式：普通用户如果提交自定义 ComfyUI 流程，至少收取标准算力（10点）
        is_admin = bool(current_user and current_user.get("role") == "admin")
        task_cost = 0 if is_admin else 10

    points_deducted = False
    if current_user:
        ok, remaining, msg = db_deduct_user_points(
            user_id=current_user["id"],
            amount=task_cost,
            reason=f"生成任务算力扣减 ({req.workflowName or req.workflowId})"
        )
        if not ok:
            raise HTTPException(status_code=402, detail=f"算力点数不足：本次生成需 {task_cost} 点，您当前账户仅剩 {remaining} 点，请兑换卡密或充值")
        points_deducted = True

    task_type = "Lite" if req.taskType and req.taskType.strip().lower() == "lite" else "Standard"

    temp_id = f"task_{int(time.time())}_{uuid.uuid4().hex[:8]}"
    user_id = current_user["id"] if current_user else ""
    user_name = current_user["username"] if current_user else "匿名访客"

    excluded_key_ids: Set[str] = set()
    real_task_id = None
    net_wss_url = None
    assigned_key_id = None
    assigned_api_key = None

    while True:
        key_info = await KEY_POOL_MANAGER.acquire_free_key(temp_id, exclude_key_ids=excluded_key_ids)
        if not key_info:
            key_info = await KEY_POOL_MANAGER.wait_for_free_key(temp_id, timeout=1.5, exclude_key_ids=excluded_key_ids)

        all_keys = KEY_POOL_MANAGER._get_all_keys()
        remaining_healthy = [
            k for k in all_keys 
            if k.get("id") not in excluded_key_ids and KEY_POOL_MANAGER._states.get(k.get("id"), {}).get("is_healthy", True)
        ]

        if not key_info:
            if not remaining_healthy:
                if points_deducted and current_user:
                    db_refund_user_points(current_user["id"], task_cost, task_id=temp_id, reason="所有算力通道异常自动退还")
                raise HTTPException(status_code=503, detail="所有可用算力通道暂时繁忙或异常，请稍后重试（算力已原路退还）")

            # 优雅排队机制
            queue_task_record = {
                "taskId": temp_id,
                "workflowId": str(req.workflowId),
                "workflowName": req.workflowName or ("本地导入工作流" if is_custom_proxy else f"工作流 {req.workflowId}"),
                "taskType": "Proxy-Native" if is_custom_proxy else task_type,
                "userId": user_id,
                "username": user_name,
                "positivePrompt": req.positivePrompt or "",
                "negativePrompt": req.negativePrompt or "",
                "cost": task_cost if points_deducted else 0,
                "status": "QUEUED",
                "createdAt": int(time.time()),
                "updatedAt": int(time.time()),
                "duration": 0,
                "consumeCoins": "0",
                "outputs": [],
                "nodeInfoList": req.nodeInfoList,
                "keyId": ""
            }
            db_save_task(queue_task_record)
            
            queue_snapshot = KEY_POOL_MANAGER.get_queue_stats()
            queue_pos = queue_snapshot.get("waiters_count", 1)
            
            background_tasks.add_task(
                dispatch_queued_task,
                temp_id, req, current_user, task_cost, is_custom_proxy, task_type
            )
            return {
                "status": "ok",
                "isQueued": True,
                "taskId": temp_id,
                "message": f"当前算力通道繁忙，任务已加入排队队列（当前排在第 {queue_pos} 位），后台正自动等待空闲调度...",
                "task": queue_task_record
            }

        if isinstance(key_info, dict):
            key_id = key_info["keyId"]
            api_key = key_info["apiKey"]
            key_name = key_info["keyName"]
        else:
            key_id, api_key, key_name = key_info[0], key_info[1], key_info[2]

        if is_custom_proxy:
            prompt_dict = copy.deepcopy(req.customPrompt or {})
            for item in req.nodeInfoList:
                nid = str(item.get("nodeId"))
                fname = item.get("fieldName")
                fval = item.get("fieldValue")
                if nid in prompt_dict and "inputs" in prompt_dict[nid]:
                    prompt_dict[nid]["inputs"][fname] = fval

            proxy_payload = {
                "prompt": prompt_dict,
                "client_id": str(uuid.uuid4())
            }

            sub_task_id, last_err = await submit_proxy_prompt_async(api_key, proxy_payload)
            if not sub_task_id:
                if is_key_fatal_error(None, str(last_err)):
                    print(f"[Silent Failover] Key {key_id} ({key_name}) failed in proxy: {last_err}. Isolating and trying next key...")
                    await KEY_POOL_MANAGER.mark_key_unhealthy(key_id, f"原生代理鉴权/风控拒绝: {last_err}")
                    excluded_key_ids.add(key_id)
                    continue
                else:
                    await KEY_POOL_MANAGER.release_key(key_id, temp_id)
                    if points_deducted and current_user:
                        db_refund_user_points(current_user["id"], task_cost, reason=f"原生代理提交失败退还: {last_err}")
                    raise HTTPException(status_code=400, detail=f"提交至云端引擎失败: {last_err}")

            real_task_id = str(sub_task_id)
            assigned_key_id = key_id
            assigned_api_key = api_key
            break

        else:
            payload = {
                "apiKey": api_key,
                "workflowId": str(req.workflowId),
                "taskType": task_type
            }
            if req.nodeInfoList:
                payload["nodeInfoList"] = req.nodeInfoList

            headers = {"Host": "www.runninghub.cn", "Content-Type": "application/json"}
            url = f"{RUNNINGHUB_API_URL}/task/openapi/create"

            try:
                res = await asyncio.to_thread(
                    HTTP_SESSION.post, url, json=payload, headers=headers, timeout=12
                )
                data = res.json()
            except Exception as e:
                await KEY_POOL_MANAGER.release_key(key_id, temp_id)
                if points_deducted and current_user:
                    db_refund_user_points(current_user["id"], task_cost, reason=f"网络请求云端引擎异常: {str(e)}")
                raise HTTPException(status_code=502, detail=f"连接云端算力调度集群异常: {str(e)}")

            code = data.get("code")
            msg = data.get("msg") or "云端未知异常"

            if code != 0:
                if is_key_fatal_error(code, msg):
                    print(f"[Silent Failover] Key {key_id} ({key_name}) fatal error [{code}]: {msg}. Isolating and trying next key...")
                    await KEY_POOL_MANAGER.mark_key_unhealthy(key_id, f"OpenAPI返回致命拒绝 [{code}]: {msg}")
                    excluded_key_ids.add(key_id)
                    continue
                else:
                    await KEY_POOL_MANAGER.release_key(key_id, temp_id)
                    if points_deducted and current_user:
                        db_refund_user_points(current_user["id"], task_cost, reason=f"云端拒绝任务: {msg}")
                    raise HTTPException(status_code=400, detail=f"云端任务提交失败: {msg}")

            real_task_id = str(data.get("data", {}).get("taskId"))
            net_wss_url = data.get("data", {}).get("netWssUrl")
            assigned_key_id = key_id
            assigned_api_key = api_key
            break

    async with KEY_POOL_MANAGER._lock:
        if assigned_key_id in KEY_POOL_MANAGER._states:
            KEY_POOL_MANAGER._states[assigned_key_id]["task_id"] = str(real_task_id)

    # 核心：将 assigned_key_id 固化存入数据库，确保后续取消和轮询始终使用同一个 Key
    task_record = {
        "taskId": str(real_task_id),
        "workflowId": str(req.workflowId),
        "workflowName": req.workflowName or ("本地导入工作流" if is_custom_proxy else f"工作流 {req.workflowId}"),
        "taskType": "Proxy-Native" if is_custom_proxy else task_type,
        "userId": user_id,
        "username": user_name,
        "positivePrompt": req.positivePrompt or "",
        "negativePrompt": req.negativePrompt or "",
        "cost": task_cost if points_deducted else 0,
        "status": "QUEUED",
        "createdAt": int(time.time()),
        "updatedAt": int(time.time()),
        "duration": 0,
        "consumeCoins": "0",
        "outputs": [],
        "nodeInfoList": req.nodeInfoList,
        "keyId": assigned_key_id
    }

    db_save_task(task_record)

    ACTIVE_POLL_TASKS.add(str(real_task_id))
    asyncio.create_task(poll_task_status(str(real_task_id), assigned_api_key, key_id=assigned_key_id))
    if net_wss_url:
        asyncio.create_task(listen_websocket_stream(net_wss_url, str(real_task_id), assigned_api_key))

    return {
        "status": "ok",
        "taskId": str(real_task_id),
        "task": task_record
    }

@router.get("/api/tasks")
async def list_tasks(current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)):
    cfg = load_config()
    api_key = get_active_api_key(cfg)
    
    if current_user:
        user_id_str = str(current_user["id"])
        user_tasks = db_load_tasks(user_id=user_id_str, limit=200)
    else:
        user_tasks = []

    is_admin = bool(current_user and current_user.get("role") == "admin")
    for t in user_tasks:
        tid = str(t.get("taskId"))
        if not is_admin:
            t["outputs"] = [o for o in t.get("outputs", []) if not o.get("userHidden") and not o.get("isTakedown")]
            
        # 实时预览无缝拼装（来自内存高速流，无 SQLite 写放大）
        if tid in ACTIVE_TASK_PREVIEWS and t.get("status") in ["RUNNING", "QUEUED"]:
            preview_item = ACTIVE_TASK_PREVIEWS[tid]
            outs = list(t.get("outputs", []))
            outs = [o for o in outs if not o.get("isRealtimePreview")]
            outs.insert(0, preview_item)
            t["outputs"] = outs

        # 断线自愈恢复：精准绑定创建该任务的具体 Key 发起云端监听
        if t.get("status") in ["RUNNING", "QUEUED"] and tid not in ACTIVE_POLL_TASKS and tid not in CANCELLED_TASKS:
            task_key_id = t.get("keyId")
            poll_api_key = None
            if task_key_id:
                for k in cfg.get("apiKeys", []):
                    if k.get("id") == task_key_id:
                        poll_api_key = decrypt_key(k.get("keyEncrypted"))
                        break
            if not poll_api_key:
                poll_api_key = api_key
            if poll_api_key:
                ACTIVE_POLL_TASKS.add(tid)
                asyncio.create_task(poll_task_status(tid, poll_api_key, key_id=task_key_id))
    
    return user_tasks

@router.get("/api/tasks/{task_id}")
def get_task(task_id: str, current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)):
    t = db_get_task(str(task_id).strip())
    if not t:
        raise HTTPException(status_code=404, detail="任务不存在")
    
    is_admin = bool(current_user and current_user.get("role") == "admin")
    task_owner = str(t.get("userId") or "")
    if task_owner:
        if not current_user:
            raise HTTPException(status_code=404, detail="任务不存在")
        if not is_admin and str(current_user["id"]) != task_owner:
            raise HTTPException(status_code=404, detail="任务不存在")

    tid = str(t.get("taskId"))
    if not is_admin:
        t["outputs"] = [o for o in t.get("outputs", []) if not o.get("userHidden") and not o.get("isTakedown")]
    
    # 实时预览无缝拼装
    if tid in ACTIVE_TASK_PREVIEWS and t.get("status") in ["RUNNING", "QUEUED"]:
        preview_item = ACTIVE_TASK_PREVIEWS[tid]
        outs = list(t.get("outputs", []))
        outs = [o for o in outs if not o.get("isRealtimePreview")]
        outs.insert(0, preview_item)
        t["outputs"] = outs

    return t

@router.post("/api/tasks/{task_id}/cancel")
async def cancel_task_endpoint(task_id: str, current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)):
    task_id_str = str(task_id).strip()
    t = db_get_task(task_id_str)
    if not t:
        raise HTTPException(status_code=404, detail="任务不存在")

    task_owner = str(t.get("userId") or "")
    if task_owner:
        if not current_user:
            raise HTTPException(status_code=403, detail="无权操作此任务")
        if current_user.get("role") != "admin" and str(current_user["id"]) != task_owner:
            raise HTTPException(status_code=403, detail="无权操作其他用户的任务")

    cur_status = str(t.get("status") or "")
    if cur_status in ("SUCCESS", "FAILED", "CANCELLED"):
        return {
            "status": "error",
            "message": f"任务已处于终态 ({cur_status})，不可取消或重复退款"
        }

    CANCELLED_TASKS.add(task_id_str)
    await KEY_POOL_MANAGER.release_key_by_task_id(task_id_str)

    cfg = load_config()
    # 核心：精准提取当初接单的 Key，杜绝跨账号取消导致的云端无感扣费
    task_key_id = t.get("keyId")
    cancel_api_key = None
    if task_key_id:
        for k in cfg.get("apiKeys", []):
            if k.get("id") == task_key_id:
                cancel_api_key = decrypt_key(k.get("keyEncrypted"))
                break
    if not cancel_api_key:
        cancel_api_key = get_active_api_key(cfg)

    cloud_status = "本地已标记取消"
    if cancel_api_key:
        try:
            cancel_url = f"{RUNNINGHUB_API_URL}/task/openapi/cancel"
            headers = {"Host": "www.runninghub.cn", "Content-Type": "application/json"}
            res = await asyncio.to_thread(
                HTTP_SESSION.post,
                cancel_url,
                json={"apiKey": cancel_api_key, "taskId": task_id_str},
                headers=headers,
                timeout=8
            )
            data = res.json()
            cloud_status = data.get("msg") or "已通知 RunningHub 云端取消"
        except Exception as e:
            cloud_status = f"云端取消请求异常: {str(e)}"

    # 原子化取消状态跃迁与幂等退款
    r_ok, refund_msg, new_bal = db_atomic_cancel_and_refund(
        task_id_str,
        reason="用户主动取消任务全额退款"
    )

    if not r_ok:
        return {
            "status": "error",
            "message": refund_msg
        }

    db_update_task(task_id_str, {
        "status": "CANCELLED",
        "error": f"用户已主动取消任务 ({cloud_status})",
        "statusText": "用户已主动取消",
        "updatedAt": int(time.time())
    })
    ACTIVE_TASK_PREVIEWS.pop(task_id_str, None)

    return {
        "status": "ok",
        "message": f"任务已成功取消 ({cloud_status})",
        "detail": refund_msg,
        "newBalance": new_bal
    }
