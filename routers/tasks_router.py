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
from core.security import is_key_fatal_error
from core.http_client import HTTP_SESSION
from core.database import (
    db_get_task, db_save_task, db_update_task,
    db_deduct_user_points, db_refund_user_points, db_load_tasks
)
from core.auth import (
    get_current_user_optional, get_user_by_id, update_user_fields
)
from services.key_pool import KEY_POOL_MANAGER
from services.runninghub import (
    ACTIVE_POLL_TASKS, CANCELLED_TASKS, submit_proxy_prompt_async,
    poll_task_status, listen_websocket_stream, dispatch_queued_task
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

    is_custom_proxy = bool(req.customPrompt)

    if not is_custom_proxy and not req.workflowId:
        raise HTTPException(status_code=400, detail="缺少必填参数：workflowId")

    task_cost = 0
    if not is_custom_proxy:
        for wf in cfg.get("workflows", []):
            if str(wf.get("id")) == str(req.workflowId):
                task_cost = int(wf.get("cost", 0) or wf.get("pointsCost", 0))
                break

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

        if not remaining_healthy:
            if points_deducted and current_user:
                db_refund_user_points(current_user["id"], task_cost, reason="算力调度通道维护全额退款")
            raise HTTPException(
                status_code=503, 
                detail="当前云端算力调度通道正在维护中，已全额退还您的算力点数，请稍后再试"
            )

        if not key_info:
            busy_cnt, total_cnt = KEY_POOL_MANAGER.get_busy_count()
            queue_pos = KEY_POOL_MANAGER.get_queue_stats()["waitingTasks"] + 1
            
            task_record = {
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
                "statusText": f"通道全满（{busy_cnt}/{total_cnt} 运行中），排队第 {queue_pos} 位等待空闲通道",
                "createdAt": int(time.time()),
                "updatedAt": int(time.time()),
                "duration": 0,
                "consumeCoins": "0",
                "outputs": [],
                "nodeInfoList": req.nodeInfoList
            }
            db_save_task(task_record)

            if current_user:
                try:
                    u_info = get_user_by_id(user_id)
                    if u_info:
                        update_user_fields(user_id, {"taskCount": u_info.get("taskCount", 0) + 1})
                except Exception:
                    pass

            asyncio.create_task(dispatch_queued_task(temp_id, req, current_user, task_cost, is_custom_proxy, task_type, excluded_key_ids))

            return {
                "status": "ok",
                "taskId": temp_id,
                "task": task_record,
                "isQueued": True
            }

        key_id, api_key, key_name = key_info

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
                "nodeInfoList": req.nodeInfoList,
                "taskType": task_type
            }
            headers = {"Host": "www.runninghub.cn", "Content-Type": "application/json"}
            try:
                res = await asyncio.to_thread(
                    HTTP_SESSION.post,
                    f"{RUNNINGHUB_API_URL}/task/openapi/create",
                    json=payload,
                    headers=headers,
                    timeout=25
                )
                data = res.json()
            except Exception as e:
                await KEY_POOL_MANAGER.release_key(key_id, temp_id)
                if points_deducted and current_user:
                    db_refund_user_points(current_user["id"], task_cost, reason="调用云端引擎失败全额退款")
                raise HTTPException(status_code=500, detail="连接云端计算引擎超时，请稍后重试")

            code = data.get("code")
            msg = str(data.get("msg") or "")

            if code != 0:
                if is_key_fatal_error(code, msg):
                    print(f"[Silent Failover] Key {key_id} ({key_name}) rejected with code [{code}]: {msg}. Marking unhealthy and silently failing over...")
                    await KEY_POOL_MANAGER.mark_key_unhealthy(key_id, f"云端拒绝任务 [{code}]: {msg}")
                    excluded_key_ids.add(key_id)
                    continue
                else:
                    await KEY_POOL_MANAGER.release_key(key_id, temp_id)
                    if points_deducted and current_user:
                        db_refund_user_points(current_user["id"], task_cost, reason=f"云端拒绝任务退还: {msg}")
                    raise HTTPException(status_code=400, detail=msg or "创建任务失败")

            real_task_id = str(data.get("data", {}).get("taskId"))
            net_wss_url = data.get("data", {}).get("netWssUrl")
            assigned_key_id = key_id
            assigned_api_key = api_key
            break

    async with KEY_POOL_MANAGER._lock:
        if assigned_key_id in KEY_POOL_MANAGER._states:
            KEY_POOL_MANAGER._states[assigned_key_id]["task_id"] = str(real_task_id)

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
        "nodeInfoList": req.nodeInfoList
    }

    db_save_task(task_record)

    if current_user:
        try:
            u_info = get_user_by_id(user_id)
            if u_info:
                update_user_fields(user_id, {"taskCount": u_info.get("taskCount", 0) + 1})
        except Exception:
            pass

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
        if not is_admin:
            t["outputs"] = [o for o in t.get("outputs", []) if not o.get("userHidden") and not o.get("isTakedown")]
        tid = str(t.get("taskId"))
        if api_key and t.get("status") in ["RUNNING", "QUEUED"] and tid not in ACTIVE_POLL_TASKS and tid not in CANCELLED_TASKS:
            ACTIVE_POLL_TASKS.add(tid)
            asyncio.create_task(poll_task_status(tid, api_key))
    
    return user_tasks

@router.get("/api/tasks/{task_id}")
def get_task(task_id: str, current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)):
    t = db_get_task(str(task_id).strip())
    if not t:
        raise HTTPException(status_code=404, detail="任务不存在")
    
    task_owner = str(t.get("userId") or "")
    if task_owner:
        if not current_user:
            raise HTTPException(status_code=404, detail="任务不存在")
        if current_user.get("role") != "admin" and str(current_user["id"]) != task_owner:
            raise HTTPException(status_code=404, detail="任务不存在")
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

    CANCELLED_TASKS.add(task_id_str)
    await KEY_POOL_MANAGER.release_key_by_task_id(task_id_str)

    cfg = load_config()
    api_key = get_active_api_key(cfg)

    cloud_status = "本地已终止"
    if api_key:
        try:
            cancel_url = f"{RUNNINGHUB_API_URL}/task/openapi/cancel"
            headers = {"Host": "www.runninghub.cn", "Content-Type": "application/json"}
            res = await asyncio.to_thread(
                HTTP_SESSION.post,
                cancel_url,
                json={"apiKey": api_key, "taskId": task_id_str},
                headers=headers,
                timeout=8
            )
            data = res.json()
            cloud_status = data.get("msg") or "已通知 RunningHub 云端取消"
        except Exception as e:
            cloud_status = f"云端取消请求异常: {str(e)}"

    cost_val = int(t.get("cost", 0) or 0)
    if task_owner and cost_val > 0 and t.get("status") in ["QUEUED", "RUNNING"]:
        db_refund_user_points(
            user_id=task_owner,
            amount=cost_val,
            task_id=task_id_str,
            reason=f"用户主动取消任务全额退款 ({task_id_str})"
        )
        db_update_task(task_id_str, {"cost": 0})

    db_update_task(task_id_str, {
        "status": "CANCELLED",
        "error": "用户已主动取消任务",
        "statusText": "用户已主动取消",
        "updatedAt": int(time.time())
    })

    return {
        "status": "ok",
        "message": f"任务已成功取消 ({cloud_status})",
        "refundedPoints": cost_val
    }
