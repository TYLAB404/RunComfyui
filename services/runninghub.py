import os
import io
import time
import json
import copy
import uuid
import base64
import asyncio
import urllib.parse
from typing import Dict, Any, Optional, Tuple, Set, List
import aiohttp
import requests
from pydantic import BaseModel

from core.config import RUNNINGHUB_API_URL, load_config, get_active_api_key
from core.security import is_key_fatal_error, decrypt_key
from core.http_client import HTTP_SESSION
from core.database import (
    db_get_task, db_save_task, db_update_task, 
    db_refund_user_points, db_atomic_cancel_and_refund, get_db_connection
)
from services.key_pool import KEY_POOL_MANAGER
from services.imgbed_service import sync_task_outputs_to_imgbed

ACTIVE_POLL_TASKS: Set[str] = set()
CANCELLED_TASKS: Set[str] = set()
# 内存级实时预览缓存（杜绝每秒高频 base64 写入 SQLite 造成写放大与数据库暴涨）
ACTIVE_TASK_PREVIEWS: Dict[str, Dict[str, Any]] = {}

def get_output_fingerprint(item: Dict[str, Any]) -> str:
    """提取产物文件的唯一物理指纹，防止重复展示"""
    url = item.get("url") or item.get("remoteUrl") or ""
    clean = url.split("?")[0].strip()
    if "://" in clean:
        proto, rest = clean.split("://", 1)
        clean = proto + "://" + "/".join(p for p in rest.split("/") if p)
    base = os.path.basename(clean)
    if base and "." in base and not base.startswith("data:"):
        return base
    fname = item.get("filename") or ""
    if fname and "." in fname and not fname.endswith("_preview.png"):
        return fname
    return clean

async def submit_proxy_prompt_async(api_key: str, proxy_payload: Dict[str, Any]) -> Tuple[Optional[str], str]:
    """向 RunningHub 云端 ComfyUI 原生提交 Prompt 任务"""
    hosts = ["www.runninghub.ai", "runninghub.ai"]
    last_err = ""

    def _do_post(url: str, payload: dict) -> Tuple[int, str]:
        try:
            from curl_cffi import requests as c_requests
            r = c_requests.post(url, json=payload, impersonate="chrome120", timeout=25)
            return r.status_code, r.text
        except Exception:
            pass
        try:
            r = HTTP_SESSION.post(url, json=payload, timeout=25)
            return r.status_code, r.text
        except Exception as e:
            return 0, str(e)

    for attempt in range(4):
        for host in hosts:
            p_url = f"https://{host}/proxy/{api_key}/prompt"
            status_code, resp_text = await asyncio.to_thread(_do_post, p_url, proxy_payload)
            if status_code == 200:
                try:
                    p_data = json.loads(resp_text)
                    task_id = p_data.get("prompt_id")
                    if task_id:
                        return str(task_id), ""

                    if "queue_remaining" in resp_text or resp_text.strip() == "{}":
                        last_err = "当前云端原生 ComfyUI 算力通道正在执行前序任务，请稍候约十几秒待出图完毕后再试。"
                        break

                    node_errs = p_data.get("node_errors")
                    err = p_data.get("error")
                    if isinstance(err, dict) and not node_errs:
                        extra_info = err.get("extra_info")
                        if isinstance(extra_info, dict) and extra_info.get("node_errors"):
                            node_errs = extra_info.get("node_errors")

                    err_details_list = []
                    if node_errs and isinstance(node_errs, dict):
                        for nid, nerr in node_errs.items():
                            if isinstance(nerr, dict):
                                err_list = nerr.get("errors", [])
                                ctype = nerr.get("class_type", "")
                                msg_parts = []
                                for e in err_list:
                                    if isinstance(e, dict):
                                        msg_parts.append(e.get("message") or e.get("type") or str(e))
                                    else:
                                        msg_parts.append(str(e))
                                detail_str = f"节点 #{nid} ({ctype}): {', '.join(msg_parts) if msg_parts else json.dumps(nerr, ensure_ascii=False)}"
                                err_details_list.append(detail_str)
                            else:
                                err_details_list.append(f"节点 #{nid}: {str(nerr)}")

                    if err_details_list:
                        combined_detail = "; ".join(err_details_list)
                        return None, f"云端 ComfyUI 节点校验失败: {combined_detail}"

                    if isinstance(err, dict):
                        msg = err.get("message") or err.get("type") or str(err)
                        details = err.get("details", "")
                        return None, f"云端 ComfyUI 校验报错: {msg} {details}".strip()
                    elif err:
                        return None, f"云端 ComfyUI 报错: {err}"

                    last_err = resp_text or "云端返回空响应"
                except Exception:
                    last_err = resp_text
            elif status_code > 0:
                last_err = f"云端服务返回 HTTP {status_code}: {resp_text}"
        await asyncio.sleep(2.5)

    return None, last_err or "云端服务繁忙，请稍后重试"

async def listen_websocket_stream(net_wss_url: str, task_id: str, api_key: str = ""):
    """后台长连接监听 RunningHub 实时 WebSocket 管道并截流进度和预览图"""
    if not net_wss_url:
        return

    parsed = urllib.parse.urlparse(net_wss_url)
    qs = urllib.parse.parse_qs(parsed.query)
    target_url = qs.get("target", [None])[0]
    client_id = qs.get("clientId", [""])[0]
    auth_query = parsed.query

    try:
        async with aiohttp.ClientSession() as session:
            async with session.ws_connect(net_wss_url, timeout=None, ssl=False, heartbeat=20.0) as ws:
                async for msg in ws:
                    if str(task_id) in CANCELLED_TASKS:
                        await ws.close()
                        break
                    if msg.type == aiohttp.WSMsgType.BINARY:
                        if len(msg.data) > 8:
                            img_bytes = msg.data[8:]
                            is_valid_image = len(img_bytes) > 2048 and (
                                img_bytes.startswith(b'\x89PNG\r\n\x1a\n') or
                                img_bytes.startswith(b'\xff\xd8\xff') or
                                img_bytes.startswith(b'GIF8') or
                                (img_bytes.startswith(b'RIFF') and b'WEBP' in img_bytes[:16])
                            )
                            if is_valid_image:
                                b64 = base64.b64encode(img_bytes).decode("ascii")
                                mime = "image/png"
                                if img_bytes.startswith(b'\xff\xd8\xff'):
                                    mime = "image/jpeg"
                                elif img_bytes.startswith(b'GIF8'):
                                    mime = "image/gif"
                                elif b'WEBP' in img_bytes[:16]:
                                    mime = "image/webp"
                                data_url = f"data:{mime};base64,{b64}"
                                # 存入内存高速流，绝不写入 SQLite 避免数据库写放大
                                ACTIVE_TASK_PREVIEWS[str(task_id)] = {
                                    "filename": f"{task_id}_preview.png",
                                    "url": data_url,
                                    "remoteUrl": data_url,
                                    "size": len(img_bytes),
                                    "isRealtime": True,
                                    "isRealtimePreview": True,
                                    "fileType": "image",
                                    "updatedAt": time.time()
                                }

                    elif msg.type == aiohttp.WSMsgType.TEXT:
                        try:
                            payload = json.loads(msg.data)
                            mtype = payload.get("type")
                            mdata = payload.get("data", {})

                            if mtype == "progress":
                                value = mdata.get("value", 0)
                                max_val = mdata.get("max", 1)
                                if max_val > 0:
                                    pct = int((value / max_val) * 100)
                                    node = mdata.get("node")
                                    status_text = f"云端 GPU 正在采样计算 ({pct}%)"
                                    if node:
                                        status_text = f"云端节点 #{node} 正在采样计算 ({pct}%)"
                                    db_update_task(str(task_id), {
                                        "status": "RUNNING",
                                        "statusText": status_text,
                                        "updatedAt": int(time.time())
                                    })
                            elif mtype == "executing":
                                node = mdata.get("node")
                                if node:
                                    db_update_task(str(task_id), {
                                        "status": "RUNNING",
                                        "statusText": f"云端 GPU 正在执行节点 #{node}",
                                        "updatedAt": int(time.time())
                                    })
                            elif mtype == "executed":
                                node_id = str(mdata.get("node", ""))
                                output = mdata.get("output", {})
                                media_items = []
                                if isinstance(output, dict):
                                    for k, v in output.items():
                                        if isinstance(v, list):
                                            for item in v:
                                                if isinstance(item, dict) and ("filename" in item or "cos_url" in item or "url" in item):
                                                    media_items.append(item)
                                
                                for m_info in media_items:
                                    fname = m_info.get("filename", "")
                                    subfolder = m_info.get("subfolder", "")
                                    m_type = m_info.get("type", "temp")
                                    m_format = m_info.get("format", "")
                                    cos_url = m_info.get("cos_url")

                                    is_video = any(fname.lower().endswith(ext) for ext in [".mp4", ".webm", ".mov", ".gif"]) or (cos_url and any(ext in cos_url.lower() for ext in [".mp4", ".webm", ".mov", ".gif"])) or "video" in str(m_format).lower()

                                    view_url = cos_url or m_info.get("url")
                                    if not view_url and fname:
                                        if auth_query:
                                            view_url = f"https://www.runninghub.ai/c_instance/view?filename={fname}&subfolder={subfolder}&type={m_type}&format={m_format}&{auth_query}"
                                        elif api_key:
                                            view_url = f"{RUNNINGHUB_API_URL}/proxy/{api_key}/view?filename={fname}&subfolder={subfolder}&type={m_type}"
                                        elif target_url:
                                            view_url = f"{target_url}/view?filename={fname}&subfolder={subfolder}&type={m_type}&clientId={client_id}"

                                    if view_url:
                                        cur_t = db_get_task(str(task_id))
                                        if cur_t:
                                            outs = cur_t.get("outputs", [])
                                            existing = [o.get("url") for o in outs]
                                            if view_url not in existing:
                                                outs.insert(0, {
                                                    "filename": fname or f"{task_id}_node_{node_id}",
                                                    "url": view_url,
                                                    "remoteUrl": view_url,
                                                    "size": 0,
                                                    "nodeId": node_id,
                                                    "title": f"Node #{node_id} {'截流视频' if is_video else '截流图像'}",
                                                    "isRealtime": True,
                                                    "fileType": "video" if is_video else "image"
                                                })
                                                db_update_task(str(task_id), {"outputs": outs, "updatedAt": int(time.time())})
                        except Exception:
                            pass
                    elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                        break
    except Exception:
        pass

async def poll_task_status(task_id: str, api_key: str, key_id: Optional[str] = None):
    """后台异步轮询 RunningHub 任务执行状态流水"""
    start_time = time.time()
    outputs_url = f"{RUNNINGHUB_API_URL}/task/openapi/outputs"
    headers = {"Host": "www.runninghub.cn", "Content-Type": "application/json"}
    
    ws_started = False
    try:
        while True:
            await asyncio.sleep(2.5)
            if str(task_id) in CANCELLED_TASKS:
                break
            try:
                res = await asyncio.to_thread(
                    HTTP_SESSION.post,
                    outputs_url,
                    json={"apiKey": api_key, "taskId": str(task_id)},
                    headers=headers,
                    timeout=15
                )
                data = res.json()
                code = data.get("code")
                msg = data.get("msg")

                # 813 状态表示云端 GPU 正在分配算力排队中 (此时云端 100% 不计费)
                if code == 813:
                    queue_duration = int(time.time() - start_time)
                    db_update_task(str(task_id), {
                        "status": "QUEUED",
                        "duration": queue_duration,
                        "statusText": f"已接入 GPU 通道 · 云端调度中 ({queue_duration}s · 排队不扣费)",
                        "updatedAt": int(time.time())
                    })

                elif code == 804:
                    run_duration = int(time.time() - start_time)
                    cur_t = db_get_task(str(task_id))
                    cur_text = cur_t.get("statusText", "") if cur_t else ""
                    if "采样" not in cur_text and "节点" not in cur_text and "排队等待" not in cur_text:
                        cur_text = f"云端 GPU 正在计算 ({run_duration}s)"
                    db_update_task(str(task_id), {
                        "status": "RUNNING",
                        "duration": run_duration,
                        "statusText": cur_text,
                        "updatedAt": int(time.time())
                    })

                    if not ws_started and data.get("data"):
                        ws_url = data["data"].get("netWssUrl")
                        if ws_url:
                            ws_started = True
                            asyncio.create_task(listen_websocket_stream(ws_url, str(task_id), api_key))
                
                # 任务执行完毕且有生成结果
                elif code == 0 and data.get("data"):
                    output_items = data["data"]
                    saved_files = []
                    total_coins = "0"
                    for idx, item in enumerate(output_items):
                        file_url = item.get("fileUrl")
                        total_coins = item.get("consumeCoins", total_coins)
                        if file_url:
                            ext = item.get("fileType", "png").lower()
                            is_video = ext in ["mp4", "webm", "mov", "gif"] or any(e in file_url.lower() for e in [".mp4", ".webm", ".mov", ".gif"])
                            filename = f"{task_id}_{idx}.{ext}"
                            
                            saved_files.append({
                                "filename": filename,
                                "url": file_url,
                                "remoteUrl": file_url,
                                "size": 0,
                                "nodeId": str(item.get("nodeId", "")),
                                "fileType": "video" if is_video else "image"
                            })
                    
                    cur_t = db_get_task(str(task_id))
                    existing_files = [f for f in (cur_t.get("outputs", []) if cur_t else []) if not f.get("isRealtimePreview")]
                    seen_fps = set()
                    final_outputs = []
                    for f in saved_files:
                        fp = get_output_fingerprint(f)
                        if fp and fp not in seen_fps:
                            seen_fps.add(fp)
                            final_outputs.append(f)
                    for f in existing_files:
                        fp = get_output_fingerprint(f)
                        if fp and fp not in seen_fps:
                            seen_fps.add(fp)
                            final_outputs.append(f)

                    db_update_task(str(task_id), {
                        "status": "SUCCESS",
                        "duration": int(time.time() - start_time),
                        "consumeCoins": total_coins,
                        "outputs": final_outputs,
                        "statusText": "生成任务已圆满完成",
                        "updatedAt": int(time.time())
                    })
                    ACTIVE_TASK_PREVIEWS.pop(str(task_id), None)
                    asyncio.create_task(sync_task_outputs_to_imgbed(str(task_id)))
                    return
                
                elif code in (803, 804) or "RUNNING" in str(msg) or "QUEUED" in str(msg):
                    db_update_task(str(task_id), {
                        "status": "RUNNING",
                        "duration": int(time.time() - start_time),
                        "updatedAt": int(time.time())
                    })
                else:
                    cur_t = db_get_task(str(task_id))
                    has_captured_real_media = False
                    if cur_t:
                        for o in cur_t.get("outputs", []):
                            if (o.get("isRealtime") and not o.get("isRealtimePreview")) or o.get("remoteUrl"):
                                has_captured_real_media = True
                                break

                    if has_captured_real_media:
                        db_update_task(str(task_id), {
                            "status": "SUCCESS",
                            "duration": int(time.time() - start_time),
                            "statusText": "生成完成 (已安全截流有效成果)",
                            "updatedAt": int(time.time())
                        })
                        ACTIVE_TASK_PREVIEWS.pop(str(task_id), None)
                        asyncio.create_task(sync_task_outputs_to_imgbed(str(task_id)))
                        return
                    else:
                        fail_data = data.get("data")
                        raw_err = str(msg or "")
                        err_msg = raw_err or "任务执行异常"
                        is_timeout = False

                        if code in (806, 807, 810) or any(k in raw_err.lower() for k in ["timeout", "time_out", "超时", "timed out", "timedout"]):
                            is_timeout = True

                        if isinstance(fail_data, dict):
                            failed_reason = fail_data.get("failedReason")
                            if isinstance(failed_reason, dict):
                                exp_msg = str(failed_reason.get("exception_message") or "")
                                if any(k in exp_msg.lower() for k in ["timeout", "time_out", "超时", "timed out"]):
                                    is_timeout = True
                                err_msg = f"云端节点 #{failed_reason.get('node_id', '')} ({failed_reason.get('node_name', '')}) 报错: {exp_msg}"
                            elif isinstance(failed_reason, str):
                                if any(k in failed_reason.lower() for k in ["timeout", "time_out", "超时", "timed out"]):
                                    is_timeout = True
                                err_msg = failed_reason

                        if is_timeout:
                            err_msg = "云端渲染超时：该任务计算量极大，已达到 RunningHub 云端单任务运行上限。系统已为您全额退还扣除的算力点数。"
                            display_status = "云端渲染超时 (已全额退还算力)"
                        elif is_key_fatal_error(code, raw_err) or is_key_fatal_error(code, err_msg):
                            if key_id:
                                asyncio.create_task(KEY_POOL_MANAGER.mark_key_unhealthy(key_id, f"轮询中触发致命熔断 [{code}]: {err_msg}"))
                            err_msg = "云端计算节点异常，已为您全额退还扣除的算力点数。"
                            display_status = "计算节点调度异常 (已全额退还算力)"
                        else:
                            display_status = f"执行失败: {err_msg[:40]}"

                        # 原子化退还扣减的算力点数并更新任务（幂等防护）
                        db_atomic_cancel_and_refund(
                            str(task_id),
                            reason="任务渲染超时/失败全额退还算力"
                        )

                        db_update_task(str(task_id), {
                            "status": "FAILED",
                            "error": err_msg,
                            "statusText": display_status,
                            "duration": int(time.time() - start_time),
                            "updatedAt": int(time.time())
                        })
                        ACTIVE_TASK_PREVIEWS.pop(str(task_id), None)
                        return
            except Exception:
                pass
    finally:
        ACTIVE_POLL_TASKS.discard(str(task_id))
        if key_id:
            await KEY_POOL_MANAGER.release_key(key_id, str(task_id))

async def dispatch_queued_task(
    local_task_id: str, 
    req: Any, 
    current_user: Optional[Dict[str, Any]], 
    task_cost: int, 
    is_custom_proxy: bool, 
    task_type: str,
    excluded_key_ids: Optional[Set[str]] = None
):
    """后台异步排队调度执行器：当通道释放时，自动认领并下发至 RunningHub (支持 100% 无感故障转移)"""
    try:
        excluded = set(excluded_key_ids or [])
        start_wait_time = time.time()
        
        real_task_id = None
        net_wss_url = None
        key_id = None
        api_key = None
        key_name = ""

        while time.time() - start_wait_time < 900.0:
            if local_task_id in CANCELLED_TASKS:
                return

            cfg = load_config()
            preferred_key_id = cfg.get("activeKeyId")
            key_info = await KEY_POOL_MANAGER.wait_for_free_key(local_task_id, timeout=15.0, exclude_key_ids=excluded, preferred_key_id=preferred_key_id)
            
            if local_task_id in CANCELLED_TASKS:
                if key_info:
                    await KEY_POOL_MANAGER.release_key(key_info[0], local_task_id)
                return

            if not key_info:
                all_keys = KEY_POOL_MANAGER._get_all_keys()
                healthy_remain = [k for k in all_keys if k.get("id") not in excluded and KEY_POOL_MANAGER._states.get(k.get("id"), {}).get("is_healthy", True)]
                if not healthy_remain:
                    break
                continue

            key_id, api_key, key_name = key_info
            db_update_task(local_task_id, {
                "statusText": "已成功分配 GPU 算力通道，正在向云端提交渲染任务...",
                "updatedAt": int(time.time())
            })

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
                remote_task_id, last_err = await submit_proxy_prompt_async(api_key, proxy_payload)
                if not remote_task_id:
                    if is_key_fatal_error(None, str(last_err)):
                        print(f"[Silent Failover In Queue] Key {key_id} ({key_name}) failed: {last_err}. Marking unhealthy and trying next key...")
                        await KEY_POOL_MANAGER.mark_key_unhealthy(key_id, f"原生代理鉴权/风控拒绝: {last_err}")
                        excluded.add(key_id)
                        continue
                    else:
                        await KEY_POOL_MANAGER.release_key(key_id, local_task_id)
                        db_atomic_cancel_and_refund(local_task_id, reason=f"原生代理提交失败退还: {last_err}")
                        db_update_task(local_task_id, {
                            "status": "FAILED",
                            "error": str(last_err),
                            "statusText": f"云端原生代理提交失败: {str(last_err)[:40]}",
                            "cost": 0,
                            "updatedAt": int(time.time())
                        })
                        return

                real_task_id = str(remote_task_id)
                net_wss_url = None
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
                    await KEY_POOL_MANAGER.release_key(key_id, local_task_id)
                    await asyncio.sleep(2)
                    continue

                code = data.get("code")
                msg = str(data.get("msg") or "")

                if code != 0:
                    if is_key_fatal_error(code, msg):
                        print(f"[Silent Failover In Queue] Key {key_id} ({key_name}) rejected with [{code}] {msg}. Silently failing over...")
                        await KEY_POOL_MANAGER.mark_key_unhealthy(key_id, f"云端拒绝任务 [{code}]: {msg}")
                        excluded.add(key_id)
                        continue
                    else:
                        await KEY_POOL_MANAGER.release_key(key_id, local_task_id)
                        db_atomic_cancel_and_refund(local_task_id, reason=f"云端拒绝任务退还: {msg}")
                        db_update_task(local_task_id, {
                            "status": "FAILED",
                            "error": msg or "创建任务失败",
                            "statusText": f"任务参数校验未通过: {msg}",
                            "cost": 0,
                            "updatedAt": int(time.time())
                        })
                        return

                real_task_id = str(data.get("data", {}).get("taskId"))
                net_wss_url = data.get("data", {}).get("netWssUrl")
                break

        if not real_task_id:
            db_atomic_cancel_and_refund(local_task_id, reason="通道繁忙排队超时退还算力")
            db_update_task(local_task_id, {
                "status": "FAILED",
                "error": "计算通道繁忙调度超时",
                "statusText": "计算节点繁忙调度超时，已为您全额退还算力点数",
                "cost": 0,
                "updatedAt": int(time.time())
            })
            return

        try:
            with get_db_connection() as conn:
                conn.execute("UPDATE tasks SET task_id = ?, key_id = ? WHERE task_id = ?;", (real_task_id, key_id, local_task_id))
                conn.commit()
        except Exception as e:
            print(f"[Warning] Failed to update task_id {local_task_id} to {real_task_id}: {e}")
        async with KEY_POOL_MANAGER._lock:
            if key_id in KEY_POOL_MANAGER._states:
                KEY_POOL_MANAGER._states[key_id]["task_id"] = real_task_id

        ACTIVE_POLL_TASKS.add(real_task_id)
        asyncio.create_task(poll_task_status(real_task_id, api_key, key_id=key_id))
        if net_wss_url:
            asyncio.create_task(listen_websocket_stream(net_wss_url, real_task_id, api_key))
    except Exception as e:
        print(f"[Dispatch Queued Task Exception] {e}")


async def reconcile_pending_tasks():
    """
    服务重启时启动对账与自愈：
    1. 本地未派发的排队任务（task_前缀）：全额退还算力并标记为失败，避免向云端轮询无效任务。
    2. 已在云端运行的真实任务：恢复 Key 独占占用与轮询监听，防止重启后新任务并发冲撞。
    """
    from core.database import db_load_tasks, db_atomic_cancel_and_refund, db_update_task
    from core.config import get_active_api_key
    from core.security import decrypt_key
    await asyncio.sleep(1.5)
    try:
        pending = db_load_tasks(status="RUNNING", is_admin=True, limit=50) + db_load_tasks(status="QUEUED", is_admin=True, limit=50)
        if pending:
            print(f"[Reconcile] 发现 {len(pending)} 个处于进行中的历史任务，正在恢复云端状态监听与对账...")
            cfg = load_config()
            for t in pending:
                tid = str(t.get("taskId"))
                if not tid or tid in ACTIVE_POLL_TASKS:
                    continue
                
                # 1. 本地排队任务在重启前未成功派发给 RunningHub (本地临时 ID)
                if t.get("status") == "QUEUED" and tid.startswith("task_"):
                    print(f"[Reconcile] 本地排队任务 {tid} 在重启前未派发，执行自动退款与终态清理")
                    try:
                        db_atomic_cancel_and_refund(tid, reason="服务器重启维护，未派发排队任务自动退还算力")
                        db_update_task(tid, {
                            "status": "FAILED",
                            "error": "服务器重启维护，排队任务已自动退还算力",
                            "statusText": "服务器维护重启，未派发的排队任务已全额退还算力",
                            "updatedAt": int(time.time())
                        })
                    except Exception as e:
                        print(f"[Reconcile] 清理本地排队任务 {tid} 失败: {e}")
                    continue

                # 2. 已在云端运行的真实任务，恢复 Key 锁定与轮询
                task_key_id = t.get("keyId")
                api_key = None
                if task_key_id:
                    for k in cfg.get("apiKeys", []):
                        if k.get("id") == task_key_id:
                            api_key = decrypt_key(k.get("keyEncrypted"))
                            break
                if not api_key:
                    api_key = get_active_api_key(cfg)
                if api_key:
                    if task_key_id:
                        await KEY_POOL_MANAGER.mark_key_busy(task_key_id, tid)
                    ACTIVE_POLL_TASKS.add(tid)
                    asyncio.create_task(poll_task_status(tid, api_key, key_id=task_key_id))
    except Exception as e:
        print(f"[Reconcile Error] {e}")


async def execute_task_cancellation(t: Dict[str, Any], is_admin: bool = False) -> Dict[str, Any]:
    """
    统一封装任务取消服务逻辑（供用户前台与管理员后台共同调用，彻底解耦路由层重复逻辑）：
    1. 校验任务状态是否处于可取消态
    2. 标记 CANCELLED_TASKS 并立即释放占用的 Key 池通道
    3. 精准匹配接单 Key 通知 RunningHub 云端中止任务
    4. 执行数据库 ACID 原子状态跃迁与幂等积分退还
    """
    task_id_str = str(t.get("taskId") or "").strip()
    cur_status = str(t.get("status") or "")
    if cur_status in ("SUCCESS", "FAILED", "CANCELLED"):
        return {
            "status": "error",
            "message": f"任务已处于终态 ({cur_status})，不可取消或重复退款"
        }

    CANCELLED_TASKS.add(task_id_str)
    await KEY_POOL_MANAGER.release_key_by_task_id(task_id_str)

    cfg = load_config()
    task_key_id = t.get("keyId")
    cancel_api_key = None
    if task_key_id:
        for k in cfg.get("apiKeys", []):
            if k.get("id") == task_key_id:
                cancel_api_key = decrypt_key(k.get("keyEncrypted"))
                break
    if not cancel_api_key:
        cancel_api_key = get_active_api_key(cfg)

    cloud_status = "已标记本地取消" if is_admin else "本地已标记取消"
    if cancel_api_key and not task_id_str.startswith("task_"):
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
            cloud_status = f"云端取消异常: {str(e)}" if is_admin else f"云端取消请求异常: {str(e)}"

    refund_reason = "管理员强制取消任务全额退款" if is_admin else "用户主动取消任务全额退款"
    r_ok, refund_msg, new_bal = db_atomic_cancel_and_refund(
        task_id_str,
        reason=refund_reason
    )

    if not r_ok:
        return {
            "status": "error",
            "message": refund_msg
        }

    if is_admin:
        db_update_task(task_id_str, {
            "status": "CANCELLED",
            "error": f"管理员后台强制取消 ({cloud_status})",
            "errorMessage": f"管理员后台强制取消 ({cloud_status})",
            "updatedAt": int(time.time()),
        })
    else:
        db_update_task(task_id_str, {
            "status": "CANCELLED",
            "error": f"用户已主动取消任务 ({cloud_status})",
            "statusText": "用户已主动取消",
            "updatedAt": int(time.time()),
        })
    ACTIVE_TASK_PREVIEWS.pop(task_id_str, None)

    resp = {
        "status": "ok",
        "message": f"任务已强制取消 ({cloud_status})" if is_admin else f"任务已成功取消 ({cloud_status})",
        "detail": refund_msg,
        "newBalance": new_bal,
    }
    if is_admin:
        resp["cloudStatus"] = cloud_status
    return resp


