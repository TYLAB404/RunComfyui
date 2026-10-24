import os
import json
import time
import random
import asyncio
import aiohttp
import copy
import urllib.parse
import uuid
import base64
import requests
from typing import Dict, Any, List, Optional, Set, Tuple
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, BackgroundTasks, Request, Depends, Response
from fastapi.responses import FileResponse, RedirectResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from security import encrypt_key, decrypt_key, mask_key, verify_key_with_runninghub
from database import (
    db_save_task, db_update_task, db_load_tasks, db_get_task, db_delete_task,
    db_get_announcements, db_save_announcement, db_update_announcement, db_delete_announcement,
    db_deduct_user_points, db_refund_user_points, db_bump_token_version,
    is_rate_limited, record_failed_attempt, clear_failed_attempts
)
from auth import (
    load_users, save_users, sanitize_user, get_user_by_id, get_user_by_identifier,
    create_user, update_user_fields, set_user_password, delete_user_by_id,
    verify_password, create_jwt_token, decode_jwt_token, verify_turnstile_token
)

app = FastAPI(title="RunningHub Web Controller", version="1.0.0")

# 生产级安全 CORS 配置：严禁 wildcard * 与 allow_credentials=True 混用
_CORS_ORIGINS_ENV = os.getenv("CORS_ORIGINS")
if _CORS_ORIGINS_ENV:
    _ALLOWED_ORIGINS = [o.strip() for o in _CORS_ORIGINS_ENV.split(",") if o.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
else:
    # 默认同源及本地开发环回地址白名单
    app.add_middleware(
        CORSMiddleware,
        allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
OUTPUTS_DIR = os.path.join(BASE_DIR, "outputs")
STATIC_DIR = os.path.join(BASE_DIR, "static")

CONFIG_PATH = os.path.join(DATA_DIR, "config.json")
TASKS_PATH = os.path.join(DATA_DIR, "tasks.json")
RUNNINGHUB_API_URL = "https://www.runninghub.cn"

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(OUTPUTS_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)

# ----------------- 用户实时 SSE 长连接广播中枢 (0 延迟下行推送) -----------------
USER_EVENT_CHANNELS: Dict[str, List[asyncio.Queue]] = {}

async def notify_user(user_id: str, event_type: str, data: Dict[str, Any]):
    """向指定在线用户广播实时下行事件 (0.1秒秒级下发，无感知极速同步)"""
    queues = USER_EVENT_CHANNELS.get(str(user_id), [])
    if not queues:
        return
    msg = json.dumps({"type": event_type, "data": data, "timestamp": int(time.time())}, ensure_ascii=False)
    for q in list(queues):
        try:
            await q.put(msg)
        except Exception:
            pass

# ----------------- 数据加载与保存 -----------------

def load_config() -> Dict[str, Any]:
    cfg = {"activeKeyId": "", "apiKeys": [], "workflows": []}
    needs_save = False
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception:
            cfg = {"activeKeyId": "", "apiKeys": [], "workflows": []}

    if "apiKeys" not in cfg or not isinstance(cfg["apiKeys"], list):
        cfg["apiKeys"] = []

    # 1. 兼容与自动迁移旧版明文 apiKey 字段 -> 落盘加密并移至 apiKeys 密钥池
    legacy_key = cfg.pop("apiKey", None)
    if legacy_key and str(legacy_key).strip():
        legacy_str = str(legacy_key).strip()
        existing = False
        for k in cfg["apiKeys"]:
            if decrypt_key(k.get("keyEncrypted", "")) == legacy_str:
                existing = True
                break
        if not existing:
            new_id = "key_" + uuid.uuid4().hex[:8]
            cfg["apiKeys"].append({
                "id": new_id,
                "name": "默认主密钥",
                "keyEncrypted": encrypt_key(legacy_str),
                "createdAt": int(time.time()),
                "note": "系统自动从旧版明文配置迁移并进行 AES-256 加密落盘"
            })
            if not cfg.get("activeKeyId"):
                cfg["activeKeyId"] = new_id
        needs_save = True

    # 2. 检查 apiKeys 中是否存在遗留明文，强制全部转换为加密密文
    for k in cfg["apiKeys"]:
        if "apiKey" in k:
            plain = k.pop("apiKey")
            if plain:
                k["keyEncrypted"] = encrypt_key(plain)
            needs_save = True
        elif "keyEncrypted" in k:
            enc = k["keyEncrypted"]
            if not enc.startswith("gAAAAA"):
                k["keyEncrypted"] = encrypt_key(enc)
                needs_save = True

    # 3. 激活 Key 兜底维护
    if cfg["apiKeys"]:
        active_ids = [k["id"] for k in cfg["apiKeys"]]
        if cfg.get("activeKeyId") not in active_ids:
            cfg["activeKeyId"] = active_ids[0]
            needs_save = True
    else:
        cfg["activeKeyId"] = ""

    # 4. 系统全局安全、多用户与 Cloudflare Turnstile 配置维护
    if "system" not in cfg or not isinstance(cfg["system"], dict):
        cfg["system"] = {}
        needs_save = True

    sys_cfg = cfg["system"]
    system_defaults = {
        "siteTitle": "RunningHub 智能创作平台",
        "turnstileEnabled": False,
        "turnstileSiteKey": "",
        "turnstileSecretKeyEncrypted": "",
        "allowRegistration": True,
        "defaultUserPoints": 100,
        "requireLoginToGenerate": False,
        "hideAuxiliaryAudioChain": True
    }
    for sk, sv in system_defaults.items():
        if sk not in sys_cfg:
            sys_cfg[sk] = sv
            needs_save = True

    if needs_save:
        save_config(cfg)

    return cfg

def save_config(cfg: Dict[str, Any]):
    """原子化安全落盘：临时文件写入 + fsync + 原子重命名替换，杜绝服务崩溃写出空配置导致密钥丢失"""
    tmp_path = f"{CONFIG_PATH}.tmp.{os.getpid()}_{random.randint(1000, 9999)}"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, CONFIG_PATH)
    except Exception as e:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
        raise e

def get_system_config_safe(cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """返回脱敏的系统全局配置（隐藏 Turnstile 密钥明文）"""
    if cfg is None:
        cfg = load_config()
    sys_cfg = dict(cfg.get("system", {}))
    secret_enc = sys_cfg.pop("turnstileSecretKeyEncrypted", "")
    secret_raw = decrypt_key(secret_enc) if secret_enc else ""
    sys_cfg["turnstileSecretKeyMasked"] = mask_key(secret_raw) if secret_raw else ""
    sys_cfg["hasTurnstileSecret"] = bool(secret_raw)
    return sys_cfg

def get_active_api_key(cfg: Optional[Dict[str, Any]] = None) -> str:
    """获取当前激活的 API Key 明文（解密后仅供后端调用 RunningHub 内部使用，不向前端暴露）"""
    if cfg is None:
        cfg = load_config()
    active_id = cfg.get("activeKeyId")
    api_keys = cfg.get("apiKeys", [])
    for k in api_keys:
        if k.get("id") == active_id:
            return decrypt_key(k.get("keyEncrypted", ""))
    if api_keys:
        return decrypt_key(api_keys[0].get("keyEncrypted", ""))
    return ""

def get_api_keys_safe(cfg: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """向前端返回已彻底脱敏的 Key 列表，杜绝明文或密文在网络传输中暴露"""
    if cfg is None:
        cfg = load_config()
    active_id = cfg.get("activeKeyId")
    safe_list = []
    for k in cfg.get("apiKeys", []):
        raw_key = decrypt_key(k.get("keyEncrypted", ""))
        safe_list.append({
            "id": k.get("id"),
            "name": k.get("name", "未命名密钥"),
            "maskedKey": mask_key(raw_key),
            "createdAt": k.get("createdAt", 0),
            "note": k.get("note", ""),
            "isActive": k.get("id") == active_id
        })
    return safe_list

def load_tasks() -> List[Dict[str, Any]]:
    """从高并发 SQLite 数据库读取任务（支持大并发与事务一致性）"""
    return db_load_tasks(is_admin=True, limit=500)

def save_tasks(tasks: List[Dict[str, Any]]):
    """持久化保存任务至 SQLite"""
    for t in tasks:
        db_save_task(t)

def update_task_record(task_id: str, updates: Dict[str, Any]):
    """原子更新任务状态、输出图像或运行时长"""
    db_update_task(task_id, updates)

def get_output_fingerprint(item: Dict[str, Any]) -> str:
    """提取产物文件的唯一物理指纹（归一化 URL 双斜杠与文件名，杜绝阶段性截流与最终结果重复展示）"""
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

# ----------------- 异步后台实时截流与轮询任务 -----------------

CANCELLED_TASKS = set()

async def listen_websocket_stream(net_wss_url: str, task_id: str, api_key: str = ""):
    """
    后台毫秒级接入 RunningHub 实时 WebSocket 管道：
    在 ComfyUI 运行过程中，只要 Preview Image 或中间图像节点一渲染完成，
    立即在流中截取该图像并落盘保存，完全无需等待整个工作流结束，更不受结尾报错影响！
    """
    if not net_wss_url:
        return

    parsed = urllib.parse.urlparse(net_wss_url)
    qs = urllib.parse.parse_qs(parsed.query)
    target_url = qs.get("target", [None])[0]
    client_id = qs.get("clientId", [""])[0]
    auth_query = parsed.query

    try:
        async with aiohttp.ClientSession() as session:
            # timeout=None 彻底解除人为计时截断，配合 heartbeat=20.0 保活，只要云端在渲染，管道永久开启直到任务自然结束
            async with session.ws_connect(net_wss_url, timeout=None, ssl=False, heartbeat=20.0) as ws:
                preview_count = 0
                async for msg in ws:
                    if str(task_id) in CANCELLED_TASKS:
                        await ws.close()
                        break
                    # 1. 处理二进制图像帧 (ComfyUI WebSocket Preview 流)
                    if msg.type == aiohttp.WSMsgType.BINARY:
                        if len(msg.data) > 8:
                            img_bytes = msg.data[8:]
                            # 严格检验必须为合法的二进制图片头 (PNG, JPEG, GIF, WEBP) 且尺寸大于 2KB
                            is_valid_image = len(img_bytes) > 2048 and (
                                img_bytes.startswith(b'\x89PNG\r\n\x1a\n') or
                                img_bytes.startswith(b'\xff\xd8\xff') or
                                img_bytes.startswith(b'GIF8') or
                                (img_bytes.startswith(b'RIFF') and b'WEBP' in img_bytes[:16])
                            )
                            if not is_valid_image:
                                continue

                            preview_count += 1
                            # 纯内存 Base64 实时预览：零落盘，零硬盘残留
                            b64_str = base64.b64encode(img_bytes).decode('ascii')
                            data_url = f"data:image/png;base64,{b64_str}"

                            # 实时更新到任务 outputs 中（仅保留最新一帧预览，单行原子更新，零写放大）
                            cur_t = db_get_task(str(task_id))
                            if cur_t:
                                outs = [o for o in cur_t.get("outputs", []) if not o.get("isRealtimePreview")]
                                outs.insert(0, {
                                    "filename": f"{task_id}_preview.png",
                                    "url": data_url,
                                    "size": len(img_bytes),
                                    "nodeId": "Preview",
                                    "title": f"实时截流预览 #{preview_count}",
                                    "isRealtime": True,
                                    "isRealtimePreview": True,
                                    "fileType": "image"
                                })
                                update_task_record(str(task_id), {"outputs": outs, "updatedAt": int(time.time())})

                    # 2. 处理 JSON 消息 (ComfyUI 节点执行状态与排队进度)
                    elif msg.type == aiohttp.WSMsgType.TEXT:
                        try:
                            payload = json.loads(msg.data)
                            mtype = payload.get("type")
                            mdata = payload.get("data", {})

                            # 提取实时排队人数信息 (ComfyUI 队列状态)
                            if mtype == "status":
                                queue_remaining = mdata.get("status", {}).get("exec_info", {}).get("queue_remaining")
                                if queue_remaining is not None:
                                    status_text = f"排队等待中 · 前方等待 {queue_remaining} 人" if queue_remaining > 0 else "已进入计算节点渲染"
                                    update_task_record(str(task_id), {
                                        "queueRemaining": queue_remaining,
                                        "statusText": status_text,
                                        "updatedAt": int(time.time())
                                    })

                            # 提取实时采样步数进度 (progress: 当前步 / 总步数)
                            elif mtype == "progress":
                                val = mdata.get("value", 0)
                                mx = mdata.get("max", 1)
                                pct = int((val / mx) * 100) if mx > 0 else 0
                                update_task_record(str(task_id), {
                                    "currentStep": f"{val}/{mx}",
                                    "progressPercent": pct,
                                    "statusText": f"采样计算中 {pct}% ({val}/{mx} 步)",
                                    "updatedAt": int(time.time())
                                })

                            # 提取当前执行节点
                            elif mtype == "executing":
                                node_id = str(mdata.get("node")) if mdata.get("node") is not None else ""
                                if node_id:
                                    update_task_record(str(task_id), {
                                        "currentNodeId": node_id,
                                        "statusText": f"正在执行节点 #{node_id}",
                                        "updatedAt": int(time.time())
                                    })

                            # 节点执行完成通知
                            if mtype == "executed":
                                node_id = str(mdata.get("node"))
                                output = mdata.get("output", {})
                                
                                # 深度提取：无论 ComfyUI 将产出放在 images, videos, gifs 还是任意键中
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

                                    # 判断是视频还是图片
                                    is_video = any(fname.lower().endswith(ext) for ext in [".mp4", ".webm", ".mov", ".gif"]) or (cos_url and any(ext in cos_url.lower() for ext in [".mp4", ".webm", ".mov", ".gif"])) or "video" in str(m_format).lower()

                                    # 纯远端直链模式：直接优先使用 COS 远端直链或官方查看直链，零落盘零中转
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
                                                update_task_record(str(task_id), {"outputs": outs, "updatedAt": int(time.time())})
                        except Exception:
                            pass
                    elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                        break
    except Exception:
        pass


async def poll_task_status(task_id: str, api_key: str):
    """后台异步轮询任务输出，并在完成后单行更新状态与计费流水"""
    start_time = time.time()
    outputs_url = f"{RUNNINGHUB_API_URL}/task/openapi/outputs"
    headers = {"Host": "www.runninghub.cn", "Content-Type": "application/json"}
    
    ws_started = False
    try:
        while True:
            await asyncio.sleep(2.5)
            if str(task_id) in CANCELLED_TASKS:
                # 任务已被用户主动取消，立即退出后台轮询
                break
            try:
                res = await asyncio.to_thread(
                    requests.post,
                    outputs_url,
                    json={"apiKey": api_key, "taskId": str(task_id)},
                    headers=headers,
                    timeout=15
                )
                data = res.json()
                code = data.get("code")
                msg = data.get("msg")

                # 813 状态表示云端排队中
                if code == 813:
                    queue_duration = int(time.time() - start_time)
                    update_task_record(str(task_id), {
                        "status": "QUEUED",
                        "duration": queue_duration,
                        "statusText": f"云端排队调度中 (已等待 {queue_duration}s)",
                        "updatedAt": int(time.time())
                    })

                # 804 状态表示任务进入 RUNNING，启动 WebSocket 实时管道并保持耗时更新
                elif code == 804:
                    run_duration = int(time.time() - start_time)
                    cur_t = db_get_task(str(task_id))
                    cur_text = cur_t.get("statusText", "") if cur_t else ""
                    if "采样" not in cur_text and "节点" not in cur_text and "排队等待" not in cur_text:
                        cur_text = f"云端 GPU 正在计算 ({run_duration}s)"
                    update_task_record(str(task_id), {
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
                    
                    # 智能指纹去重合并：官方直链优先，消除 WebSocket 阶段性截流产生的同节点同文件重复展示
                    cur_t = db_get_task(str(task_id))
                    existing_files = [f for f in (cur_t.get("outputs", []) if cur_t else []) if not f.get("isRealtimePreview")]
                    seen_fps = set()
                    final_outputs = []
                    # 1. 优先存入官方标准产出
                    for f in saved_files:
                        fp = get_output_fingerprint(f)
                        if fp and fp not in seen_fps:
                            seen_fps.add(fp)
                            final_outputs.append(f)
                    # 2. 补充官方列表中未包含的其他节点真实产出 (避免同图重复)
                    for f in existing_files:
                        fp = get_output_fingerprint(f)
                        if fp and fp not in seen_fps:
                            seen_fps.add(fp)
                            final_outputs.append(f)

                    update_task_record(str(task_id), {
                        "status": "SUCCESS",
                        "duration": int(time.time() - start_time),
                        "consumeCoins": total_coins,
                        "outputs": final_outputs,
                        "statusText": "生成任务已圆满完成",
                        "updatedAt": int(time.time())
                    })
                    return
                
                # 正在排队或执行中
                elif code in (803, 804) or "RUNNING" in str(msg) or "QUEUED" in str(msg):
                    update_task_record(str(task_id), {
                        "status": "RUNNING",
                        "duration": int(time.time() - start_time),
                        "updatedAt": int(time.time())
                    })
                else:
                    # 容错截流防护：若已捕获有效媒体输出则视为成功，否则退还算力点数并标记失败
                    cur_t = db_get_task(str(task_id))
                    has_captured_real_media = False
                    if cur_t:
                        for o in cur_t.get("outputs", []):
                            if (o.get("isRealtime") and not o.get("isRealtimePreview")) or o.get("remoteUrl"):
                                has_captured_real_media = True
                                break

                    if has_captured_real_media:
                        update_task_record(str(task_id), {
                            "status": "SUCCESS",
                            "duration": int(time.time() - start_time),
                            "statusText": "生成完成 (已安全截流有效成果)",
                            "updatedAt": int(time.time())
                        })
                        return
                    else:
                        fail_data = data.get("data")
                        err_msg = msg or "任务执行异常"
                        if isinstance(fail_data, dict):
                            failed_reason = fail_data.get("failedReason")
                            if isinstance(failed_reason, dict) and failed_reason.get("exception_message"):
                                err_msg = f"云端节点 #{failed_reason.get('node_id', '')} ({failed_reason.get('node_name', '')}) 报错: {failed_reason.get('exception_message', '')}"

                        # 自动退还用户扣除的算力点数 (P0-5 计费闭环)
                        if cur_t and cur_t.get("userId") and cur_t.get("cost"):
                            cost_val = int(cur_t.get("cost", 0))
                            if cost_val > 0:
                                db_refund_user_points(
                                    user_id=cur_t["userId"],
                                    amount=cost_val,
                                    task_id=str(task_id),
                                    reason=f"任务渲染失败全额退还算力 ({task_id})"
                                )
                                update_task_record(str(task_id), {"cost": 0})

                        update_task_record(str(task_id), {
                            "status": "FAILED",
                            "error": err_msg,
                            "statusText": f"执行失败: {err_msg[:40]}",
                            "duration": int(time.time() - start_time),
                            "updatedAt": int(time.time())
                        })
                        return
            except Exception:
                # 临时网络抖动，继续重试
                pass
    finally:
        ACTIVE_POLL_TASKS.discard(str(task_id))



# ----------------- 用户鉴权依赖与数据模型 -----------------

class RegisterRequest(BaseModel):
    username: str
    email: Optional[str] = ""
    password: str
    turnstileToken: Optional[str] = ""

class LoginRequest(BaseModel):
    identifier: str
    password: str
    turnstileToken: Optional[str] = ""

class ChangePasswordRequest(BaseModel):
    oldPassword: str
    newPassword: str

class AdminUpdateUserRequest(BaseModel):
    role: Optional[str] = None
    points: Optional[int] = None
    isActive: Optional[bool] = None
    newPassword: Optional[str] = None

class AdminSystemConfigRequest(BaseModel):
    siteTitle: Optional[str] = None
    turnstileEnabled: Optional[bool] = None
    turnstileSiteKey: Optional[str] = None
    turnstileSecretKey: Optional[str] = None
    allowRegistration: Optional[bool] = None
    defaultUserPoints: Optional[int] = None
    requireLoginToGenerate: Optional[bool] = None
    hideAuxiliaryAudioChain: Optional[bool] = None

async def get_current_user_optional(request: Request) -> Optional[Dict[str, Any]]:
    """从 Authorization 标头或 Cookie 中解析用户（未登录返回 None）"""
    auth_header = request.headers.get("Authorization")
    token = None
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    if not token:
        token = request.cookies.get("auth_token")
    if not token:
        token = request.query_params.get("token")
    if not token:
        return None
    
    payload = decode_jwt_token(token)
    if not payload or not payload.get("sub"):
        return None
    
    user = get_user_by_id(payload["sub"])
    if not user or not user.get("isActive", True):
        return None

    # 秒级会话吊销门禁：若管理员已停用账号或修改了密码，旧 Token 版本号即刻失配，实现 0.1 秒秒踢
    expected_ver = user.get("token_version", 1)
    token_ver = payload.get("ver", 1)
    if expected_ver != token_ver:
        return None

    return sanitize_user(user)

async def get_current_user(user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)) -> Dict[str, Any]:
    """强制要求用户登录"""
    if not user:
        raise HTTPException(status_code=401, detail="请先登录后再进行此操作")
    return user

async def get_current_admin(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """强制要求管理员权限"""
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="权限不足：仅管理员可以访问此接口")
    return user

# ----------------- API 路由: 认证与用户系统 -----------------

@app.get("/api/auth/public-config")
def get_public_auth_config():
    """面向前端登录注册界面的公开基础配置（无任何私钥敏感数据）"""
    cfg = load_config()
    sys_cfg = cfg.get("system", {})
    users = load_users()
    return {
        "siteTitle": sys_cfg.get("siteTitle", "RunningHub 智能调度中心"),
        "turnstileEnabled": bool(sys_cfg.get("turnstileEnabled", False)),
        "turnstileSiteKey": sys_cfg.get("turnstileSiteKey", ""),
        "allowRegistration": bool(sys_cfg.get("allowRegistration", True)),
        "requireLoginToGenerate": bool(sys_cfg.get("requireLoginToGenerate", False)),
        "isFirstUser": len(users) == 0
    }

@app.post("/api/auth/register")
async def register_user(req: RegisterRequest, request: Request, response: Response):
    cfg = load_config()
    sys_cfg = cfg.get("system", {})
    if not sys_cfg.get("allowRegistration", True):
        raise HTTPException(status_code=403, detail="管理员已关闭新用户注册通道")
    
    username = req.username.strip()
    if len(username) < 3 or len(username) > 30:
        raise HTTPException(status_code=400, detail="用户名长度需在 3 到 30 个字符之间")
    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="密码长度不能少于 6 位")
    
    # Cloudflare Turnstile 验证
    if sys_cfg.get("turnstileEnabled"):
        secret_enc = sys_cfg.get("turnstileSecretKeyEncrypted", "")
        secret_key = decrypt_key(secret_enc) if secret_enc else ""
        if secret_key:
            client_ip = request.client.host if request.client else ""
            ok, msg = await verify_turnstile_token(req.turnstileToken, secret_key, client_ip)
            if not ok:
                raise HTTPException(status_code=400, detail=msg)
    
    default_points = sys_cfg.get("defaultUserPoints", 100)
    try:
        user = create_user(
            username=username,
            email=req.email or "",
            password=req.password,
            role="user",
            points=default_points
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    token = create_jwt_token({
        "sub": user["id"],
        "username": user["username"],
        "role": user["role"],
        "ver": user.get("token_version", 1)
    })
    
    is_secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    response.set_cookie(key="auth_token", value=token, httponly=True, max_age=86400 * 7, samesite="lax", secure=is_secure)
    return {
        "status": "ok",
        "token": token,
        "user": sanitize_user(user),
        "isFirstAdmin": user["role"] == "admin",
        "message": "🎉 欢迎！作为系统首位用户，您已自动获得超级管理员权限！" if user["role"] == "admin" else "注册成功，欢迎加入！"
    }

@app.post("/api/auth/login")
async def login_user(req: LoginRequest, request: Request, response: Response):
    cfg = load_config()
    sys_cfg = cfg.get("system", {})
    
    client_ip = request.client.host if request.client else "unknown"
    rate_key = f"{client_ip}:{req.identifier.strip().lower()}"
    if is_rate_limited(rate_key):
        raise HTTPException(status_code=429, detail="密码连续错误次数过多，账户已被临时锁定 15 分钟以防暴力破解，请稍后再试")
    
    # Cloudflare Turnstile 验证
    if sys_cfg.get("turnstileEnabled"):
        secret_enc = sys_cfg.get("turnstileSecretKeyEncrypted", "")
        secret_key = decrypt_key(secret_enc) if secret_enc else ""
        if secret_key:
            ok, msg = await verify_turnstile_token(req.turnstileToken, secret_key, client_ip)
            if not ok:
                raise HTTPException(status_code=400, detail=msg)
    
    user = get_user_by_identifier(req.identifier)
    if not user:
        record_failed_attempt(rate_key)
        raise HTTPException(status_code=400, detail="用户名或邮箱不存在")
    if not user.get("isActive", True):
        raise HTTPException(status_code=403, detail="该账户已被管理员停用封禁，请联系管理员")
    
    if not verify_password(req.password, user.get("passwordHash", ""), user.get("salt", "")):
        record_failed_attempt(rate_key)
        raise HTTPException(status_code=400, detail="密码错误，请重新输入")
    
    clear_failed_attempts(rate_key)
    update_user_fields(user["id"], {"lastLogin": int(time.time())})
    user["lastLogin"] = int(time.time())
    
    token = create_jwt_token({
        "sub": user["id"],
        "username": user["username"],
        "role": user["role"],
        "ver": user.get("token_version", 1)
    })
    is_secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    response.set_cookie(key="auth_token", value=token, httponly=True, max_age=86400 * 7, samesite="lax", secure=is_secure)
    return {
        "status": "ok",
        "token": token,
        "user": sanitize_user(user)
    }

@app.get("/api/auth/me")
def get_me(user: Dict[str, Any] = Depends(get_current_user)):
    fresh = get_user_by_id(user["id"])
    if not fresh:
        raise HTTPException(status_code=404, detail="用户不存在")
    return sanitize_user(fresh)

@app.get("/api/events/user")
async def user_events_stream(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """用户长连接实时下行 SSE 事件通道 (秒级停用踢出、实时算力到账同步)"""
    user_id = str(current_user["id"])
    queue = asyncio.Queue()
    USER_EVENT_CHANNELS.setdefault(user_id, []).append(queue)

    async def event_generator():
        try:
            # 建立长连接时即刻下发当前会话状态
            yield f"data: {json.dumps({'type': 'CONNECTED', 'data': {'userId': user_id, 'points': current_user.get('points', 0)}})}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    # 等待下行事件或 15 秒心跳保活
                    msg = await asyncio.wait_for(queue.get(), timeout=15.0)
                    yield f"data: {msg}\n\n"
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
        finally:
            if user_id in USER_EVENT_CHANNELS:
                try:
                    USER_EVENT_CHANNELS[user_id].remove(queue)
                    if not USER_EVENT_CHANNELS[user_id]:
                        del USER_EVENT_CHANNELS[user_id]
                except Exception:
                    pass

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )

@app.post("/api/auth/logout")
def logout_user(response: Response):
    response.delete_cookie(key="auth_token")
    return {"status": "ok", "message": "已成功退出登录"}

@app.post("/api/auth/change-password")
def change_user_password(req: ChangePasswordRequest, user: Dict[str, Any] = Depends(get_current_user)):
    full_user = get_user_by_id(user["id"])
    if not full_user:
        raise HTTPException(status_code=404, detail="用户不存在")
    if not verify_password(req.oldPassword, full_user.get("passwordHash", ""), full_user.get("salt", "")):
        raise HTTPException(status_code=400, detail="当前原密码不正确")
    if len(req.newPassword) < 6:
        raise HTTPException(status_code=400, detail="新密码长度不能少于 6 位")
    set_user_password(user["id"], req.newPassword)
    return {"status": "ok", "message": "密码修改成功，请牢记新密码"}

# ----------------- API 路由: 开发者后台管理 -----------------

@app.get("/api/admin/overview")
def admin_overview(_: Dict[str, Any] = Depends(get_current_admin)):
    users = load_users()
    tasks = load_tasks()
    cfg = load_config()
    sys_cfg = cfg.get("system", {})
    
    now = time.time()
    today_tasks = [t for t in tasks if t.get("createdAt", 0) >= now - 86400]
    success_tasks = [t for t in tasks if t.get("status") == "SUCCESS"]
    failed_tasks = [t for t in tasks if t.get("status") == "FAILED"]
    total_coins = sum(float(t.get("consumeCoins", 0) or 0) for t in tasks)
    
    secret_enc = sys_cfg.get("turnstileSecretKeyEncrypted", "")
    secret_raw = decrypt_key(secret_enc) if secret_enc else ""
    
    return {
        "totalUsers": len(users),
        "adminCount": sum(1 for u in users if u.get("role") == "admin"),
        "activeUsers": sum(1 for u in users if u.get("isActive", True)),
        "totalTasks": len(tasks),
        "todayTasks": len(today_tasks),
        "successTasks": len(success_tasks),
        "failedTasks": len(failed_tasks),
        "totalCoinsUsed": round(total_coins, 2),
        "turnstileEnabled": bool(sys_cfg.get("turnstileEnabled")),
        "turnstileConfigured": bool(secret_raw and sys_cfg.get("turnstileSiteKey")),
        "turnstileSiteKey": sys_cfg.get("turnstileSiteKey", ""),
        "activeKeyMasked": mask_key(get_active_api_key(cfg)),
        "serverTime": int(now)
    }

@app.get("/api/admin/users")
def admin_list_users(_: Dict[str, Any] = Depends(get_current_admin)):
    users = load_users()
    tasks = load_tasks()
    task_counts = {}
    for t in tasks:
        uid = t.get("userId")
        if uid:
            task_counts[uid] = task_counts.get(uid, 0) + 1
    
    result = []
    for u in users:
        safe = sanitize_user(u)
        safe["taskCount"] = task_counts.get(u["id"], u.get("taskCount", 0))
        result.append(safe)
    result.sort(key=lambda x: x.get("createdAt", 0), reverse=True)
    return result

class AdminResetPasswordRequest(BaseModel):
    newPassword: str

@app.put("/api/admin/users/{user_id}")
async def admin_update_user(user_id: str, req: AdminUpdateUserRequest, admin: Dict[str, Any] = Depends(get_current_admin)):
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    
    updates = {}
    if req.role is not None:
        if req.role not in ("admin", "user"):
            raise HTTPException(status_code=400, detail="角色必须是 admin 或 user")
        if user_id == admin["id"] and req.role != "admin":
            users = load_users()
            admins = [u for u in users if u.get("role") == "admin"]
            if len(admins) <= 1:
                raise HTTPException(status_code=400, detail="系统必须保留至少一位管理员，无法降级自身")
        updates["role"] = req.role
    
    points_changed = False
    if req.points is not None:
        new_pts = max(0, int(req.points))
        if new_pts != user.get("points", 0):
            updates["points"] = new_pts
            points_changed = True

    is_deactivating = False
    if req.isActive is not None:
        if user_id == admin["id"] and not req.isActive:
            raise HTTPException(status_code=400, detail="不能封禁当前登录的管理员账号")
        if not req.isActive and user.get("isActive", True):
            is_deactivating = True
        updates["isActive"] = bool(req.isActive)
    
    if updates:
        update_user_fields(user_id, updates)
    
    pwd_changed = False
    if req.newPassword and len(req.newPassword.strip()) >= 6:
        set_user_password(user_id, req.newPassword.strip())
        pwd_changed = True
    
    fresh = get_user_by_id(user_id)

    # 核心：实时 SSE 下发，真正实现 0.1 秒秒踢与算力余额原地跳变
    if is_deactivating:
        await notify_user(
            user_id=user_id,
            event_type="KICK_OFF",
            data={"reason": "您的账户已被管理员停用，已强制下线"}
        )
    elif pwd_changed:
        await notify_user(
            user_id=user_id,
            event_type="KICK_OFF",
            data={"reason": "管理员已修改您的密码凭据，请重新登录"}
        )
    elif points_changed and fresh:
        await notify_user(
            user_id=user_id,
            event_type="POINTS_UPDATED",
            data={"points": fresh.get("points", 0), "reason": "管理员在后台更新了您的算力点数"}
        )

    return {"status": "ok", "user": sanitize_user(fresh)}

@app.post("/api/admin/users/{user_id}/reset-password")
async def admin_reset_user_password(
    user_id: str,
    req: AdminResetPasswordRequest,
    admin: Dict[str, Any] = Depends(get_current_admin)
):
    if len(req.newPassword.strip()) < 6:
        raise HTTPException(status_code=400, detail="新密码不能少于 6 位")
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    set_user_password(user_id, req.newPassword.strip())
    # 实时通知被重置密码的用户秒退
    await notify_user(
        user_id=user_id,
        event_type="KICK_OFF",
        data={"reason": "管理员已重置您的登录密码，请使用新密码重新登录"}
    )
    return {"status": "ok"}

@app.delete("/api/admin/users/{user_id}")
async def admin_delete_user(user_id: str, admin: Dict[str, Any] = Depends(get_current_admin)):
    if user_id == admin["id"]:
        raise HTTPException(status_code=400, detail="无法删除当前正在登录的管理员账号")
    
    target = get_user_by_id(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="用户不存在")
    
    await notify_user(
        user_id=user_id,
        event_type="KICK_OFF",
        data={"reason": "您的账号已被管理员注销，会话已终止"}
    )
    delete_user_by_id(user_id)
    return {"status": "ok", "message": f"用户 {target.get('username')} 已被安全删除"}

@app.get("/api/admin/system")
def admin_get_system_config(_: Dict[str, Any] = Depends(get_current_admin)):
    return get_system_config_safe()

@app.post("/api/admin/system")
@app.put("/api/admin/system")
def admin_update_system_config(req: AdminSystemConfigRequest, _: Dict[str, Any] = Depends(get_current_admin)):
    cfg = load_config()
    sys_cfg = cfg.setdefault("system", {})
    
    if req.siteTitle is not None:
        sys_cfg["siteTitle"] = req.siteTitle.strip()
    if req.turnstileEnabled is not None:
        sys_cfg["turnstileEnabled"] = bool(req.turnstileEnabled)
    if req.turnstileSiteKey is not None:
        raw_site = req.turnstileSiteKey.strip()
        if raw_site.count("0x") >= 2 and len(raw_site) > 60:
            parts = raw_site.split("0x")
            if len(parts) >= 3 and parts[1] == parts[2]:
                raw_site = "0x" + parts[1]
        sys_cfg["turnstileSiteKey"] = raw_site
    if req.turnstileSecretKey is not None and req.turnstileSecretKey.strip():
        raw_secret = req.turnstileSecretKey.strip()
        if raw_secret.count("0x") >= 2 and len(raw_secret) > 60:
            parts = raw_secret.split("0x")
            if len(parts) >= 3 and parts[1] == parts[2]:
                raw_secret = "0x" + parts[1]
        if not raw_secret.startswith("****") and "****" not in raw_secret:
            sys_cfg["turnstileSecretKeyEncrypted"] = encrypt_key(raw_secret)
    if req.allowRegistration is not None:
        sys_cfg["allowRegistration"] = bool(req.allowRegistration)
    if req.defaultUserPoints is not None:
        sys_cfg["defaultUserPoints"] = max(0, int(req.defaultUserPoints))
    if req.requireLoginToGenerate is not None:
        sys_cfg["requireLoginToGenerate"] = bool(req.requireLoginToGenerate)
    if req.hideAuxiliaryAudioChain is not None:
        sys_cfg["hideAuxiliaryAudioChain"] = bool(req.hideAuxiliaryAudioChain)
    
    save_config(cfg)
    safe_data = get_system_config_safe(cfg)
    safe_data["status"] = "ok"
    return safe_data

# ----------------- API 路由: 公告与通知系统 -----------------

class AnnouncementCreateRequest(BaseModel):
    title: str
    content: str
    tag: Optional[str] = "官方公告"
    isActive: Optional[bool] = True

class AnnouncementUpdateRequest(BaseModel):
    title: Optional[str] = None
    content: Optional[str] = None
    tag: Optional[str] = None
    isActive: Optional[bool] = None

@app.get("/api/announcements")
def get_public_announcements():
    """面向前台普通用户的活跃公告列表"""
    return db_get_announcements(active_only=True)

@app.get("/api/admin/announcements")
def get_admin_announcements(_: Dict[str, Any] = Depends(get_current_admin)):
    """管理员全量公告列表（包括停用的）"""
    return db_get_announcements(active_only=False)

@app.post("/api/admin/announcements")
def create_admin_announcement(req: AnnouncementCreateRequest, _: Dict[str, Any] = Depends(get_current_admin)):
    if not req.title.strip():
        raise HTTPException(status_code=400, detail="公告标题不能为空")
    if not req.content.strip():
        raise HTTPException(status_code=400, detail="公告内容不能为空")
    return db_save_announcement(
        title=req.title,
        content=req.content,
        tag=req.tag or "官方公告",
        is_active=True if req.isActive is None else bool(req.isActive)
    )

@app.put("/api/admin/announcements/{anno_id}")
def update_admin_announcement(anno_id: str, req: AnnouncementUpdateRequest, _: Dict[str, Any] = Depends(get_current_admin)):
    updates = {}
    if req.title is not None:
        updates["title"] = req.title.strip()
    if req.content is not None:
        updates["content"] = req.content.strip()
    if req.tag is not None:
        updates["tag"] = req.tag.strip()
    if req.isActive is not None:
        updates["isActive"] = bool(req.isActive)
    db_update_announcement(anno_id, updates)
    return {"status": "ok"}

@app.delete("/api/admin/announcements/{anno_id}")
def delete_admin_announcement(anno_id: str, _: Dict[str, Any] = Depends(get_current_admin)):
    db_delete_announcement(anno_id)
    return {"status": "ok"}

@app.post("/api/admin/auth/login")
async def admin_portal_login(req: LoginRequest, request: Request, response: Response):
    """管理员独立后台专属登录接口（严格鉴权：仅允许具有 admin 角色的账号通过）"""
    client_ip = request.client.host if request.client else "unknown"
    rate_key = f"admin_gate:{client_ip}:{req.identifier.strip().lower()}"
    if is_rate_limited(rate_key, max_attempts=5, window_seconds=900):
        raise HTTPException(status_code=429, detail="管理员登录失败过多，入口已锁定 15 分钟")
    
    user = get_user_by_identifier(req.identifier)
    if not user:
        record_failed_attempt(rate_key)
        raise HTTPException(status_code=400, detail="管理员账号或密码错误")
    
    if user.get("role") != "admin":
        record_failed_attempt(rate_key)
        raise HTTPException(status_code=403, detail="拒绝访问：该账号非系统超级管理员")
        
    if not user.get("isActive", True):
        raise HTTPException(status_code=403, detail="该管理员账号已被禁用")
        
    if not verify_password(req.password, user.get("passwordHash", ""), user.get("salt", "")):
        record_failed_attempt(rate_key)
        raise HTTPException(status_code=400, detail="管理员账号或密码错误")
        
    clear_failed_attempts(rate_key)
    update_user_fields(user["id"], {"lastLogin": int(time.time())})
    
    token = create_jwt_token({
        "sub": user["id"],
        "username": user["username"],
        "role": "admin",
        "ver": user.get("token_version", 1)
    })
    is_secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    response.set_cookie(key="auth_token", value=token, httponly=True, max_age=86400 * 7, samesite="lax", secure=is_secure)
    return {
        "status": "ok",
        "token": token,
        "user": sanitize_user(user)
    }

# ----------------- API 路由: 基础配置与密钥池 -----------------

class ConfigUpdateModel(BaseModel):
    apiKey: Optional[str] = None

class AddKeyModel(BaseModel):
    name: str
    apiKey: str
    note: Optional[str] = ""
    setActive: Optional[bool] = False

@app.get("/api/config")
def get_config(current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)):
    """获取系统运行配置（严格鉴权隔离：普通用户与访客绝不泄露 API 密钥列表与激活信息）"""
    cfg = load_config()
    active_key_str = get_active_api_key(cfg)
    is_admin = current_user and current_user.get("role") == "admin"
    
    base_res = {
        "hasKey": bool(active_key_str),
        "workflows": cfg.get("workflows", []),
        "system": get_system_config_safe(cfg) if is_admin else {
            "siteTitle": cfg.get("system", {}).get("siteTitle", "RunningHub 智能调度中心"),
            "allowRegistration": bool(cfg.get("system", {}).get("allowRegistration", True)),
            "requireLoginToGenerate": bool(cfg.get("system", {}).get("requireLoginToGenerate", True)),
            "defaultUserPoints": cfg.get("system", {}).get("defaultUserPoints", 100),
            "hideAuxiliaryAudioChain": bool(cfg.get("system", {}).get("hideAuxiliaryAudioChain", True))
        }
    }
    
    if is_admin:
        active_info = None
        for k in cfg.get("apiKeys", []):
            if k.get("id") == cfg.get("activeKeyId"):
                active_info = k
                break
        base_res.update({
            "activeKeyId": cfg.get("activeKeyId", ""),
            "activeKeyName": active_info.get("name", "") if active_info else "",
            "activeMaskedKey": mask_key(active_key_str) if active_key_str else "",
            "keys": get_api_keys_safe(cfg)
        })
    else:
        base_res.update({
            "activeKeyId": "",
            "activeKeyName": "",
            "activeMaskedKey": "",
            "keys": []
        })
    return base_res

@app.post("/api/config")
def update_config(data: ConfigUpdateModel, _: Dict[str, Any] = Depends(get_current_admin)):
    """向下兼容的旧版单 Key 更新接口（仅限管理员访问）"""
    cfg = load_config()
    if data.apiKey and data.apiKey.strip():
        raw_key = data.apiKey.strip()
        # 查找或更新默认 key
        active_id = cfg.get("activeKeyId")
        updated = False
        for k in cfg.get("apiKeys", []):
            if k.get("id") == active_id:
                k["keyEncrypted"] = encrypt_key(raw_key)
                updated = True
                break
        if not updated:
            new_id = "key_" + uuid.uuid4().hex[:8]
            cfg.setdefault("apiKeys", []).append({
                "id": new_id,
                "name": "主账号密钥",
                "keyEncrypted": encrypt_key(raw_key),
                "createdAt": int(time.time()),
                "note": "通过通用配置接口更新"
            })
            cfg["activeKeyId"] = new_id
        save_config(cfg)
    return {"status": "ok", "hasKey": bool(get_active_api_key(cfg))}

@app.get("/api/keys")
def list_keys(_: Dict[str, Any] = Depends(get_current_admin)):
    """获取所有已存储的 API Key 列表（仅限管理员，脱敏后输出）"""
    cfg = load_config()
    return {
        "status": "ok",
        "keys": get_api_keys_safe(cfg),
        "activeKeyId": cfg.get("activeKeyId", "")
    }

@app.post("/api/keys")
def add_key(data: AddKeyModel, _: Dict[str, Any] = Depends(get_current_admin)):
    """添加新的 API Key（仅限管理员，后端即时 Fernet 加密）"""
    raw_key = data.apiKey.strip()
    if not raw_key:
        raise HTTPException(status_code=400, detail="API Key 不能为空")

    cfg = load_config()
    key_id = "key_" + uuid.uuid4().hex[:8]
    new_entry = {
        "id": key_id,
        "name": data.name.strip() or f"密钥 #{len(cfg.get('apiKeys', [])) + 1}",
        "keyEncrypted": encrypt_key(raw_key),
        "createdAt": int(time.time()),
        "note": (data.note or "").strip()
    }
    cfg.setdefault("apiKeys", []).append(new_entry)
    if data.setActive or len(cfg["apiKeys"]) == 1 or not cfg.get("activeKeyId"):
        cfg["activeKeyId"] = key_id
    save_config(cfg)
    return {
        "status": "ok",
        "keys": get_api_keys_safe(cfg),
        "activeKeyId": cfg.get("activeKeyId", ""),
        "addedId": key_id
    }

@app.post("/api/keys/{key_id}/activate")
def activate_key(key_id: str, _: Dict[str, Any] = Depends(get_current_admin)):
    """切换当前激活的 API Key（仅限管理员）"""
    cfg = load_config()
    found = any(k.get("id") == key_id for k in cfg.get("apiKeys", []))
    if not found:
        raise HTTPException(status_code=404, detail="指定的 API Key 不存在")
    cfg["activeKeyId"] = key_id
    save_config(cfg)
    return {
        "status": "ok",
        "activeKeyId": key_id,
        "keys": get_api_keys_safe(cfg)
    }

@app.delete("/api/keys/{key_id}")
def delete_key(key_id: str, _: Dict[str, Any] = Depends(get_current_admin)):
    """删除指定的 API Key（仅限管理员）"""
    cfg = load_config()
    cfg["apiKeys"] = [k for k in cfg.get("apiKeys", []) if k.get("id") != key_id]
    if cfg.get("activeKeyId") == key_id:
        cfg["activeKeyId"] = cfg["apiKeys"][0]["id"] if cfg["apiKeys"] else ""
    save_config(cfg)
    return {
        "status": "ok",
        "keys": get_api_keys_safe(cfg),
        "activeKeyId": cfg.get("activeKeyId", "")
    }

@app.post("/api/keys/{key_id}/test")
def test_key(key_id: str, _: Dict[str, Any] = Depends(get_current_admin)):
    """实时连通性测试（仅限管理员）"""
    cfg = load_config()
    target_key = None
    for k in cfg.get("apiKeys", []):
        if k.get("id") == key_id:
            target_key = k
            break
    if not target_key:
        raise HTTPException(status_code=404, detail="该密钥不存在")
    raw_key = decrypt_key(target_key.get("keyEncrypted", ""))
    valid, msg = verify_key_with_runninghub(raw_key)
    return {"status": "ok", "valid": valid, "message": msg}

@app.get("/api/workflows")
def get_workflows():
    cfg = load_config()
    return cfg.get("workflows", [])

class WorkflowModel(BaseModel):
    id: str
    name: str
    description: Optional[str] = ""
    category: Optional[str] = "通用"
    pointsCost: Optional[int] = 5
    defaultParams: Optional[Dict[str, Any]] = None

@app.post("/api/workflows")
def add_or_update_workflow(wf: WorkflowModel, current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)):
    """添加或修改工作流"""
    cfg = load_config()
    workflows = cfg.get("workflows", [])
    existing = False
    for i, w in enumerate(workflows):
        if str(w.get("id")) == str(wf.id):
            workflows[i] = wf.dict()
            existing = True
            break
    if not existing:
        workflows.append(wf.dict())
    cfg["workflows"] = workflows
    save_config(cfg)
    return {"status": "ok", "workflow": wf.dict()}

@app.delete("/api/workflows/{workflow_id}")
def delete_workflow(workflow_id: str, current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)):
    """删除工作流"""
    cfg = load_config()
    cfg["workflows"] = [w for w in cfg.get("workflows", []) if str(w.get("id")) != str(workflow_id)]
    save_config(cfg)
    return {"status": "ok"}

def detect_silent_audio_subgraphs(nodes: Dict[str, Any]) -> Set[str]:
    """
    拓扑检测 ComfyUI 中常见的静音/占位音频生成 4 节点流水线：
    Node 1 (GetImageSize / GetImageSizeAndCount)
      -> Node 2 (SimpleCalculator / SimpleCalculatorKJ)
        -> Node 3 (EmptyAudio)
          -> Node 4 (SaveAudio / SaveAudioAdvanced)
    
    严格限制：只有当这 4 个节点严格按照此有向无环依赖链级联连接时，才认定为辅助占位链路并隐藏。
    若任意节点独立存在或未形成该完整 4 节点链路，则视为用户真实操作节点，正常展示。
    """
    def normalize_type(ctype: Any) -> str:
        return str(ctype).replace("_", "").replace(" ", "").lower()

    def is_node_type(node: Dict[str, Any], candidates: List[str]) -> bool:
        norm = normalize_type(node.get("class_type", ""))
        return any(c in norm for c in candidates)

    def get_node_incoming_sources(node: Dict[str, Any]) -> Set[str]:
        sources = set()
        inputs = node.get("inputs", {})
        if isinstance(inputs, dict):
            for val in inputs.values():
                if isinstance(val, (list, tuple)) and len(val) >= 1:
                    sources.add(str(val[0]))
        return sources

    hidden_ids: Set[str] = set()
    for n4_id, n4 in nodes.items():
        if is_node_type(n4, ["saveaudio"]):
            for n3_id in get_node_incoming_sources(n4):
                n3 = nodes.get(n3_id)
                if n3 and is_node_type(n3, ["emptyaudio"]):
                    for n2_id in get_node_incoming_sources(n3):
                        n2 = nodes.get(n2_id)
                        if n2 and is_node_type(n2, ["simplecalculator"]):
                            for n1_id in get_node_incoming_sources(n2):
                                n1 = nodes.get(n1_id)
                                if n1 and is_node_type(n1, ["getimagesize"]):
                                    chain = {str(n1_id), str(n2_id), str(n3_id), str(n4_id)}
                                    hidden_ids.update(chain)
    return hidden_ids

def parse_nodes_to_dynamic_schema(nodes: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """对 ComfyUI 节点结构做深度动态解析，提取提示词、尺寸、采样器、参考图视频、以及全节点可调项"""
    prompt_nodes = []
    sampler_nodes = []
    latent_nodes = []
    image_nodes = []
    video_nodes = []
    audio_nodes = []
    quality_nodes = []
    output_nodes = []
    all_editable_nodes = []

    for nid, node in nodes.items():
        ctype = node.get("class_type", "")
        inputs = node.get("inputs", {})

        # 获取当前节点中所有的常量字面量字段（排除 link 引用列表，如 ['1', 0]）
        literal_fields = {k: v for k, v in inputs.items() if not isinstance(v, (list, dict))}

        # 1. 提示词与文本节点
        if "CLIPTextEncode" in ctype or "RH_Prompter" in ctype or "Prompt" in ctype or "JjkText" in ctype or ("text" in literal_fields and isinstance(literal_fields["text"], str) and len(literal_fields["text"]) > 0):
            field_name = "text" if "text" in literal_fields else "prompt"
            if field_name in literal_fields:
                prompt_nodes.append({
                    "nodeId": str(nid),
                    "class_type": ctype,
                    "title": f"提示词节点 #{nid} ({ctype})",
                    "fieldName": field_name,
                    "defaultValue": str(literal_fields[field_name])
                })

        # 2. 采样器与步数/调度器节点 (优先匹配真实带有 steps 的调度器或采样器)
        if ("steps" in literal_fields and "cfg" in literal_fields) or ctype in ("KSampler", "KSamplerAdvanced"):
            sampler_fields = {
                k: v for k, v in literal_fields.items()
                if k in ["steps", "cfg", "sampler_name", "scheduler", "seed", "denoise"]
            }
            if sampler_fields:
                sampler_nodes.append({
                    "nodeId": str(nid),
                    "class_type": ctype,
                    "title": f"采样器节点 #{nid} ({ctype})",
                    "fields": sampler_fields
                })
        elif "steps" in literal_fields:
            sched_fields = {
                k: v for k, v in literal_fields.items()
                if k in ["steps", "scheduler", "denoise"]
            }
            if sched_fields:
                sampler_nodes.append({
                    "nodeId": str(nid),
                    "class_type": ctype,
                    "title": f"步数与调度器 #{nid} ({ctype})",
                    "fields": sched_fields
                })

        # 3. 画面尺寸与批次节点 (EmptyLatentImage)
        if "EmptyLatentImage" in ctype or "Latent" in ctype or ("width" in literal_fields and "height" in literal_fields):
            latent_fields = {
                k: v for k, v in literal_fields.items()
                if k in ["width", "height", "batch_size"]
            }
            if latent_fields:
                latent_nodes.append({
                    "nodeId": str(nid),
                    "class_type": ctype,
                    "title": f"尺寸节点 #{nid} ({ctype})",
                    "fields": latent_fields
                })

        # 4. 参考图输入节点 (LoadImage / UploadImage)
        if "LoadImage" in ctype or "UploadImage" in ctype or ("image" in literal_fields and isinstance(literal_fields["image"], str)):
            if "image" in literal_fields:
                image_nodes.append({
                    "nodeId": str(nid),
                    "class_type": ctype,
                    "title": f"参考图输入 #{nid} ({ctype})",
                    "fieldName": "image",
                    "defaultValue": str(literal_fields.get("image", ""))
                })

        # 5. 参考视频输入节点 (VHS_LoadVideo / LoadVideo)
        if "LoadVideo" in ctype or ("video" in literal_fields and isinstance(literal_fields["video"], str)):
            if "video" in literal_fields:
                video_nodes.append({
                    "nodeId": str(nid),
                    "class_type": ctype,
                    "title": f"参考视频输入 #{nid} ({ctype})",
                    "fieldName": "video",
                    "defaultValue": str(literal_fields.get("video", ""))
                })

        # 5.1 参考音频输入节点 (LoadAudio / VHS_LoadAudio / AudioLoader / 或包含 audio 参数)
        if any(k.lower() in ctype.lower() for k in ["loadaudio", "audioloader"]) or any(k in literal_fields for k in ["audio", "audio_file", "audio_path", "sound", "voice", "speech"]):
            audio_field = next((k for k in ["audio", "audio_file", "audio_path", "sound", "voice", "speech"] if k in literal_fields and isinstance(literal_fields[k], str)), None)
            if audio_field:
                audio_nodes.append({
                    "nodeId": str(nid),
                    "class_type": ctype,
                    "title": f"参考音频输入 #{nid} ({ctype})",
                    "fieldName": audio_field,
                    "defaultValue": str(literal_fields.get(audio_field, ""))
                })

        # 6. 画质/基准分辨率节点 (如 PrimitiveInt: 1280)
        if ctype in ("PrimitiveInt", "Int") and "value" in literal_fields:
            val = literal_fields["value"]
            if isinstance(val, int) and (val >= 256 or val in [512, 720, 768, 1024, 1080, 1280, 1920]):
                quality_nodes.append({
                    "nodeId": str(nid),
                    "class_type": ctype,
                    "title": f"画质/分辨率尺寸 #{nid} ({ctype})",
                    "fieldName": "value",
                    "defaultValue": val
                })

        # 7. 输出类节点 (SaveImage, PreviewImage, SaveVideo, VHS_VideoCombine, 等)
        if any(k in ctype for k in ["SaveImage", "PreviewImage", "SaveVideo", "VHS_VideoCombine", "Preview", "SaveAudio", "Output"]):
            output_nodes.append({
                "nodeId": str(nid),
                "class_type": ctype,
                "title": f"输出节点 #{nid} ({ctype})",
                "isVideo": any(v in ctype for v in ["Video", "VHS"]),
                "isAudio": "Audio" in ctype
            })

        # 8. 全节点字面量清单（带详细字段元数据，供前端全量可调参数面板渲染）
        if literal_fields:
            field_meta = []
            for k, v in literal_fields.items():
                ftype = "str"
                if isinstance(v, bool):
                    ftype = "bool"
                elif isinstance(v, int):
                    ftype = "int"
                elif isinstance(v, float):
                    ftype = "float"
                field_meta.append({
                    "name": k,
                    "value": v,
                    "type": ftype
                })
            all_editable_nodes.append({
                "nodeId": str(nid),
                "class_type": ctype,
                "fields": literal_fields,
                "fieldMeta": field_meta
            })

    # 拓扑检测静音音频占位辅助链路 (GetImageSize -> Simple Calculator -> Empty Audio -> Save Audio)
    hide_auxiliary = bool(cfg.get("system", {}).get("hideAuxiliaryAudioChain", True))
    hidden_node_ids: Set[str] = detect_silent_audio_subgraphs(nodes) if hide_auxiliary else set()

    if hidden_node_ids:
        prompt_nodes = [p for p in prompt_nodes if str(p.get("nodeId")) not in hidden_node_ids]
        sampler_nodes = [s for s in sampler_nodes if str(s.get("nodeId")) not in hidden_node_ids]
        latent_nodes = [l for l in latent_nodes if str(l.get("nodeId")) not in hidden_node_ids]
        image_nodes = [im for im in image_nodes if str(im.get("nodeId")) not in hidden_node_ids]
        video_nodes = [vm for vm in video_nodes if str(vm.get("nodeId")) not in hidden_node_ids]
        audio_nodes = [am for am in audio_nodes if str(am.get("nodeId")) not in hidden_node_ids]
        quality_nodes = [q for q in quality_nodes if str(q.get("nodeId")) not in hidden_node_ids]
        output_nodes = [o for o in output_nodes if str(o.get("nodeId")) not in hidden_node_ids]
        all_editable_nodes = [n for n in all_editable_nodes if str(n.get("nodeId")) not in hidden_node_ids]

    # 智能区分正向、负向与主体提示词
    categorized_prompts = []
    for p in prompt_nodes:
        text_val = p["defaultValue"].strip().lower()
        if any(w in text_val for w in ["bad", "blurry", "worst quality", "low quality", "deformed", "distorted", "artifacts", "lowres"]) or "negative" in p["class_type"].lower():
            role = "negative"
            label = "负向提示词 (Negative Prompt)"
        elif len(text_val) > 20 or "positive" in p["class_type"].lower() or any(w in text_val for w in ["masterpiece", "detailed", "描述", "人物", "衣服", "服装", "背景", "镜头"]):
            role = "positive"
            label = "正向主提示词 (Positive Prompt)"
        else:
            role = "subject"
            label = "主体/补充描述"
        categorized_prompts.append({**p, "role": role, "label": f"{label} #{p['nodeId']}"})

    if categorized_prompts and not any(p["role"] == "positive" for p in categorized_prompts):
        categorized_prompts[0]["role"] = "positive"
        categorized_prompts[0]["label"] = f"核心提示词 #{categorized_prompts[0]['nodeId']}"

    # 针对全节点列表按 nodeId 升序排序
    def node_sort_key(n):
        try:
            return (0, int(n["nodeId"]))
        except Exception:
            return (1, str(n["nodeId"]))
    all_editable_nodes.sort(key=node_sort_key)

    return {
        "hiddenAuxiliaryNodeIds": list(hidden_node_ids) if hidden_node_ids else [],
        "dynamicSchema": {
            "promptNodes": categorized_prompts,
            "samplerNode": sampler_nodes[0] if sampler_nodes else None,
            "latentNode": latent_nodes[0] if latent_nodes else None,
            "imageNodes": image_nodes,
            "videoNodes": video_nodes,
            "audioNodes": audio_nodes,
            "qualityNodes": quality_nodes,
            "allEditableNodes": all_editable_nodes
        }
    }

@app.post("/api/workflows/inspect")
def inspect_workflow_endpoint(payload: Dict[str, Any]):
    """通过 RunningHub OpenAPI 读取工作流的 ComfyUI 原始结构并做深度动态提取"""
    workflow_id = payload.get("workflowId")
    if not workflow_id:
        raise HTTPException(status_code=400, detail="Missing workflowId")
    
    cfg = load_config()
    api_key = payload.get("apiKey") or get_active_api_key(cfg)
    if not api_key:
        raise HTTPException(status_code=400, detail="未配置有效 API Key，请先进入顶部切换或设置中添加启用密钥")
    
    url = f"{RUNNINGHUB_API_URL}/api/openapi/getJsonApiFormat"
    try:
        res = requests.post(url, json={"apiKey": api_key, "workflowId": str(workflow_id)}, timeout=15)
        raw_data = res.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Request to RunningHub failed: {str(e)}")
    
    if raw_data.get("code") != 0:
        raise HTTPException(status_code=400, detail=raw_data.get("msg") or "获取工作流信息失败")
    
    prompt_str = raw_data.get("data", {}).get("prompt", "{}")
    try:
        nodes = json.loads(prompt_str)
    except Exception:
        nodes = {}

    parsed = parse_nodes_to_dynamic_schema(nodes, cfg)
    return {
        "status": "ok",
        "workflowId": str(workflow_id),
        "totalNodes": len(nodes),
        "hiddenAuxiliaryNodeIds": parsed["hiddenAuxiliaryNodeIds"],
        "dynamicSchema": parsed["dynamicSchema"]
    }

OBJECT_INFO_CACHE_PATH = os.path.join(DATA_DIR, "object_info_cache.json")
_MEMORY_OBJECT_INFO: Optional[Dict[str, Any]] = None

def get_cached_object_info(api_key: str) -> Dict[str, Any]:
    """
    获取或缓存 RunningHub 云端全部节点的完整定义（19800+ 节点定义）
    用于在用户上传普通 Web 画布格式工作流时，自动将其无缝编译为标准的 ComfyUI API Prompt 格式
    """
    global _MEMORY_OBJECT_INFO
    if _MEMORY_OBJECT_INFO is not None:
        return _MEMORY_OBJECT_INFO

    # 1. 尝试从本地磁盘缓存加载
    if os.path.exists(OBJECT_INFO_CACHE_PATH):
        try:
            mtime = os.path.getmtime(OBJECT_INFO_CACHE_PATH)
            # 7天内缓存有效
            if time.time() - mtime < 86400 * 7:
                with open(OBJECT_INFO_CACHE_PATH, "r", encoding="utf-8") as f:
                    _MEMORY_OBJECT_INFO = json.load(f)
                    return _MEMORY_OBJECT_INFO
        except Exception:
            pass

    # 2. 从云端 proxy 拉取
    if not api_key:
        return {}

    for host in ["www.runninghub.cn", "www.runninghub.ai"]:
        try:
            url = f"https://{host}/proxy/{api_key}/object_info"
            res = requests.get(url, timeout=12)
            if res.status_code == 200:
                data = res.json()
                if isinstance(data, dict) and len(data) > 100:
                    _MEMORY_OBJECT_INFO = data
                    try:
                        with open(OBJECT_INFO_CACHE_PATH, "w", encoding="utf-8") as f:
                            json.dump(data, f, ensure_ascii=False)
                    except Exception:
                        pass
                    return _MEMORY_OBJECT_INFO
        except Exception:
            continue

    return _MEMORY_OBJECT_INFO or {}

def convert_ui_workflow_to_prompt(ui_json: Dict[str, Any], obj_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    将 ComfyUI Web 画布工程文件 (LiteGraph 格式) 自动转换为云端可执行的 API Prompt 格式。
    自动解析并穿透前端虚拟总线节点 (Set_*/Get_* 无线总线节点、Reroute 重定向节点、Primitive 原生数值节点、Note 视觉便签等)。
    """
    nodes = ui_json.get("nodes", [])
    links = ui_json.get("links", [])
    nodes_by_id = {str(n.get("id")): n for n in nodes if n.get("id") is not None}

    # 1. 建立基础 link_id 映射：link_id -> [origin_node_id, origin_slot_index]
    link_map = {}
    for l in links:
        if isinstance(l, (list, tuple)) and len(l) >= 4:
            lid, src_id, src_slot = l[0], str(l[1]), int(l[2])
            link_map[lid] = [src_id, src_slot]

    # 2. 识别与提取虚拟节点元数据
    def extract_var_name(node: dict, prefix: str) -> str:
        ntype = str(node.get("type", "")).strip()
        title = str(node.get("title", "")).strip()
        props = node.get("properties") or {}
        if ntype.lower().startswith(prefix.lower() + "_"):
            return ntype[len(prefix) + 1:].strip()
        if title.lower().startswith(prefix.lower() + "_"):
            return title[len(prefix) + 1:].strip()
        for k in ["name", "var_name", "variable_name", "key"]:
            if props.get(k):
                return str(props[k]).strip()
        wv = node.get("widgets_values")
        if isinstance(wv, list) and len(wv) > 0 and isinstance(wv[0], str) and wv[0].strip():
            return wv[0].strip()
        elif isinstance(wv, dict):
            for k in ["name", "var_name", "variable_name", "key"]:
                if wv.get(k):
                    return str(wv[k]).strip()
        if title and title != ntype and not title.lower().startswith("set") and not title.lower().startswith("get"):
            return title.strip()
        return ""

    def is_virtual_node(node: dict) -> bool:
        ntype = str(node.get("type", "")).strip().lower()
        title = str(node.get("title", "")).strip().lower()
        if ntype == "reroute" or title == "reroute":
            return True
        if ntype.startswith("set_") or ntype.startswith("get_"):
            return True
        if ntype in ["setnode", "getnode", "set", "get"]:
            return True
        if ntype.startswith("primitive"):
            return True
        if ntype in ["note", "markdown", "textnote", "group"]:
            return True
        return False

    reroute_node_map = {}
    for nid, node in nodes_by_id.items():
        ntype = str(node.get("type", "")).strip().lower()
        title = str(node.get("title", "")).strip().lower()
        if ntype == "reroute" or title == "reroute":
            for inp in node.get("inputs", []):
                if inp.get("link") is not None:
                    reroute_node_map[nid] = inp.get("link")
                    break

    get_node_map = {}
    for nid, node in nodes_by_id.items():
        ntype = str(node.get("type", "")).strip().lower()
        if ntype.startswith("get_") or ntype in ["getnode", "get"]:
            get_node_map[nid] = extract_var_name(node, "get")

    wireless_bus = {}
    for nid, node in nodes_by_id.items():
        ntype = str(node.get("type", "")).strip().lower()
        if ntype.startswith("set_") or ntype in ["setnode", "set"]:
            var_name = extract_var_name(node, "set")
            for inp in node.get("inputs", []):
                in_lid = inp.get("link")
                if in_lid is not None:
                    wireless_bus[var_name] = in_lid
                    break

    primitive_node_map = {}
    for nid, node in nodes_by_id.items():
        ntype = str(node.get("type", "")).strip().lower()
        if ntype.startswith("primitive"):
            wv = node.get("widgets_values")
            if isinstance(wv, list) and len(wv) > 0:
                primitive_node_map[nid] = wv[0]

    # 3. 递归穿透解析真实信号源 (递归展开 Reroute 链与 Get/Set 虚拟无线总线)
    def resolve_source(nid: str, slot: int, visited=None):
        if visited is None:
            visited = set()
        if (nid, slot) in visited or len(visited) > 30:
            return [nid, slot]
        visited.add((nid, slot))

        if nid in reroute_node_map:
            in_lid = reroute_node_map[nid]
            if in_lid in link_map:
                up_nid, up_slot = link_map[in_lid]
                return resolve_source(up_nid, up_slot, visited)

        if nid in get_node_map:
            var_name = get_node_map[nid]
            if var_name in wireless_bus:
                in_lid = wireless_bus[var_name]
                if in_lid in link_map:
                    up_nid, up_slot = link_map[in_lid]
                    return resolve_source(up_nid, up_slot, visited)

        return [nid, slot]

    # 4. 全局替换所有连线映射至最终实体节点
    for lid in list(link_map.keys()):
        src_id, src_slot = link_map[lid]
        final_src_id, final_src_slot = resolve_source(src_id, src_slot)
        link_map[lid] = [final_src_id, final_src_slot]

    # 5. 生成 API Prompt 字典（剔除所有虚拟节点，直连实体节点）
    prompt = {}
    for node in nodes:
        nid = str(node.get("id"))
        ntype = node.get("type")
        if not nid or not ntype:
            continue
        if is_virtual_node(node):
            continue

        inputs = {}
        # A. 关联所有输入连线
        for inp in node.get("inputs", []):
            name = inp.get("name")
            lid = inp.get("link")
            if lid is not None and lid in link_map:
                src_nid, src_slot = link_map[lid]
                if src_nid in primitive_node_map:
                    inputs[name] = primitive_node_map[src_nid]
                else:
                    inputs[name] = [src_nid, src_slot]

        # B. 映射 widgets_values 参数
        w_values = node.get("widgets_values")
        if isinstance(w_values, dict):
            inputs.update(w_values)
        elif isinstance(w_values, list):
            node_def = obj_info.get(ntype, {})
            req_inputs = node_def.get("input", {}).get("required", {})
            opt_inputs = node_def.get("input", {}).get("optional", {})

            def is_widget_type(spec):
                if not isinstance(spec, (list, tuple)) or len(spec) == 0:
                    return False
                t = spec[0]
                if isinstance(t, list):
                    return True  # 下拉列表选项
                if isinstance(t, str) and t.upper() in ["INT", "FLOAT", "STRING", "BOOLEAN", "BOOLEAN_NOT"]:
                    return True
                return False

            # 筛选出属于真实 widget 的参数项（即未被 incoming link 占用，且属于前端控件而非纯连线插槽）
            widget_field_names = []
            for fname, fspec in req_inputs.items():
                if is_widget_type(fspec) and fname not in inputs:
                    widget_field_names.append((fname, fspec))
            for fname, fspec in opt_inputs.items():
                if is_widget_type(fspec) and fname not in inputs:
                    widget_field_names.append((fname, fspec))

            w_idx = 0
            for fname, fspec in widget_field_names:
                if w_idx >= len(w_values):
                    break
                val = w_values[w_idx]
                w_idx += 1
                inputs[fname] = val
                # 处理 ComfyUI LiteGraph 专用的 control_after_generate 虚拟占位组件 (如 'randomize', 'fixed')
                if w_idx < len(w_values) and isinstance(w_values[w_idx], str) and w_values[w_idx] in ["randomize", "fixed", "increment", "decrement"]:
                    w_idx += 1

        prompt[nid] = {
            "class_type": ntype,
            "inputs": inputs,
            "_meta": {"title": node.get("title") or ntype}
        }

    return prompt

@app.post("/api/workflows/parse_json")
async def parse_workflow_json_endpoint(
    file: UploadFile = File(...),
    current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    """用户直接上传本地 ComfyUI 工作流 JSON 文件（免 workflowId 直接执行模式，支持 Web 画布与 API 两种格式自动转换）"""
    cfg = load_config()
    filename = file.filename or "custom_workflow.json"
    content_bytes = await file.read()
    try:
        content_text = content_bytes.decode("utf-8")
        raw_json = json.loads(content_text)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"文件不是合法的 JSON 格式: {str(e)}")

    # 智能识别与自适应转换 ComfyUI 格式
    if isinstance(raw_json, dict) and "prompt" in raw_json and isinstance(raw_json["prompt"], dict):
        nodes = raw_json["prompt"]
    elif isinstance(raw_json, dict) and any("class_type" in v for v in raw_json.values() if isinstance(v, dict)):
        nodes = raw_json
    elif isinstance(raw_json, dict) and "nodes" in raw_json and isinstance(raw_json["nodes"], list):
        # 用户上传的是普通 ComfyUI Web 画布工程文件：自动转码为 API Prompt 格式！
        api_key = get_active_api_key(cfg)
        obj_info = get_cached_object_info(api_key)
        nodes = convert_ui_workflow_to_prompt(raw_json, obj_info)
        if not nodes:
            raise HTTPException(status_code=400, detail="画布工程文件自动转换失败，未识别到有效节点。")
    else:
        raise HTTPException(status_code=400, detail="未能识别出有效的 ComfyUI 工作流节点拓扑，请确保为 ComfyUI 格式 JSON。")

    parsed = parse_nodes_to_dynamic_schema(nodes, cfg)
    return {
        "status": "ok",
        "workflowName": filename,
        "totalNodes": len(nodes),
        "customPrompt": nodes,
        "hiddenAuxiliaryNodeIds": parsed["hiddenAuxiliaryNodeIds"],
        "dynamicSchema": parsed["dynamicSchema"]
    }

@app.post("/api/upload")
async def upload_file_to_runninghub(
    file: UploadFile = File(...),
    current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    """上传本地图片或视频到 RunningHub，严格限制单文件 30MB 与安全扩展名，防内存 DoS"""
    cfg = load_config()
    sys_cfg = cfg.get("system", {})
    if sys_cfg.get("requireLoginToGenerate") and not current_user:
        raise HTTPException(status_code=401, detail="当前系统已开启强制登录，请先登录后再上传素材")

    api_key = get_active_api_key(cfg)
    if not api_key:
        raise HTTPException(status_code=400, detail="未配置有效 API Key，请先进入顶部切换或设置中配置启用")

    # 1. 安全扩展名白名单校验 (支持图片、视频与音频格式)
    filename_raw = file.filename or ""
    allowed_image_exts = {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif"}
    allowed_video_exts = {".mp4", ".webm", ".mov"}
    allowed_audio_exts = {".mp3", ".wav", ".flac", ".ogg", ".m4a", ".aac", ".wma", ".opus"}
    allowed_exts = allowed_image_exts | allowed_video_exts | allowed_audio_exts

    ext = os.path.splitext(filename_raw)[1].lower()
    if ext not in allowed_exts:
        raise HTTPException(status_code=400, detail=f"不支持的文件格式: {ext}，支持图像、视频与音频文件 (mp3/wav/flac/ogg/m4a 等)")

    # 2. 流式分块读取并限流最大 30MB，彻底免疫内存 DoS
    MAX_UPLOAD_SIZE = 30 * 1024 * 1024
    chunk_size = 1024 * 512
    total_size = 0
    buffer = bytearray()
    
    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
        total_size += len(chunk)
        if total_size > MAX_UPLOAD_SIZE:
            raise HTTPException(status_code=413, detail="素材文件过大，单文件上传上限为 30MB")
        buffer.extend(chunk)

    file_bytes = bytes(buffer)
    upload_url = "https://www.runninghub.ai/openapi/v2/media/upload/binary"
    headers = {
        "Authorization": f"Bearer {api_key}"
    }

    try:
        files = {"file": (filename_raw, file_bytes, file.content_type)}
        res = await asyncio.to_thread(requests.post, upload_url, headers=headers, files=files, timeout=120)
        resp_data = res.json()
        if resp_data.get("code") == 0:
            data = resp_data.get("data", {})
            inferred_type = "audio" if ext in allowed_audio_exts else ("video" if ext in allowed_video_exts else "image")
            return {
                "status": "ok",
                "fileName": data.get("fileName"),
                "downloadUrl": data.get("download_url"),
                "fileType": data.get("type") or inferred_type
            }
        else:
            raise HTTPException(status_code=400, detail=resp_data.get("msg") or "上传失败")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"上传至 RunningHub 发生异常: {str(e)}")

async def submit_proxy_prompt_async(api_key: str, proxy_payload: Dict[str, Any]) -> Tuple[Optional[str], str]:
    """
    向 RunningHub 云端 ComfyUI 原生代理引擎提交 Prompt 任务
    具备智能排队等待、curl_cffi加速与精确错误原因解析
    """
    hosts = ["www.runninghub.ai", "runninghub.ai"]
    last_err = ""

    def _do_post(url: str, payload: dict) -> Tuple[int, str]:
        # 1. 优先尝试 curl_cffi 模拟浏览器，规避跨境网络握手卡顿
        try:
            from curl_cffi import requests as c_requests
            r = c_requests.post(url, json=payload, impersonate="chrome120", timeout=25)
            return r.status_code, r.text
        except Exception:
            pass
        # 2. 备用标准 requests
        try:
            r = requests.post(url, json=payload, timeout=25)
            return r.status_code, r.text
        except Exception as e:
            return 0, str(e)

    # 针对云端单任务独占队列机制：若前序任务正在运行，最多智能重试 4 次（每次间隔 3 秒）
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

                    # 1. 检测是否是云端单通道队列占用 (排队中)
                    if "queue_remaining" in resp_text or resp_text.strip() == "{}":
                        last_err = "当前云端原生 ComfyUI 算力通道正在执行前序任务，请稍候约十几秒待出图完毕后再试。"
                        break  # 跳出当前 host，进行下一轮重试

                    # 2. 精准提取 ComfyUI 报告的真实节点或模型错误
                    print(f"[Proxy Prompt Response] status=200 text={resp_text[:1000]}", flush=True)

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
                        print(f"[Proxy Prompt Node Error] {combined_detail}", flush=True)
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
            else:
                last_err = f"连接云端超时或网络中断: {resp_text}"

        # 每次重试等待 3 秒，给云端前序任务完成出图释放显存的时间
        await asyncio.sleep(3)

    return None, last_err or "当前云端原生 ComfyUI 算力通道正在运算中，请稍候约十几秒后再试。"

class GenerateRequest(BaseModel):
    workflowId: str
    nodeInfoList: List[Dict[str, Any]]
    positivePrompt: Optional[str] = None
    negativePrompt: Optional[str] = None
    workflowName: Optional[str] = None
    taskType: Optional[str] = "Standard"
    customPrompt: Optional[Dict[str, Any]] = None

@app.post("/api/generate")
async def generate_task(
    req: GenerateRequest, 
    background_tasks: BackgroundTasks,
    current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    cfg = load_config()
    sys_cfg = cfg.get("system", {})
    require_login = bool(sys_cfg.get("requireLoginToGenerate", True))
    if require_login and not current_user:
        raise HTTPException(status_code=401, detail="当前系统已开启强制登录，请先登录后再提交生成任务")

    api_key = get_active_api_key(cfg)
    if not api_key:
        raise HTTPException(status_code=400, detail="未配置有效 API Key，请先进入顶部切换或设置中添加启用密钥")

    is_custom_proxy = bool(req.customPrompt or str(req.workflowId).startswith("custom_"))

    # 匹配目标工作流并计算点数单价 (P0-5 计费闭环)
    target_wf = next((w for w in cfg.get("workflows", []) if str(w.get("id")) == str(req.workflowId)), {})
    task_cost = int(target_wf.get("pointsCost", sys_cfg.get("defaultTaskCost", 5)))

    # 原子条件扣减积分：SQL 级 points >= task_cost 严格行锁，彻底杜绝并发超扣与负数
    points_deducted = False
    if current_user:
        ok, remaining, msg = db_deduct_user_points(
            user_id=current_user["id"],
            amount=task_cost,
            reason=f"生成任务算力扣减 ({req.workflowName or req.workflowId})"
        )
        if not ok:
            raise HTTPException(status_code=402, detail=f"算力点数不足：本次生成需 {task_cost} 点，您当前账户仅剩 {remaining} 点，请联系管理员充值")
        points_deducted = True

    # 规范化算力档位：Standard (标准极速独享通道) vs Lite (经济共享排队通道)
    task_type = "Lite" if req.taskType and req.taskType.strip().lower() == "lite" else "Standard"

    task_id = None
    net_wss_url = None

    if is_custom_proxy:
        # 模式 A: 用户上传的本地 ComfyUI 工作流，通过 RunningHub 原生 Proxy 代理通道免 ID 直接运行
        prompt_dict = copy.deepcopy(req.customPrompt or {})
        # 将用户在前端面板上修改过的字段参数反写回 prompt 节点结构
        for item in req.nodeInfoList:
            nid = str(item.get("nodeId"))
            fname = item.get("fieldName")
            fval = item.get("fieldValue")
            if nid in prompt_dict and "inputs" in prompt_dict[nid]:
                prompt_dict[nid]["inputs"][fname] = fval

        client_id = str(uuid.uuid4())
        proxy_payload = {
            "prompt": prompt_dict,
            "client_id": client_id
        }

        task_id, last_err = await submit_proxy_prompt_async(api_key, proxy_payload)

        if not task_id:
            print(f"[Proxy Prompt Failed] Reason: {last_err}")
            if points_deducted and current_user:
                db_refund_user_points(current_user["id"], task_cost, reason=f"原生代理提交失败退还: {last_err}")
            raise HTTPException(status_code=400, detail=f"提交至云端 ComfyUI 原生代理引擎失败: {last_err}")
    else:
        # 模式 B: 传统的 RunningHub 云端已保存模板工作流 (通过 workflowId 调度)
        payload = {
            "apiKey": api_key,
            "workflowId": str(req.workflowId),
            "nodeInfoList": req.nodeInfoList,
            "taskType": task_type
        }

        headers = {"Host": "www.runninghub.cn", "Content-Type": "application/json"}
        try:
            res = await asyncio.to_thread(
                requests.post,
                f"{RUNNINGHUB_API_URL}/task/openapi/create",
                json=payload,
                headers=headers,
                timeout=25
            )
            data = res.json()
        except Exception as e:
            # 异常退还已扣减点数
            if points_deducted and current_user:
                db_refund_user_points(current_user["id"], task_cost, reason="调用云端引擎失败全额退款")
            raise HTTPException(status_code=500, detail=f"调用 RunningHub 创建任务失败: {str(e)}")

        if data.get("code") != 0:
            if points_deducted and current_user:
                db_refund_user_points(current_user["id"], task_cost, reason=f"云端拒绝任务退还: {data.get('msg')}")
            raise HTTPException(status_code=400, detail=data.get("msg") or "创建任务失败")

        task_id = data.get("data", {}).get("taskId")
        net_wss_url = data.get("data", {}).get("netWssUrl")

    user_id = current_user["id"] if current_user else ""
    user_name = current_user["username"] if current_user else "匿名访客"

    task_record = {
        "taskId": str(task_id),
        "workflowId": str(req.workflowId),
        "workflowName": req.workflowName or ("本地导入工作流" if is_custom_proxy else f"工作流 {req.workflowId}"),
        "taskType": "Proxy-Native" if is_custom_proxy else task_type,
        "userId": user_id,
        "username": user_name,
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

    # 单行原子写入任务，彻底根除 O(N) 写入放大
    db_save_task(task_record)

    # 若为登录用户，累加其生成任务计数
    if current_user:
        try:
            u_info = get_user_by_id(user_id)
            if u_info:
                update_user_fields(user_id, {"taskCount": u_info.get("taskCount", 0) + 1})
        except Exception:
            pass

    # 启动后台双轨守护：以独立协程登记并启动轮询与 WebSocket，彻底解决 BackgroundTasks 串行阻塞与重复轮询
    ACTIVE_POLL_TASKS.add(str(task_id))
    asyncio.create_task(poll_task_status(str(task_id), api_key))
    if net_wss_url:
        asyncio.create_task(listen_websocket_stream(net_wss_url, str(task_id), api_key))

    return {
        "status": "ok",
        "taskId": str(task_id),
        "task": task_record
    }

ACTIVE_POLL_TASKS = set()

@app.get("/api/tasks")
async def list_tasks(current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)):
    cfg = load_config()
    api_key = get_active_api_key(cfg)
    
    # 严格多租户数据行级隔离：前台任务列表只展示属于当前登录用户自己提交的任务
    if current_user:
        user_id_str = str(current_user["id"])
        user_tasks = db_load_tasks(user_id=user_id_str, limit=200)
    else:
        user_tasks = []

    if api_key:
        for t in user_tasks:
            tid = str(t.get("taskId"))
            if t.get("status") in ["RUNNING", "QUEUED"] and tid not in ACTIVE_POLL_TASKS and tid not in CANCELLED_TASKS:
                ACTIVE_POLL_TASKS.add(tid)
                asyncio.create_task(poll_task_status(tid, api_key))
    
    return user_tasks

@app.get("/api/admin/tasks")
def admin_list_all_tasks(_: Dict[str, Any] = Depends(get_current_admin)):
    """管理员全量任务审计视图"""
    return db_load_tasks(is_admin=True, limit=500)

@app.get("/api/tasks/{task_id}")
def get_task(task_id: str, current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)):
    """获取单个任务详情（严格多租户鉴权校验，杜绝越权枚举读取）"""
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

@app.post("/api/tasks/{task_id}/cancel")
async def cancel_task_endpoint(task_id: str, current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)):
    """主动取消任务（严格租户校验 + 算力点数自动退还 + 单行原子状态更新）"""
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

    cfg = load_config()
    api_key = get_active_api_key(cfg)

    cloud_status = "本地已终止"
    if api_key:
        try:
            cancel_url = f"{RUNNINGHUB_API_URL}/task/openapi/cancel"
            headers = {"Host": "www.runninghub.cn", "Content-Type": "application/json"}
            res = await asyncio.to_thread(
                requests.post,
                cancel_url,
                json={"apiKey": api_key, "taskId": task_id_str},
                headers=headers,
                timeout=8
            )
            data = res.json()
            cloud_status = data.get("msg") or "已通知 RunningHub 云端取消"
        except Exception as e:
            cloud_status = f"云端取消请求异常: {str(e)}"

    # 算力点数退还闭环
    cost_val = int(t.get("cost", 0) or 0)
    if task_owner and cost_val > 0 and t.get("status") in ["QUEUED", "RUNNING"]:
        db_refund_user_points(
            user_id=task_owner,
            amount=cost_val,
            task_id=task_id_str,
            reason=f"用户主动取消任务全额退款 ({task_id_str})"
        )
        update_task_record(task_id_str, {"cost": 0})

    # 单行原子更新本地任务状态为 CANCELLED
    update_task_record(task_id_str, {
        "status": "CANCELLED",
        "error": "用户已主动取消任务",
        "statusText": "用户已主动取消",
        "updatedAt": int(time.time())
    })

    return {
        "status": "ok",
        "taskId": task_id_str,
        "cloudStatus": cloud_status,
        "message": f"任务已成功取消 ({cloud_status})"
    }

@app.get("/api/gallery")
def get_gallery(current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)):
    """获取当前登录用户的专属成果画廊（严格多租户隔离：每个人只能看到自己生成的图像/视频成果）"""
    if not current_user:
        return []
    
    user_id_str = str(current_user["id"])
    tasks = db_load_tasks(user_id=user_id_str, limit=500)

    items = []
    seen = set()
    for t in tasks:
        created_at = t.get("createdAt", int(time.time()))
        for out in t.get("outputs", []):
            url = out.get("url") or out.get("remoteUrl")
            if not url or url.startswith("data:"):
                continue
            fname = out.get("filename") or os.path.basename(url.split("?")[0])
            if fname in seen:
                continue
            seen.add(fname)
            ext = os.path.splitext(fname)[1].lower()
            file_type = out.get("fileType")
            if not file_type or file_type == "image":
                if ext in {".mp3", ".wav", ".flac", ".ogg", ".m4a", ".aac", ".wma", ".opus"}:
                    file_type = "audio"
                elif ext in {".mp4", ".webm", ".mov"}:
                    file_type = "video"
                else:
                    file_type = "image"
            items.append({
                "filename": fname,
                "url": url,
                "remoteUrl": out.get("remoteUrl", url),
                "size": out.get("size", 0),
                "createdAt": created_at,
                "fileType": file_type,
                "taskId": t.get("taskId"),
                "username": t.get("username", "")
            })
    items.sort(key=lambda x: x["createdAt"], reverse=True)
    return items

@app.delete("/api/gallery/{filename}")
def delete_gallery_file(filename: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    """删除画廊成果（强制登录 + 严格所有权鉴权 + 单行更新消除写放大）"""
    safe_name = os.path.basename(filename)
    user_id = str(current_user["id"])
    is_admin = current_user.get("role") == "admin"
    
    # 查找归属于该用户（或管理员模式下任意用户）且包含该文件的任务
    user_tasks = db_load_tasks(limit=500) if is_admin else db_load_tasks(user_id=user_id, limit=500)
    found_and_updated = False
    
    for t in user_tasks:
        outs = t.get("outputs", [])
        has_file = any(o.get("filename") == safe_name or os.path.basename(o.get("url", "").split("?")[0]) == safe_name for o in outs)
        if has_file:
            task_owner = str(t.get("userId") or "")
            if not is_admin and task_owner != user_id:
                raise HTTPException(status_code=403, detail="无权删除其他用户的成果文件")
            
            new_outs = [o for o in outs if o.get("filename") != safe_name and os.path.basename(o.get("url", "").split("?")[0]) != safe_name]
            update_task_record(str(t.get("taskId")), {
                "outputs": new_outs,
                "updatedAt": int(time.time())
            })
            found_and_updated = True

    if not found_and_updated and not is_admin:
        raise HTTPException(status_code=404, detail="文件不存在或无权操作")

    # 本地文件安全清理
    fpath = os.path.join(OUTPUTS_DIR, safe_name)
    if os.path.exists(fpath):
        try:
            os.remove(fpath)
        except Exception:
            pass
            
    return {"status": "ok"}
    
    safe_name = os.path.basename(filename)
    fpath = os.path.join(OUTPUTS_DIR, safe_name)
    if os.path.exists(fpath):
        try:
            os.remove(fpath)
        except Exception:
            pass
    return {"status": "ok"}

# ----------------- 独立前端门户路由 -----------------

@app.get("/sign-in")
def serve_sign_in_page():
    """独立登录/注册门户页面 (参考 Moyuu 风格深色全屏体验)"""
    login_path = os.path.join(STATIC_DIR, "login.html")
    if os.path.exists(login_path):
        return FileResponse(login_path)
    return RedirectResponse(url="/")

@app.get("/login")
def serve_login_alias():
    """别名快速跳转"""
    return RedirectResponse(url="/sign-in")

@app.get("/register")
def serve_register_alias():
    """别名快速跳转至注册选项卡"""
    return RedirectResponse(url="/sign-in#register")

@app.get("/admin")
def serve_admin_page():
    """独立开发者超级后台管理中心 (纯前后端分离专属看板)"""
    admin_path = os.path.join(STATIC_DIR, "admin.html")
    if os.path.exists(admin_path):
        return FileResponse(admin_path)
    return RedirectResponse(url="/")

# 挂载静态文件
app.mount("/outputs", StaticFiles(directory=OUTPUTS_DIR), name="outputs")
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    # host 0.0.0.0 允许局域网或公网通过服务器 IP / 域名访问
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
