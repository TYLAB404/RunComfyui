import os
import json
import time
import random
import asyncio
import aiohttp
import urllib.parse
import uuid
import base64
import requests
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, BackgroundTasks, Request, Depends, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from security import encrypt_key, decrypt_key, mask_key, verify_key_with_runninghub
from auth import (
    load_users, save_users, sanitize_user, get_user_by_id, get_user_by_identifier,
    create_user, update_user_fields, set_user_password, delete_user_by_id,
    verify_password, create_jwt_token, decode_jwt_token, verify_turnstile_token
)

app = FastAPI(title="RunningHub Web Controller", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
        "requireLoginToGenerate": False
    }
    for sk, sv in system_defaults.items():
        if sk not in sys_cfg:
            sys_cfg[sk] = sv
            needs_save = True

    if needs_save:
        save_config(cfg)

    return cfg

def save_config(cfg: Dict[str, Any]):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)

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
    if os.path.exists(TASKS_PATH):
        try:
            with open(TASKS_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return []

def save_tasks(tasks: List[Dict[str, Any]]):
    with open(TASKS_PATH, "w", encoding="utf-8") as f:
        json.dump(tasks, f, indent=2, ensure_ascii=False)

def update_task_record(task_id: str, updates: Dict[str, Any]):
    tasks = load_tasks()
    for t in tasks:
        if t.get("taskId") == task_id:
            t.update(updates)
            break
    save_tasks(tasks)

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

                            # 实时更新到任务 outputs 中（仅保留最新一帧预览，避免占用冗余存储）
                            tasks = load_tasks()
                            for t in tasks:
                                if t.get("taskId") == task_id:
                                    t["outputs"] = [o for o in t.get("outputs", []) if not o.get("isRealtimePreview")]
                                    t["outputs"].insert(0, {
                                        "filename": f"{task_id}_preview.png",
                                        "url": data_url,
                                        "size": len(img_bytes),
                                        "nodeId": "Preview",
                                        "title": f"实时截流预览 #{preview_count}",
                                        "isRealtime": True,
                                        "isRealtimePreview": True,
                                        "fileType": "image"
                                    })
                                    save_tasks(tasks)
                                    break

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
                                        tasks = load_tasks()
                                        for t in tasks:
                                            if t.get("taskId") == task_id:
                                                existing = [o.get("url") for o in t.get("outputs", [])]
                                                if view_url not in existing:
                                                    t.setdefault("outputs", []).insert(0, {
                                                        "filename": fname or f"{task_id}_node_{node_id}",
                                                        "url": view_url,
                                                        "remoteUrl": view_url,
                                                        "size": 0,
                                                        "nodeId": node_id,
                                                        "title": f"Node #{node_id} {'截流视频' if is_video else '截流图像'}",
                                                        "isRealtime": True,
                                                        "fileType": "video" if is_video else "image"
                                                    })
                                                    save_tasks(tasks)
                                                break
                        except Exception:
                            pass
                    elif msg.type in (aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                        break
    except Exception:
        pass


async def poll_task_status(task_id: str, api_key: str):
    """后台异步轮询任务输出，并在完成后自动下载到本地 outputs"""
    start_time = time.time()
    outputs_url = f"{RUNNINGHUB_API_URL}/task/openapi/outputs"
    headers = {"Host": "www.runninghub.cn", "Content-Type": "application/json"}
    
    ws_started = False
    # 彻底解除人为倒计时限制：只要任务处于 QUEUED 或 RUNNING，就永远保持轮询守候，直到云端任务自然结束！
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
                tasks = load_tasks()
                for t in tasks:
                    if t.get("taskId") == str(task_id):
                        t.update({
                            "status": "QUEUED",
                            "queueDuration": queue_duration,
                            "duration": queue_duration,
                            "statusText": f"云端排队调度中 (已等待 {queue_duration}s)",
                            "updatedAt": int(time.time())
                        })
                        save_tasks(tasks)
                        break

            # 804 状态表示任务进入 RUNNING，启动 WebSocket 实时管道并保持耗时更新
            if code == 804:
                run_duration = int(time.time() - start_time)
                tasks = load_tasks()
                for t in tasks:
                    if t.get("taskId") == str(task_id):
                        cur_text = t.get("statusText", "")
                        if "采样" not in cur_text and "节点" not in cur_text and "排队等待" not in cur_text:
                            cur_text = f"云端 GPU 正在计算 ({run_duration}s)"
                        t.update({
                            "status": "RUNNING",
                            "duration": run_duration,
                            "statusText": cur_text,
                            "updatedAt": int(time.time())
                        })
                        save_tasks(tasks)
                        break

                if not ws_started and data.get("data"):
                    ws_url = data["data"].get("netWssUrl")
                    if ws_url:
                        ws_started = True
                        asyncio.create_task(listen_websocket_stream(ws_url, str(task_id), api_key))
            
            # 任务执行完毕且有生成结果
            if code == 0 and data.get("data"):
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
                        
                        # 纯远端直链模式：服务器零落盘、零下载中转，直接将官方 COS CDN 远端直链发给客户端！
                        saved_files.append({
                            "filename": filename,
                            "url": file_url,
                            "remoteUrl": file_url,
                            "size": 0,
                            "nodeId": str(item.get("nodeId", "")),
                            "fileType": "video" if is_video else "image"
                        })
                
                # 合并官方直链结果与先前截流的直链，剔除临时 base64 预览
                tasks = load_tasks()
                for t in tasks:
                    if t.get("taskId") == task_id:
                        existing_files = [f for f in t.get("outputs", []) if not f.get("isRealtimePreview")]
                        seen_urls = set()
                        final_outputs = []
                        for f in saved_files + existing_files:
                            u = f.get("url")
                            if u and u not in seen_urls:
                                seen_urls.add(u)
                                final_outputs.append(f)

                        t.update({
                            "status": "SUCCESS",
                            "duration": int(time.time() - start_time),
                            "consumeCoins": total_coins,
                            "outputs": final_outputs,
                            "updatedAt": int(time.time())
                        })
                        save_tasks(tasks)
                        break
                return
            
            # 正在排队或执行中
            elif code in (803, 804) or "RUNNING" in str(msg) or "QUEUED" in str(msg):
                update_task_record(task_id, {
                    "status": "RUNNING",
                    "duration": int(time.time() - start_time),
                    "updatedAt": int(time.time())
                })
            else:
                # 核心容错截流防护：
                # 即使云端因结尾节点报错而返回 FAILED (code 805)，
                # 但只要我们已经截获了真实视频或图像输出，直接判定为生成成功！
                tasks = load_tasks()
                has_captured_real_media = False
                for t in tasks:
                    if t.get("taskId") == task_id:
                        for o in t.get("outputs", []):
                            if (o.get("isRealtime") and not o.get("isRealtimePreview")) or o.get("remoteUrl"):
                                has_captured_real_media = True
                                break
                        break

                if has_captured_real_media:
                    update_task_record(task_id, {
                        "status": "SUCCESS",
                        "duration": int(time.time() - start_time),
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

                    update_task_record(task_id, {
                        "status": "FAILED",
                        "error": err_msg,
                        "duration": int(time.time() - start_time),
                        "updatedAt": int(time.time())
                    })
                    return
        except Exception as e:
            # 临时网络抖动，继续重试
            pass



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

async def get_current_user_optional(request: Request) -> Optional[Dict[str, Any]]:
    """从 Authorization 标头或 Cookie 中解析用户（未登录返回 None）"""
    auth_header = request.headers.get("Authorization")
    token = None
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    if not token:
        token = request.cookies.get("auth_token")
    if not token:
        return None
    
    payload = decode_jwt_token(token)
    if not payload or not payload.get("sub"):
        return None
    
    user = get_user_by_id(payload["sub"])
    if not user or not user.get("isActive", True):
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
        "role": user["role"]
    })
    
    response.set_cookie(key="auth_token", value=token, httponly=True, max_age=86400 * 7, samesite="lax")
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
    
    # Cloudflare Turnstile 验证
    if sys_cfg.get("turnstileEnabled"):
        secret_enc = sys_cfg.get("turnstileSecretKeyEncrypted", "")
        secret_key = decrypt_key(secret_enc) if secret_enc else ""
        if secret_key:
            client_ip = request.client.host if request.client else ""
            ok, msg = await verify_turnstile_token(req.turnstileToken, secret_key, client_ip)
            if not ok:
                raise HTTPException(status_code=400, detail=msg)
    
    user = get_user_by_identifier(req.identifier)
    if not user:
        raise HTTPException(status_code=400, detail="用户名或邮箱不存在")
    if not user.get("isActive", True):
        raise HTTPException(status_code=403, detail="该账户已被管理员停用封禁，请联系管理员")
    
    if not verify_password(req.password, user.get("passwordHash", ""), user.get("salt", "")):
        raise HTTPException(status_code=400, detail="密码错误，请重新输入")
    
    update_user_fields(user["id"], {"lastLogin": int(time.time())})
    user["lastLogin"] = int(time.time())
    
    token = create_jwt_token({
        "sub": user["id"],
        "username": user["username"],
        "role": user["role"]
    })
    response.set_cookie(key="auth_token", value=token, httponly=True, max_age=86400 * 7, samesite="lax")
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

@app.put("/api/admin/users/{user_id}")
def admin_update_user(user_id: str, req: AdminUpdateUserRequest, admin: Dict[str, Any] = Depends(get_current_admin)):
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
    
    if req.points is not None:
        updates["points"] = max(0, int(req.points))
    if req.isActive is not None:
        if user_id == admin["id"] and not req.isActive:
            raise HTTPException(status_code=400, detail="不能封禁当前登录的管理员账号")
        updates["isActive"] = bool(req.isActive)
    
    if updates:
        update_user_fields(user_id, updates)
    
    if req.newPassword and len(req.newPassword.strip()) >= 6:
        set_user_password(user_id, req.newPassword.strip())
    
    fresh = get_user_by_id(user_id)
    return {"status": "ok", "user": sanitize_user(fresh)}

@app.delete("/api/admin/users/{user_id}")
def admin_delete_user(user_id: str, admin: Dict[str, Any] = Depends(get_current_admin)):
    if user_id == admin["id"]:
        raise HTTPException(status_code=400, detail="无法删除当前正在登录的管理员账号")
    
    target = get_user_by_id(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="用户不存在")
    
    delete_user_by_id(user_id)
    return {"status": "ok", "message": f"用户 {target.get('username')} 已被安全删除"}

@app.get("/api/admin/system")
def admin_get_system_config(_: Dict[str, Any] = Depends(get_current_admin)):
    return get_system_config_safe()

@app.put("/api/admin/system")
def admin_update_system_config(req: AdminSystemConfigRequest, _: Dict[str, Any] = Depends(get_current_admin)):
    cfg = load_config()
    sys_cfg = cfg.setdefault("system", {})
    
    if req.siteTitle is not None:
        sys_cfg["siteTitle"] = req.siteTitle.strip()
    if req.turnstileEnabled is not None:
        sys_cfg["turnstileEnabled"] = bool(req.turnstileEnabled)
    if req.turnstileSiteKey is not None:
        sys_cfg["turnstileSiteKey"] = req.turnstileSiteKey.strip()
    if req.turnstileSecretKey is not None and req.turnstileSecretKey.strip():
        raw_secret = req.turnstileSecretKey.strip()
        if not raw_secret.startswith("****") and "****" not in raw_secret:
            sys_cfg["turnstileSecretKeyEncrypted"] = encrypt_key(raw_secret)
    if req.allowRegistration is not None:
        sys_cfg["allowRegistration"] = bool(req.allowRegistration)
    if req.defaultUserPoints is not None:
        sys_cfg["defaultUserPoints"] = max(0, int(req.defaultUserPoints))
    if req.requireLoginToGenerate is not None:
        sys_cfg["requireLoginToGenerate"] = bool(req.requireLoginToGenerate)
    
    save_config(cfg)
    return {"status": "ok", "system": get_system_config_safe(cfg)}

# ----------------- API 路由: 基础配置与密钥池 -----------------

class ConfigUpdateModel(BaseModel):
    apiKey: Optional[str] = None

class AddKeyModel(BaseModel):
    name: str
    apiKey: str
    note: Optional[str] = ""
    setActive: Optional[bool] = False

@app.get("/api/config")
def get_config():
    cfg = load_config()
    active_key_str = get_active_api_key(cfg)
    active_info = None
    for k in cfg.get("apiKeys", []):
        if k.get("id") == cfg.get("activeKeyId"):
            active_info = k
            break
    return {
        "hasKey": bool(active_key_str),
        "activeKeyId": cfg.get("activeKeyId", ""),
        "activeKeyName": active_info.get("name", "") if active_info else "",
        "activeMaskedKey": mask_key(active_key_str) if active_key_str else "",
        "keys": get_api_keys_safe(cfg),
        "workflows": cfg.get("workflows", []),
        "system": get_system_config_safe(cfg)
    }

@app.post("/api/config")
def update_config(data: ConfigUpdateModel):
    """向下兼容的旧版单 Key 更新接口（已全面升级为安全落盘加密与池化管理）"""
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
def list_keys():
    """获取所有已存储的 API Key 列表（全流程脱敏，绝不向浏览器暴露明文或密文）"""
    cfg = load_config()
    return {
        "status": "ok",
        "keys": get_api_keys_safe(cfg),
        "activeKeyId": cfg.get("activeKeyId", "")
    }

@app.post("/api/keys")
def add_key(data: AddKeyModel):
    """添加新的 API Key（后端即时 AES-256 / Fernet 落盘加密，杜绝明文留存）"""
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
def activate_key(key_id: str):
    """快速切换当前生效的活动 API Key"""
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
def delete_key(key_id: str):
    """删除指定的 API Key，如删除了当前激活项则自动平滑切换至下一项"""
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
def test_key(key_id: str):
    """实时连通性测试：调用 RunningHub 官方鉴权端点验证 Key 状态"""
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
    defaultParams: Optional[Dict[str, Any]] = None

@app.post("/api/workflows")
def add_or_update_workflow(wf: WorkflowModel):
    cfg = load_config()
    workflows = cfg.get("workflows", [])
    existing = False
    for i, w in enumerate(workflows):
        if w.get("id") == wf.id:
            workflows[i] = wf.dict()
            existing = True
            break
    if not existing:
        workflows.append(wf.dict())
    cfg["workflows"] = workflows
    save_config(cfg)
    return {"status": "ok", "workflow": wf.dict()}

@app.delete("/api/workflows/{workflow_id}")
def delete_workflow(workflow_id: str):
    cfg = load_config()
    cfg["workflows"] = [w for w in cfg.get("workflows", []) if w.get("id") != workflow_id]
    save_config(cfg)
    return {"status": "ok"}

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

    # 动态深度结构解析
    prompt_nodes = []
    sampler_nodes = []
    latent_nodes = []
    image_nodes = []
    video_nodes = []
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
        "status": "ok",
        "workflowId": str(workflow_id),
        "totalNodes": len(nodes),
        "dynamicSchema": {
            "promptNodes": categorized_prompts,
            "samplerNode": sampler_nodes[0] if sampler_nodes else None,
            "latentNode": latent_nodes[0] if latent_nodes else None,
            "imageNodes": image_nodes,
            "videoNodes": video_nodes,
            "qualityNodes": quality_nodes,
            "allEditableNodes": all_editable_nodes
        }
    }

@app.post("/api/upload")
async def upload_file_to_runninghub(file: UploadFile = File(...)):
    """上传本地图片或视频到 RunningHub，返回远程存储名，方便传入 LoadImage / VHS_LoadVideo 节点"""
    cfg = load_config()
    api_key = get_active_api_key(cfg)
    if not api_key:
        raise HTTPException(status_code=400, detail="未配置有效 API Key，请先进入顶部切换或设置中配置启用")

    file_bytes = await file.read()
    upload_url = "https://www.runninghub.ai/openapi/v2/media/upload/binary"
    headers = {
        "Authorization": f"Bearer {api_key}"
    }

    try:
        files = {"file": (file.filename, file_bytes, file.content_type)}
        res = await asyncio.to_thread(requests.post, upload_url, headers=headers, files=files, timeout=120)
        resp_data = res.json()
        if resp_data.get("code") == 0:
            data = resp_data.get("data", {})
            return {
                "status": "ok",
                "fileName": data.get("fileName"),
                "downloadUrl": data.get("download_url"),
                "fileType": data.get("type", "file")
            }
        else:
            raise HTTPException(status_code=400, detail=resp_data.get("msg") or "上传失败")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"上传至 RunningHub 发生异常: {str(e)}")

class GenerateRequest(BaseModel):
    workflowId: str
    nodeInfoList: List[Dict[str, Any]]
    positivePrompt: Optional[str] = None
    negativePrompt: Optional[str] = None
    workflowName: Optional[str] = None
    taskType: Optional[str] = "Standard"

@app.post("/api/generate")
async def generate_task(
    req: GenerateRequest, 
    background_tasks: BackgroundTasks,
    current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    cfg = load_config()
    sys_cfg = cfg.get("system", {})
    if sys_cfg.get("requireLoginToGenerate") and not current_user:
        raise HTTPException(status_code=401, detail="当前系统已开启强制登录，请先登录后再提交生成任务")

    api_key = get_active_api_key(cfg)
    if not api_key:
        raise HTTPException(status_code=400, detail="未配置有效 API Key，请先进入顶部切换或设置中添加启用密钥")

    # 规范化算力档位：Standard (标准极速独享通道) vs Lite (经济共享排队通道)
    task_type = "Lite" if req.taskType and req.taskType.strip().lower() == "lite" else "Standard"

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
            timeout=20
        )
        data = res.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"调用 RunningHub 创建任务失败: {str(e)}")

    if data.get("code") != 0:
        raise HTTPException(status_code=400, detail=data.get("msg") or "创建任务失败")

    task_id = data.get("data", {}).get("taskId")
    net_wss_url = data.get("data", {}).get("netWssUrl")

    user_id = current_user["id"] if current_user else ""
    user_name = current_user["username"] if current_user else "匿名访客"

    task_record = {
        "taskId": str(task_id),
        "workflowId": str(req.workflowId),
        "workflowName": req.workflowName or f"工作流 {req.workflowId}",
        "taskType": task_type,
        "userId": user_id,
        "username": user_name,
        "positivePrompt": req.positivePrompt or "",
        "negativePrompt": req.negativePrompt or "",
        "status": "QUEUED",
        "createdAt": int(time.time()),
        "updatedAt": int(time.time()),
        "duration": 0,
        "consumeCoins": "0",
        "outputs": [],
        "nodeInfoList": req.nodeInfoList
    }

    tasks = load_tasks()
    tasks.insert(0, task_record)
    save_tasks(tasks)

    # 若为登录用户，累加其生成任务计数
    if current_user:
        try:
            u_info = get_user_by_id(user_id)
            if u_info:
                update_user_fields(user_id, {"taskCount": u_info.get("taskCount", 0) + 1})
        except Exception:
            pass

    # 启动后台双轨守护：轮询 + 实时 WebSocket 毫秒级截流
    background_tasks.add_task(poll_task_status, str(task_id), api_key)
    if net_wss_url:
        background_tasks.add_task(listen_websocket_stream, net_wss_url, str(task_id), api_key)

    return {
        "status": "ok",
        "taskId": str(task_id),
        "task": task_record
    }

ACTIVE_POLL_TASKS = set()

@app.get("/api/tasks")
async def list_tasks(current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)):
    all_tasks = load_tasks()
    cfg = load_config()
    api_key = get_active_api_key(cfg)
    if api_key:
        for t in all_tasks:
            tid = str(t.get("taskId"))
            if t.get("status") in ["RUNNING", "QUEUED"] and tid not in ACTIVE_POLL_TASKS and tid not in CANCELLED_TASKS:
                ACTIVE_POLL_TASKS.add(tid)
                asyncio.create_task(poll_task_status(tid, api_key))
    
    # 权限隔离过滤：管理员看全部，普通用户看自己，未登录看公开历史
    if current_user and current_user.get("role") == "admin":
        return all_tasks
    elif current_user:
        return [t for t in all_tasks if str(t.get("userId")) == str(current_user["id"]) or not t.get("userId")]
    else:
        return [t for t in all_tasks if not t.get("userId")]

@app.get("/api/admin/tasks")
def admin_list_all_tasks(_: Dict[str, Any] = Depends(get_current_admin)):
    """管理员全量任务审计视图"""
    return load_tasks()
    return tasks

@app.get("/api/tasks/{task_id}")
def get_task(task_id: str):
    tasks = load_tasks()
    for t in tasks:
        if t.get("taskId") == task_id:
            return t
    raise HTTPException(status_code=404, detail="Task not found")

@app.post("/api/tasks/{task_id}/cancel")
async def cancel_task_endpoint(task_id: str):
    """主动取消正在运行或排队中的任务，同时通知 RunningHub 云端与终止本地后台协程"""
    task_id_str = str(task_id).strip()
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

    # 更新本地任务状态为 CANCELLED
    tasks = load_tasks()
    for t in tasks:
        if str(t.get("taskId")) == task_id_str:
            t["status"] = "CANCELLED"
            t["error"] = "用户已主动取消任务"
            t["updatedAt"] = int(time.time())
            break
    save_tasks(tasks)

    return {
        "status": "ok",
        "taskId": task_id_str,
        "cloudStatus": cloud_status,
        "message": f"任务已成功取消 ({cloud_status})"
    }

@app.get("/api/gallery")
def get_gallery(current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)):
    """获取已生成媒体输出（优先直接读取任务远端直链，支持多用户与管理员隔离）"""
    all_tasks = load_tasks()
    if current_user and current_user.get("role") == "admin":
        tasks = all_tasks
    elif current_user:
        tasks = [t for t in all_tasks if str(t.get("userId")) == str(current_user["id"]) or not t.get("userId")]
    else:
        tasks = [t for t in all_tasks if not t.get("userId")]

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
            items.append({
                "filename": fname,
                "url": url,
                "remoteUrl": out.get("remoteUrl", url),
                "size": out.get("size", 0),
                "createdAt": created_at,
                "fileType": out.get("fileType", "image"),
                "taskId": t.get("taskId"),
                "username": t.get("username", "")
            })
    items.sort(key=lambda x: x["createdAt"], reverse=True)
    return items

@app.delete("/api/gallery/{filename}")
def delete_gallery_file(filename: str, current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)):
    tasks = load_tasks()
    changed = False
    for t in tasks:
        # 如果非管理员且任务有归属，只有任务所属人可以删除
        if current_user and current_user.get("role") != "admin" and t.get("userId"):
            if str(t.get("userId")) != str(current_user["id"]):
                continue

        new_outs = [o for o in t.get("outputs", []) if o.get("filename") != filename and os.path.basename(o.get("url", "").split("?")[0]) != filename]
        if len(new_outs) != len(t.get("outputs", [])):
            t["outputs"] = new_outs
            changed = True
    if changed:
        save_tasks(tasks)
    
    safe_name = os.path.basename(filename)
    fpath = os.path.join(OUTPUTS_DIR, safe_name)
    if os.path.exists(fpath):
        try:
            os.remove(fpath)
        except Exception:
            pass
    return {"status": "ok"}

# 挂载静态文件
app.mount("/outputs", StaticFiles(directory=OUTPUTS_DIR), name="outputs")
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    # host 0.0.0.0 允许局域网或公网通过服务器 IP / 域名访问
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
