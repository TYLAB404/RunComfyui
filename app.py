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
import io
import re
from typing import Dict, Any, List, Optional, Set, Tuple
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, BackgroundTasks, Request, Depends, Response
from fastapi.responses import FileResponse, RedirectResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from security import encrypt_key, decrypt_key, mask_key, verify_key_with_runninghub
from database import (
    init_database, get_db_connection, db_save_task, db_update_task,
    db_get_task, db_delete_task, db_load_tasks, db_deduct_user_points,
    db_refund_user_points, db_bump_token_version, db_get_announcements,
    db_save_announcement, db_update_announcement, db_delete_announcement,
    db_delete_tasks_batch, is_rate_limited, record_failed_attempt, clear_failed_attempts,
    db_generate_cdkeys, db_redeem_cdkey, db_list_cdkeys, db_void_cdkey,
    db_delete_cdkey, db_get_unused_cdkeys_export, is_redeem_rate_limited,
    record_failed_redeem_attempt, clear_failed_redeem_attempts
)
from auth import (
    load_users, save_users, sanitize_user, get_user_by_id, get_user_by_identifier,
    create_user, update_user_fields, set_user_password, delete_user_by_id,
    verify_password, create_jwt_token, decode_jwt_token, verify_turnstile_token
)

app = FastAPI(title="RunningHub Web Controller", version="1.0.0")

@app.on_event("startup")
async def app_startup_watchdogs():
    asyncio.create_task(key_pool_watchdog_loop())
    asyncio.create_task(key_pool_health_inspector_loop())


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

def sort_workflows(workflows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """工作流排序：置顶排在最前 (按置顶时间倒序)，其次官方推荐，再次更新时间"""
    return sorted(
        workflows,
        key=lambda w: (
            1 if w.get("isPinned") else 0,
            int(w.get("pinnedAt") or 0),
            1 if w.get("isOfficial") else 0,
            int(w.get("updatedAt") or 0)
        ),
        reverse=True
    )

def filter_workflows_for_user(workflows: List[Dict[str, Any]], current_user: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """多租户工作流隔离策略：管理员全量可见；普通用户仅可见上架的官方工作流 + 本人创建的上架工作流"""
    sorted_all = sort_workflows(workflows)
    if current_user and current_user.get("role") == "admin":
        return sorted_all
    
    res = []
    user_id_str = str(current_user["id"]) if current_user else ""
    for w in sorted_all:
        is_official = bool(w.get("isOfficial", False))
        is_active = bool(w.get("isActive", True))
        owner_id = str(w.get("ownerId", ""))
        
        if is_official and is_active:
            res.append(w)
        elif user_id_str and owner_id == user_id_str and is_active:
            res.append(w)
            
    return res

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
        "hideAuxiliaryAudioChain": True,
        "imgbedEnabled": True,
        "imgbedUploadUrl": "https://imgbed.2364498.xyz/upload",
        "imgbedAuthHeaderEncrypted": encrypt_key("Bearer imgbed_165f2632dbcc32e7d3187a3b36051a8785fa6bc6d5834b0dd69ee07134a139b2"),
        "imgbedRootFolder": "RunComfyui",
        "imgbedIsolateByUser": True,
        "imgbedConcurrency": 3
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
    """返回脱敏的系统全局配置（隐藏 Turnstile 密钥与图床密钥明文）"""
    if cfg is None:
        cfg = load_config()
    sys_cfg = dict(cfg.get("system", {}))
    secret_enc = sys_cfg.pop("turnstileSecretKeyEncrypted", "")
    secret_raw = decrypt_key(secret_enc) if secret_enc else ""
    sys_cfg["turnstileSecretKeyMasked"] = mask_key(secret_raw) if secret_raw else ""
    sys_cfg["hasTurnstileSecret"] = bool(secret_raw)

    # ImgBed 图床敏感密钥脱敏
    imgbed_enc = sys_cfg.pop("imgbedAuthHeaderEncrypted", "")
    imgbed_raw = decrypt_key(imgbed_enc) if imgbed_enc else ""
    sys_cfg["imgbedAuthHeaderMasked"] = mask_key(imgbed_raw) if imgbed_raw else ""
    sys_cfg["hasImgbedAuthHeader"] = bool(imgbed_raw)
    return sys_cfg

def get_imgbed_config(cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """获取内部图床配置（含解密后的 AuthHeader）"""
    if cfg is None:
        cfg = load_config()
    sys_cfg = cfg.get("system", {})
    enc_auth = sys_cfg.get("imgbedAuthHeaderEncrypted", "")
    raw_auth = decrypt_key(enc_auth) if enc_auth else ""
    return {
        "enabled": bool(sys_cfg.get("imgbedEnabled", True)),
        "uploadUrl": sys_cfg.get("imgbedUploadUrl", "https://imgbed.2364498.xyz/upload"),
        "rawAuthHeader": raw_auth,
        "authHeaderMasked": mask_key(raw_auth) if raw_auth else "",
        "hasAuthHeader": bool(raw_auth),
        "rootFolder": sys_cfg.get("imgbedRootFolder", "RunComfyui") or "RunComfyui",
        "isolateByUser": bool(sys_cfg.get("imgbedIsolateByUser", True)),
        "concurrency": int(sys_cfg.get("imgbedConcurrency", 3))
    }


# ----------------- RunningHub 多 API Key 轮询调度器与并发互斥管理器 -----------------


# ----------------- 运维告警邮件与 SMTP 客户端引擎 -----------------

_ALERTED_KEY_INCIDENTS: Dict[str, float] = {}

def send_admin_alert_email(subject: str, html_body: str) -> Tuple[bool, str]:
    """
    发送系统运维告警邮件至管理员指定邮箱
    支持 SSL (465) 与 TLS (587/25) 协议，密码加密存储
    """
    cfg = load_config()
    smtp_cfg = cfg.get("system", {}).get("smtp", {})
    if not smtp_cfg.get("enabled"):
        return False, "SMTP 邮件告警未开启"
    
    host = (smtp_cfg.get("host") or "").strip()
    port = int(smtp_cfg.get("port") or 465)
    user = (smtp_cfg.get("user") or "").strip()
    enc_pwd = smtp_cfg.get("passwordEncrypted") or ""
    pwd = decrypt_key(enc_pwd) if enc_pwd else ""
    admin_email = (smtp_cfg.get("adminEmail") or "").strip()
    
    if not host or not user or not pwd or not admin_email:
        return False, "SMTP 邮件配置不完整（缺少主机、账号、密码或接收邮箱）"
    
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    from email.header import Header

    msg = MIMEMultipart()
    msg['From'] = Header(f"RunComfyUI 运维管家 <{user}>", 'utf-8')
    msg['To'] = Header(admin_email, 'utf-8')
    msg['Subject'] = Header(subject, 'utf-8')
    msg.attach(MIMEText(html_body, 'html', 'utf-8'))

    try:
        if port == 465:
            server = smtplib.SMTP_SSL(host, port, timeout=12)
        else:
            server = smtplib.SMTP(host, port, timeout=12)
            server.starttls()
        server.login(user, pwd)
        server.sendmail(user, [admin_email], msg.as_string())
        server.quit()
        return True, "告警邮件已成功发送"
    except Exception as e:
        print(f"[SMTP Error] Failed to send alert email: {e}")
        return False, f"邮件发送失败: {str(e)}"

async def async_notify_key_incident(key_id: str, key_name: str, masked_key: str, error_msg: str):
    """异步检测并发送 Key 异常告警邮件（带 4 小时冷却，杜绝频繁轰炸站长邮箱）"""
    now = time.time()
    last_sent = _ALERTED_KEY_INCIDENTS.get(key_id, 0)
    if now - last_sent < 14400:  # 4 小时内不重复发送同一 Key 告警
        return
    _ALERTED_KEY_INCIDENTS[key_id] = now
    
    html = f"""
    <div style="font-family: sans-serif; background-color: #0b0f19; color: #e2e8f0; padding: 24px; border-radius: 16px; max-width: 600px; margin: 0 auto; border: 1px solid #334155;">
      <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 16px;">
        <span style="font-size: 24px;">🚨</span>
        <h2 style="margin: 0; color: #f43f5e; font-size: 20px;">RunningHub 算力账号异常熔断告警</h2>
      </div>
      <p style="font-size: 14px; line-height: 1.6; color: #cbd5e1;">
        尊敬的管理员，系统在任务调度/自动巡检中检测到底层 API Key 出现致命异常，<b>已自动将其移出派单队列（熔断隔离）</b>。
      </p>
      <div style="background-color: #1e293b; padding: 16px; border-radius: 12px; margin: 16px 0; font-size: 13px;">
        <p style="margin: 6px 0;"><b>异常账号名称：</b> <span style="color: #38bdf8;">{key_name}</span></p>
        <p style="margin: 6px 0;"><b>Key 标识与掩码：</b> <code style="color: #a78bfa;">{key_id} ({masked_key})</code></p>
        <p style="margin: 6px 0;"><b>官方具体报错：</b> <span style="color: #f43f5e; font-family: monospace;">{error_msg}</span></p>
        <p style="margin: 6px 0;"><b>检测告警时间：</b> {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}</p>
      </div>
      <div style="background-color: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); padding: 12px; border-radius: 10px; font-size: 12px; color: #34d399;">
        🛡️ <b>用户体验保护说明：</b><br>
        系统已自动 PASS 绕过该账号，并将后续用户任务<b>100% 无感故障转移至其他健康 Key</b>，用户端未产生任何封禁报错感知。
      </div>
      <p style="font-size: 12px; color: #94a3b8; margin-top: 20px;">
        建议操作：请登录 RunningHub 官网检查该账号状态（如是否被风控封禁、是否欠费），并在后台控制台更换或恢复该 Key。
      </p>
    </div>
    """
    await asyncio.to_thread(
        send_admin_alert_email,
        f"【紧急运维告警】RunningHub 账号 [{key_name}] 已被自动熔断隔离",
        html
    )


class KeyPoolManager:
    """
    RunningHub 多 API Key 轮询调度器与单并发互斥池 (支持健康熔断与无感故障转移)
    """
    def __init__(self):
        self._states: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()
        self._waiters: List[asyncio.Event] = []

    def _get_all_keys(self) -> List[Dict[str, Any]]:
        cfg = load_config()
        return cfg.get("apiKeys", [])

    async def acquire_free_key(self, task_id: str, exclude_key_ids: Optional[Set[str]] = None) -> Optional[Tuple[str, str, str]]:
        """
        原子挑选一个【空闲且健康】的 API Key。
        若传入 exclude_key_ids，则直接跳过指定的故障 Key（用于静默无感自动故障转移）。
        """
        async with self._lock:
            all_keys = self._get_all_keys()
            if not all_keys:
                return None
            
            excludes = exclude_key_ids or set()
            for k in all_keys:
                kid = k.get("id")
                if kid in excludes:
                    continue
                st = self._states.setdefault(kid, {
                    "is_busy": False, 
                    "task_id": None, 
                    "busy_since": None,
                    "is_healthy": True,
                    "health_error": "",
                    "last_checked": 0
                })
                # 只有未占用 且 状态健康 的 Key 才能接单
                if not st["is_busy"] and st.get("is_healthy", True):
                    raw = decrypt_key(k.get("keyEncrypted", ""))
                    if raw:
                        st["is_busy"] = True
                        st["task_id"] = str(task_id)
                        st["busy_since"] = time.time()
                        return kid, raw, k.get("name", "未命名密钥")
            return None

    async def wait_for_free_key(self, task_id: str, timeout: float = 300.0, exclude_key_ids: Optional[Set[str]] = None) -> Optional[Tuple[str, str, str]]:
        start = time.time()
        while time.time() - start < timeout:
            key_info = await self.acquire_free_key(task_id, exclude_key_ids=exclude_key_ids)
            if key_info:
                return key_info
            
            ev = asyncio.Event()
            async with self._lock:
                self._waiters.append(ev)
            
            try:
                await asyncio.wait_for(ev.wait(), timeout=min(3.0, max(0.5, timeout - (time.time() - start))))
            except (asyncio.TimeoutError, TimeoutError):
                pass
            finally:
                async with self._lock:
                    if ev in self._waiters:
                        self._waiters.remove(ev)
        return None

    async def release_key(self, key_id: str, task_id: Optional[str] = None):
        async with self._lock:
            if key_id in self._states:
                st = self._states[key_id]
                if task_id is None or st.get("task_id") == str(task_id):
                    st["is_busy"] = False
                    st["task_id"] = None
                    st["busy_since"] = None
            for w in self._waiters:
                w.set()
            self._waiters.clear()

    async def release_key_by_task_id(self, task_id: str):
        async with self._lock:
            for kid, st in self._states.items():
                if st.get("task_id") == str(task_id):
                    st["is_busy"] = False
                    st["task_id"] = None
                    st["busy_since"] = None
            for w in self._waiters:
                w.set()
            self._waiters.clear()

    async def mark_key_unhealthy(self, key_id: str, error_reason: str):
        """将某个 Key 标记为故障/被封禁熔断，并触发后台告警邮件"""
        key_name = key_id
        masked = "****"
        async with self._lock:
            st = self._states.setdefault(key_id, {
                "is_busy": False, "task_id": None, "busy_since": None,
                "is_healthy": True, "health_error": "", "last_checked": 0
            })
            st["is_healthy"] = False
            st["health_error"] = str(error_reason)
            st["is_busy"] = False
            st["task_id"] = None
            st["busy_since"] = None
            
            # 查找名称与掩码用于邮件
            for k in self._get_all_keys():
                if k.get("id") == key_id:
                    key_name = k.get("name", key_id)
                    masked = mask_key(decrypt_key(k.get("keyEncrypted", "")))
                    break
            
            # 唤醒其他排队者使用其余健康 Key
            for w in self._waiters:
                w.set()
            self._waiters.clear()

        # 异步派发邮件告警
        asyncio.create_task(async_notify_key_incident(key_id, key_name, masked, error_reason))

    async def mark_key_healthy(self, key_id: str):
        """管理员一键恢复某个 Key 为健康可用状态"""
        async with self._lock:
            if key_id in self._states:
                st = self._states[key_id]
                st["is_healthy"] = True
                st["health_error"] = ""
            _ALERTED_KEY_INCIDENTS.pop(key_id, None)
            for w in self._waiters:
                w.set()
            self._waiters.clear()

    async def inspect_all_keys(self) -> List[Dict[str, Any]]:
        """全池主动巡检所有 Key，更新健康状态"""
        all_keys = self._get_all_keys()
        results = []
        for k in all_keys:
            kid = k.get("id")
            name = k.get("name", "未命名密钥")
            raw = decrypt_key(k.get("keyEncrypted", ""))
            masked = mask_key(raw)
            valid, msg = await asyncio.to_thread(verify_key_with_runninghub, raw)
            
            async with self._lock:
                st = self._states.setdefault(kid, {
                    "is_busy": False, "task_id": None, "busy_since": None,
                    "is_healthy": True, "health_error": "", "last_checked": 0
                })
                st["last_checked"] = time.time()
                if valid:
                    st["is_healthy"] = True
                    st["health_error"] = ""
                else:
                    st["is_healthy"] = False
                    st["health_error"] = msg
                    st["is_busy"] = False
                    st["task_id"] = None
            
            if not valid:
                asyncio.create_task(async_notify_key_incident(kid, name, masked, msg))

            results.append({
                "id": kid,
                "name": name,
                "maskedKey": masked,
                "isValid": valid,
                "message": msg
            })
        return results

    def get_pool_status(self) -> List[Dict[str, Any]]:
        all_keys = self._get_all_keys()
        now = time.time()
        res = []
        for k in all_keys:
            kid = k.get("id")
            raw = decrypt_key(k.get("keyEncrypted", ""))
            st = self._states.get(kid, {
                "is_busy": False, "task_id": None, "busy_since": None,
                "is_healthy": True, "health_error": "", "last_checked": 0
            })
            is_busy = bool(st.get("is_busy"))
            is_healthy = bool(st.get("is_healthy", True))
            busy_duration = int(now - st["busy_since"]) if (is_busy and st.get("busy_since")) else 0
            res.append({
                "id": kid,
                "name": k.get("name", "未命名密钥"),
                "maskedKey": mask_key(raw),
                "isBusy": is_busy,
                "isHealthy": is_healthy,
                "healthError": st.get("health_error", ""),
                "currentTaskId": st.get("task_id") if is_busy else None,
                "busyDuration": busy_duration,
                "note": k.get("note", "")
            })
        return res

    async def reset_key(self, key_id: str):
        await self.release_key(key_id)
        await self.mark_key_healthy(key_id)

    def get_busy_count(self) -> Tuple[int, int]:
        all_keys = self._get_all_keys()
        busy_keys = sum(1 for k in all_keys if self._states.get(k.get("id"), {}).get("is_busy"))
        return busy_keys, len(all_keys)

    def get_queue_stats(self) -> Dict[str, Any]:
        all_keys = self._get_all_keys()
        total_keys = len(all_keys)
        healthy_keys = sum(1 for k in all_keys if self._states.get(k.get("id"), {}).get("is_healthy", True))
        busy_keys = sum(1 for k in all_keys if self._states.get(k.get("id"), {}).get("is_busy"))
        waiting_tasks = len(self._waiters)
        return {
            "totalKeys": total_keys,
            "healthyKeys": healthy_keys,
            "bannedKeys": total_keys - healthy_keys,
            "busyKeys": busy_keys,
            "freeKeys": max(0, healthy_keys - busy_keys),
            "waitingTasks": waiting_tasks
        }

KEY_POOL_MANAGER = KeyPoolManager()

async def key_pool_watchdog_loop():
    """纯状态对账守护协程：每 20 秒自检一次，仅同步已完成/取消的任务释放"""
    while True:
        await asyncio.sleep(20)
        try:
            async with KEY_POOL_MANAGER._lock:
                for kid, st in KEY_POOL_MANAGER._states.items():
                    if st.get("is_busy"):
                        tid = st.get("task_id")
                        if tid:
                            task = db_get_task(tid)
                            if task and task.get("status") in ("SUCCESS", "FAILED", "CANCELLED"):
                                print(f"[Watchdog] Task {tid} finished ({task.get('status')}), auto-releasing key {kid}")
                                st["is_busy"] = False
                                st["task_id"] = None
                                st["busy_since"] = None
        except Exception as e:
            print(f"[Watchdog Error] {e}")

async def key_pool_health_inspector_loop():
    """无人值守自动健康巡检守护协程：每 30 分钟对所有 Key 巡检一次，发现异常自动隔离并邮件告警"""
    while True:
        await asyncio.sleep(1800)  # 30 分钟自检一次
        try:
            print("[Health Inspector] Starting periodic full pool health inspection...")
            await KEY_POOL_MANAGER.inspect_all_keys()
        except Exception as e:
            print(f"[Health Inspector Error] {e}")



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

# ----------------- 自建图床流式中继与流量整形异步工作引擎 -----------------

IMGBED_SEMAPHORE = asyncio.Semaphore(3)

def _sanitize_folder_name(name: str) -> str:
    if not name:
        return "guest"
    cleaned = re.sub(r'[^\w\-]', '_', str(name).strip())
    return cleaned or "guest"

async def sync_single_file_to_imgbed(
    file_url: str,
    default_filename: str,
    username: str,
    imgbed_cfg: Dict[str, Any]
) -> Optional[str]:
    """
    通过内存流式中继，将远程文件上传到自建图床（零硬盘落地，支持子文件夹隔离）
    """
    if not imgbed_cfg.get("enabled"):
        return None
    raw_auth = imgbed_cfg.get("rawAuthHeader")
    if not raw_auth:
        return None
        
    upload_base = imgbed_cfg.get("uploadUrl", "https://imgbed.2364498.xyz/upload").strip()
    root_folder = imgbed_cfg.get("rootFolder", "RunComfyui").strip() or "RunComfyui"
    
    if imgbed_cfg.get("isolateByUser", True):
        user_folder = _sanitize_folder_name(username)
        target_folder = f"{root_folder}/{user_folder}"
    else:
        target_folder = root_folder

    sep = "&" if "?" in upload_base else "?"
    upload_url = f"{upload_base}{sep}uploadFolder={urllib.parse.quote(target_folder)}"

    # 1. 内存流式拉取远程或本地文件（零硬盘写入）
    file_bytes = b""
    content_type = ""
    if file_url.startswith("/outputs/") or file_url.startswith("outputs/"):
        local_rel = file_url.lstrip("/")
        if os.path.exists(local_rel):
            try:
                with open(local_rel, "rb") as fp:
                    file_bytes = fp.read()
            except Exception as e:
                print(f"[ImgBed Warning] Local read failed for {file_url}: {e}")
                return "EXPIRED"
        else:
            print(f"[ImgBed Notice] Local file missing at {file_url}, marking as expired")
            return "EXPIRED"
    elif file_url.startswith("http://") or file_url.startswith("https://"):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(file_url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        file_bytes = await resp.read()
                        content_type = resp.headers.get("Content-Type") or "application/octet-stream"
                    elif resp.status in (404, 403, 410):
                        print(f"[ImgBed Notice] Remote source missing/expired (HTTP {resp.status}) at {file_url}")
                        return "EXPIRED"
                    else:
                        print(f"[ImgBed Warning] Remote returned HTTP {resp.status} for {file_url}")
                        return None
        except Exception as e:
            print(f"[ImgBed Warning] Stream fetch failed from {file_url}: {e}")
            return None
    else:
        return "EXPIRED"

    if not file_bytes:
        return None

    fname = default_filename or os.path.basename(file_url.split("?")[0]) or "output.png"
    if not content_type or content_type == "application/octet-stream":
        ext = os.path.splitext(fname)[1].lower()
        if ext in [".png", ".jpg", ".jpeg", ".webp"]:
            content_type = f"image/{ext.lstrip('.')}" if ext != ".jpg" else "image/jpeg"
        elif ext in [".mp4", ".webm"]:
            content_type = f"video/{ext.lstrip('.')}"
        elif ext in [".mp3", ".wav", ".ogg", ".flac", ".m4a"]:
            content_type = f"audio/{ext.lstrip('.')}"

    headers = {"Authorization": raw_auth}
    
    # 2. 信号量排队防打爆
    async with IMGBED_SEMAPHORE:
        for attempt in range(2):
            try:
                def _do_upload():
                    files = {"file": (fname, io.BytesIO(file_bytes), content_type)}
                    return requests.post(upload_url, headers=headers, files=files, timeout=30)
                
                up_resp = await asyncio.to_thread(_do_upload)
                if up_resp.status_code == 200:
                    data = up_resp.json()
                    src = None
                    if isinstance(data, list) and len(data) > 0:
                        src = data[0].get("src")
                    elif isinstance(data, dict):
                        src = data.get("src") or data.get("url")
                    
                    if src:
                        if src.startswith("http://") or src.startswith("https://"):
                            return src
                        parsed_base = urllib.parse.urlparse(upload_base)
                        domain = f"{parsed_base.scheme}://{parsed_base.netloc}"
                        clean_src = "/" + src.lstrip("/")
                        return f"{domain}{clean_src}"
            except Exception as e:
                print(f"[ImgBed Warning] Upload attempt {attempt+1} error: {e}")
            await asyncio.sleep(1.0)
            
    return None

async def sync_task_outputs_to_imgbed(task_id: str):
    """
    后台任务：在任务生成成功后，平滑将各个成果流式备份到用户隔离图床文件夹。
    注意：用户的任务展示与下载直链必须严格保持为 RunningHub 原始链接 (url/remoteUrl)，
    图床链接仅作为管理员数据归档备份存储在 imgbedUrl 中！
    """
    try:
        t = db_get_task(str(task_id))
        if not t:
            return
        outputs = t.get("outputs", [])
        if not outputs:
            return
        
        cfg = load_config()
        imgbed_cfg = get_imgbed_config(cfg)
        if not imgbed_cfg.get("enabled"):
            return
            
        username = t.get("username") or "guest"
        updated = False
        new_outputs = []
        
        for out in outputs:
            # 若已备份到图床，保留并跳过
            if out.get("imgbedUrl"):
                if "imgbed.2364498.xyz" in out.get("url", "") and out.get("remoteUrl"):
                    out_fix = dict(out)
                    out_fix["url"] = out["remoteUrl"]
                    new_outputs.append(out_fix)
                    updated = True
                else:
                    new_outputs.append(out)
                continue

            # 若此前已标记为源端失效/已过期，无需反复无休止尝试重试
            if out.get("sourceExpired"):
                new_outputs.append(out)
                continue
            
            cur_url = out.get("remoteUrl") or out.get("url") or ""
            if "imgbed.2364498.xyz" in cur_url and out.get("remoteUrl"):
                cur_url = out.get("remoteUrl")
                
            if not cur_url:
                new_outputs.append(out)
                continue
                
            fname = out.get("filename") or os.path.basename(cur_url.split("?")[0])
            perm_url = await sync_single_file_to_imgbed(cur_url, fname, username, imgbed_cfg)
            if perm_url == "EXPIRED":
                out_copy = dict(out)
                out_copy["sourceExpired"] = True
                out_copy["imgbedError"] = "原厂源端文件已失效/丢失 (404)"
                new_outputs.append(out_copy)
                updated = True
                print(f"[ImgBed] Output marked as expired for Task {task_id} ({username})")
            elif perm_url:
                out_copy = dict(out)
                if out.get("remoteUrl"):
                    out_copy["url"] = out["remoteUrl"]
                elif not out_copy.get("url") or "imgbed.2364498.xyz" in out_copy.get("url", ""):
                    out_copy["url"] = cur_url
                out_copy["remoteUrl"] = cur_url
                out_copy["imgbedUrl"] = perm_url
                out_copy["storage"] = "imgbed"
                out_copy["sourceExpired"] = False
                out_copy["imgbedFolder"] = f"{imgbed_cfg['rootFolder']}/{_sanitize_folder_name(username)}"
                out_copy["imgbedSyncedAt"] = int(time.time())
                new_outputs.append(out_copy)
                updated = True
                print(f"[ImgBed] Successfully backed up output for Task {task_id} ({username}) -> {perm_url} (User keeps original RunningHub URL)")
            else:
                new_outputs.append(out)
                
        if updated:
            update_task_record(str(task_id), {"outputs": new_outputs, "updatedAt": int(time.time())})
    except Exception as e:
        print(f"[ImgBed Error] Error syncing task {task_id}: {e}")

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


async def poll_task_status(task_id: str, api_key: str, key_id: Optional[str] = None):
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

                # 813 状态表示云端 GPU 正在分配算力排队中 (此时云端 100% 不计费)
                if code == 813:
                    queue_duration = int(time.time() - start_time)
                    update_task_record(str(task_id), {
                        "status": "QUEUED",
                        "duration": queue_duration,
                        "statusText": f"已接入 GPU 通道 · 云端调度中 ({queue_duration}s · 排队不扣费)",
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
                    asyncio.create_task(sync_task_outputs_to_imgbed(str(task_id)))
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
                        asyncio.create_task(sync_task_outputs_to_imgbed(str(task_id)))
                        return
                    else:
                        fail_data = data.get("data")
                        raw_err = str(msg or "")
                        err_msg = raw_err or "任务执行异常"
                        is_timeout = False

                        # 深度精准识别 RunningHub 云端超时错误码 (806, 807, 810) 与各类超时关键词
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

                        # 自动退还用户扣除的算力点数 (P0-5 计费闭环)
                        if cur_t and cur_t.get("userId") and cur_t.get("cost"):
                            cost_val = int(cur_t.get("cost", 0))
                            if cost_val > 0:
                                db_refund_user_points(
                                    user_id=cur_t["userId"],
                                    amount=cost_val,
                                    task_id=str(task_id),
                                    reason=f"任务渲染超时/失败全额退还算力 ({task_id})"
                                )
                                update_task_record(str(task_id), {"cost": 0})

                        update_task_record(str(task_id), {
                            "status": "FAILED",
                            "error": err_msg,
                            "statusText": display_status,
                            "duration": int(time.time() - start_time),
                            "updatedAt": int(time.time())
                        })
                        return
            except Exception:
                # 临时网络抖动，继续重试
                pass
    finally:
        ACTIVE_POLL_TASKS.discard(str(task_id))
        if key_id:
            await KEY_POOL_MANAGER.release_key(key_id, str(task_id))



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
    # 自建图床配置
    imgbedEnabled: Optional[bool] = None
    imgbedUploadUrl: Optional[str] = None
    imgbedAuthHeader: Optional[str] = None
    imgbedRootFolder: Optional[str] = None
    imgbedIsolateByUser: Optional[bool] = None
    imgbedConcurrency: Optional[int] = None

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
        "broadcast": sys_cfg.get("broadcast", {"enabled": False, "message": "", "level": "info"}),
        "maintenance": sys_cfg.get("maintenance", {"enabled": False, "message": "系统维护中"}),
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
    if req.imgbedEnabled is not None:
        sys_cfg["imgbedEnabled"] = bool(req.imgbedEnabled)
    if req.imgbedUploadUrl is not None:
        sys_cfg["imgbedUploadUrl"] = req.imgbedUploadUrl.strip()
    if req.imgbedRootFolder is not None:
        sys_cfg["imgbedRootFolder"] = req.imgbedRootFolder.strip() or "RunComfyui"
    if req.imgbedIsolateByUser is not None:
        sys_cfg["imgbedIsolateByUser"] = bool(req.imgbedIsolateByUser)
    if req.imgbedConcurrency is not None:
        sys_cfg["imgbedConcurrency"] = max(1, min(10, int(req.imgbedConcurrency)))
    if req.imgbedAuthHeader is not None and req.imgbedAuthHeader.strip():
        raw_header = req.imgbedAuthHeader.strip()
        if not raw_header.startswith("****") and "****" not in raw_header:
            sys_cfg["imgbedAuthHeaderEncrypted"] = encrypt_key(raw_header)
    
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
        "workflows": filter_workflows_for_user(cfg.get("workflows", []), current_user),
        "system": get_system_config_safe(cfg) if is_admin else {
            "siteTitle": cfg.get("system", {}).get("siteTitle", "RunningHub 智能调度中心"),
            "allowRegistration": bool(cfg.get("system", {}).get("allowRegistration", True)),
            "requireLoginToGenerate": bool(cfg.get("system", {}).get("requireLoginToGenerate", True)),
            "defaultUserPoints": cfg.get("system", {}).get("defaultUserPoints", 100),
            "hideAuxiliaryAudioChain": bool(cfg.get("system", {}).get("hideAuxiliaryAudioChain", True)),
            "broadcast": cfg.get("system", {}).get("broadcast", {"enabled": False, "message": "", "level": "info"}),
            "maintenance": cfg.get("system", {}).get("maintenance", {"enabled": False, "message": "系统维护中"})
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
def get_workflows(current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)):
    """获取工作流列表（具备多租户隔离与置顶排序）"""
    cfg = load_config()
    return filter_workflows_for_user(cfg.get("workflows", []), current_user)

class WorkflowModel(BaseModel):
    id: str
    name: str
    description: Optional[str] = ""
    category: Optional[str] = "官方预设"
    pointsCost: Optional[int] = 5
    defaultParams: Optional[Dict[str, Any]] = None
    isOfficial: Optional[bool] = None
    isActive: Optional[bool] = True
    isPinned: Optional[bool] = False

@app.post("/api/workflows")
def add_or_update_workflow(wf: WorkflowModel, current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)):
    """添加或修改工作流（具备租户隔离与官方工作流防篡改防护）"""
    cfg = load_config()
    workflows = cfg.get("workflows", [])
    is_admin = current_user and current_user.get("role") == "admin"
    
    existing_idx = None
    existing_wf = None
    for i, w in enumerate(workflows):
        if str(w.get("id")) == str(wf.id):
            existing_idx = i
            existing_wf = w
            break
            
    wf_data = wf.dict()
    wf_data["updatedAt"] = int(time.time())
    
    if not is_admin:
        if not current_user:
            raise HTTPException(status_code=401, detail="请先登录后再保存自定义工作流")
            
        if existing_wf:
            if existing_wf.get("isOfficial"):
                raise HTTPException(status_code=403, detail="【官方预设工作流】受全平台保护，仅限管理员修改")
            if str(existing_wf.get("ownerId", "")) != str(current_user["id"]):
                raise HTTPException(status_code=403, detail="无权修改其他用户的私有工作流")
                
        wf_data["isOfficial"] = False
        wf_data["ownerId"] = str(current_user["id"])
        wf_data["ownerName"] = str(current_user.get("username", "用户"))
        wf_data["isActive"] = True
        wf_data["isPinned"] = False
        if not wf_data.get("category") or wf_data.get("category") == "官方预设":
            wf_data["category"] = "我的自建"
    else:
        if wf_data.get("isOfficial") is None:
            wf_data["isOfficial"] = existing_wf.get("isOfficial", True) if existing_wf else True
        if wf_data.get("isOfficial"):
            wf_data["ownerId"] = None
            wf_data["ownerName"] = "系统官方"
        else:
            if existing_wf and existing_wf.get("ownerId"):
                wf_data["ownerId"] = existing_wf["ownerId"]
                wf_data["ownerName"] = existing_wf.get("ownerName", "用户")
            else:
                wf_data["ownerId"] = str(current_user["id"]) if current_user else "admin"
                wf_data["ownerName"] = current_user.get("username", "管理员") if current_user else "管理员"
                
    if existing_idx is not None:
        workflows[existing_idx] = wf_data
    else:
        workflows.append(wf_data)
        
    cfg["workflows"] = workflows
    save_config(cfg)
    return {"status": "ok", "workflow": wf_data}

@app.delete("/api/workflows/{workflow_id}")
def delete_workflow(workflow_id: str, current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)):
    """删除工作流（防越权：普通用户只能删除自己的工作流，禁止删除官方工作流）"""
    cfg = load_config()
    workflows = cfg.get("workflows", [])
    target = next((w for w in workflows if str(w.get("id")) == str(workflow_id)), None)
    if not target:
        raise HTTPException(status_code=404, detail="工作流不存在")
        
    is_admin = current_user and current_user.get("role") == "admin"
    if not is_admin:
        if not current_user:
            raise HTTPException(status_code=401, detail="请先登录后再进行操作")
        if target.get("isOfficial"):
            raise HTTPException(status_code=403, detail="【官方预设工作流】全平台受保护，仅限管理员下架或删除")
        if str(target.get("ownerId", "")) != str(current_user["id"]):
            raise HTTPException(status_code=403, detail="无权删除非本人的私有工作流")
            
    cfg["workflows"] = [w for w in workflows if str(w.get("id")) != str(workflow_id)]
    save_config(cfg)
    return {"status": "ok", "message": f"工作流 {workflow_id} 已成功删除"}

# ==================== 管理员工作流全权管控接口 ====================
@app.get("/api/admin/workflows")
def admin_list_workflows(_: Dict[str, Any] = Depends(get_current_admin)):
    """管理员全量工作流列表（包含官方与所有用户自建）"""
    cfg = load_config()
    return sort_workflows(cfg.get("workflows", []))

@app.post("/api/admin/workflows/{workflow_id}/toggle-active")
def admin_toggle_workflow_active(workflow_id: str, _: Dict[str, Any] = Depends(get_current_admin)):
    """切换工作流上架/下架状态"""
    cfg = load_config()
    workflows = cfg.get("workflows", [])
    target = next((w for w in workflows if str(w.get("id")) == str(workflow_id)), None)
    if not target:
        raise HTTPException(status_code=404, detail="工作流不存在")
    target["isActive"] = not bool(target.get("isActive", True))
    target["updatedAt"] = int(time.time())
    save_config(cfg)
    return {"status": "ok", "workflow": target, "isActive": target["isActive"]}

@app.post("/api/admin/workflows/{workflow_id}/toggle-pin")
def admin_toggle_workflow_pin(workflow_id: str, _: Dict[str, Any] = Depends(get_current_admin)):
    """切换工作流置顶状态"""
    cfg = load_config()
    workflows = cfg.get("workflows", [])
    target = next((w for w in workflows if str(w.get("id")) == str(workflow_id)), None)
    if not target:
        raise HTTPException(status_code=404, detail="工作流不存在")
    is_pinned = not bool(target.get("isPinned", False))
    target["isPinned"] = is_pinned
    target["pinnedAt"] = int(time.time()) if is_pinned else 0
    target["updatedAt"] = int(time.time())
    save_config(cfg)
    return {"status": "ok", "workflow": target, "isPinned": target["isPinned"]}

@app.post("/api/admin/workflows/{workflow_id}/toggle-official")
def admin_toggle_workflow_official(workflow_id: str, _: Dict[str, Any] = Depends(get_current_admin)):
    """切换工作流官方/自建属性"""
    cfg = load_config()
    workflows = cfg.get("workflows", [])
    target = next((w for w in workflows if str(w.get("id")) == str(workflow_id)), None)
    if not target:
        raise HTTPException(status_code=404, detail="工作流不存在")
    is_off = not bool(target.get("isOfficial", False))
    target["isOfficial"] = is_off
    if is_off:
        target["ownerId"] = None
        target["ownerName"] = "系统官方"
        if not target.get("category") or target.get("category") == "我的自建":
            target["category"] = "官方预设"
    target["updatedAt"] = int(time.time())
    save_config(cfg)
    return {"status": "ok", "workflow": target, "isOfficial": target["isOfficial"]}

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
        err_msg = str(raw_data.get("msg") or "获取工作流信息失败")
        if "WORKFLOW_NOT_SAVED" in err_msg.upper() or "NOT_RUNNING" in err_msg.upper():
            err_msg = "该工作流在 RunningHub 上尚未保存或未运行过：请在 RunningHub 网页版画布左上角点击【保存 (Alt+S)】或先运行一次，云端即可同步编译并开放 API 格式！"
        raise HTTPException(status_code=400, detail=err_msg)
    
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


async def dispatch_queued_task(
    local_task_id: str, 
    req: GenerateRequest, 
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

        # 最长排队等待 15 分钟 (900s)
        while time.time() - start_wait_time < 900.0:
            if local_task_id in CANCELLED_TASKS:
                return

            key_info = await KEY_POOL_MANAGER.wait_for_free_key(local_task_id, timeout=15.0, exclude_key_ids=excluded)
            
            if local_task_id in CANCELLED_TASKS:
                if key_info:
                    await KEY_POOL_MANAGER.release_key(key_info[0], local_task_id)
                return

            if not key_info:
                # 检查池中是否还存在任何健康 Key
                all_keys = KEY_POOL_MANAGER._get_all_keys()
                healthy_remain = [k for k in all_keys if k.get("id") not in excluded and KEY_POOL_MANAGER._states.get(k.get("id"), {}).get("is_healthy", True)]
                if not healthy_remain:
                    print(f"[Queue Dispatch] All keys in pool are exhausted or unhealthy for task {local_task_id}")
                    break
                continue

            key_id, api_key, key_name = key_info
            update_task_record(local_task_id, {
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
                        if current_user:
                            db_refund_user_points(current_user["id"], task_cost, task_id=local_task_id, reason=f"原生代理提交失败退还: {last_err}")
                        update_task_record(local_task_id, {
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
                        requests.post,
                        f"{RUNNINGHUB_API_URL}/task/openapi/create",
                        json=payload,
                        headers=headers,
                        timeout=25
                    )
                    data = res.json()
                except Exception as e:
                    # 偶发网络超时，释放 key 并继续排队重试
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
                        continue # 100% 用户无感故障转移，继续等待其余健康 Key
                    else:
                        # 非 Key 问题（如用户参数错误）
                        await KEY_POOL_MANAGER.release_key(key_id, local_task_id)
                        if current_user:
                            db_refund_user_points(current_user["id"], task_cost, task_id=local_task_id, reason=f"云端拒绝任务退还: {msg}")
                        update_task_record(local_task_id, {
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
            # 达到最长排队上限或全池故障，全额退还算力，绝不向用户暴露 403 / RunningHub 封禁细节
            if current_user:
                db_refund_user_points(current_user["id"], task_cost, task_id=local_task_id, reason="通道繁忙排队超时退还算力")
            update_task_record(local_task_id, {
                "status": "FAILED",
                "error": "计算通道繁忙调度超时",
                "statusText": "计算节点繁忙调度超时，已为您全额退还算力点数",
                "cost": 0,
                "updatedAt": int(time.time())
            })
            return

        # 将 local_task_id 替换或映射至 real_task_id
        if real_task_id != local_task_id:
            with get_db_connection() as conn:
                conn.execute("UPDATE tasks SET task_id = ? WHERE task_id = ?;", (real_task_id, local_task_id))
                conn.commit()
            async with KEY_POOL_MANAGER._lock:
                if key_id in KEY_POOL_MANAGER._states:
                    KEY_POOL_MANAGER._states[key_id]["task_id"] = real_task_id

        ACTIVE_POLL_TASKS.add(real_task_id)
        asyncio.create_task(poll_task_status(real_task_id, api_key, key_id=key_id))
        if net_wss_url:
            asyncio.create_task(listen_websocket_stream(net_wss_url, real_task_id, api_key))
    except Exception as e:
        print(f"[Dispatch Queued Task Exception] {e}")


@app.post("/api/generate")
async def generate_task(
    req: GenerateRequest, 
    background_tasks: BackgroundTasks,
    current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    cfg = load_config()
    
    # 动态检查全站维护模式
    sys_settings = cfg.get("system", {})
    if sys_settings.get("maintenanceMode"):
        # 允许管理员在维护模式下继续测试与发布
        if not (current_user and current_user.get("role") == "admin"):
            reason = sys_settings.get("maintenanceReason") or "系统正在例行升级维护中，请稍后再试"
            raise HTTPException(status_code=503, detail=f"【系统维护公告】{reason}")

    # 优先检测原生 ComfyUI 代理模式
    is_custom_proxy = bool(req.customPrompt)

    if not is_custom_proxy and not req.workflowId:
        raise HTTPException(status_code=400, detail="缺少必填参数：workflowId")

    # 动态核算当前工作流所需点数 (P0-5 计费闭环)
    task_cost = 0
    if not is_custom_proxy:
        for wf in cfg.get("workflows", []):
            if str(wf.get("id")) == str(req.workflowId):
                task_cost = int(wf.get("cost", 0))
                break

    # 执行原子扣费逻辑：若点数不足立即拦截，扣费成功则记录账单
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

    # 规范化算力档位：Standard (标准极速独享通道) vs Lite (经济共享排队通道)
    task_type = "Lite" if req.taskType and req.taskType.strip().lower() == "lite" else "Standard"

    temp_id = f"task_{int(time.time())}_{uuid.uuid4().hex[:8]}"
    user_id = current_user["id"] if current_user else ""
    user_name = current_user["username"] if current_user else "匿名访客"

    excluded_key_ids: Set[str] = set()
    real_task_id = None
    net_wss_url = None
    assigned_key_id = None
    assigned_api_key = None

    # ---------------- 核心：100% 用户无感自动故障转移与 Key 派单调度循环 ----------------
    while True:
        # 1. 尝试原子抢占一个空闲且健康的 Key
        key_info = await KEY_POOL_MANAGER.acquire_free_key(temp_id, exclude_key_ids=excluded_key_ids)
        if not key_info:
            # 短暂等待 1.5 秒看是否有其他任务刚好结束释放
            key_info = await KEY_POOL_MANAGER.wait_for_free_key(temp_id, timeout=1.5, exclude_key_ids=excluded_key_ids)

        # 检查池中是否还存在任何健康 Key
        all_keys = KEY_POOL_MANAGER._get_all_keys()
        remaining_healthy = [
            k for k in all_keys 
            if k.get("id") not in excluded_key_ids and KEY_POOL_MANAGER._states.get(k.get("id"), {}).get("is_healthy", True)
        ]

        if not remaining_healthy:
            # 极端异常：全池所有 Key 均已失效或被封禁，立即全额退款，绝对屏蔽 403 / RunningHub / 封禁 等技术敏感词
            if points_deducted and current_user:
                db_refund_user_points(current_user["id"], task_cost, reason="算力调度通道维护全额退款")
            raise HTTPException(
                status_code=503, 
                detail="当前云端算力调度通道正在维护中，已全额退还您的算力点数，请稍后再试"
            )

        # 情况 A: 存在健康 Key 但当前全忙，转入本地智能排队模式 (无感知，不报错)
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

            # 启动后台排队监听协程 (携带已隔离的 excluded_key_ids)
            asyncio.create_task(dispatch_queued_task(temp_id, req, current_user, task_cost, is_custom_proxy, task_type, excluded_key_ids))

            return {
                "status": "ok",
                "taskId": temp_id,
                "task": task_record,
                "isQueued": True
            }

        # 情况 B: 成功获取到一个健康空闲 Key，立即向云端提交任务
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
                # 检查是否为 Key 权限/封禁故障
                if is_key_fatal_error(None, str(last_err)):
                    print(f"[Silent Failover] Key {key_id} ({key_name}) failed in proxy: {last_err}. Isolating and trying next key...")
                    await KEY_POOL_MANAGER.mark_key_unhealthy(key_id, f"原生代理鉴权/风控拒绝: {last_err}")
                    excluded_key_ids.add(key_id)
                    continue # 100% 用户无感知，自动轮询尝试下一个健康 Key！
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
                    requests.post,
                    f"{RUNNINGHUB_API_URL}/task/openapi/create",
                    json=payload,
                    headers=headers,
                    timeout=25
                )
                data = res.json()
            except Exception as e:
                # 偶发网络异常
                await KEY_POOL_MANAGER.release_key(key_id, temp_id)
                if points_deducted and current_user:
                    db_refund_user_points(current_user["id"], task_cost, reason="调用云端引擎失败全额退款")
                raise HTTPException(status_code=500, detail="连接云端计算引擎超时，请稍后重试")

            code = data.get("code")
            msg = str(data.get("msg") or "")

            if code != 0:
                # 核心拦截：精准捕获 403 封禁 / 302 / 301 / 401 / 806 / 欠费 / 违规风控 等各类 Key 致命错误
                if is_key_fatal_error(code, msg):
                    print(f"[Silent Failover] Key {key_id} ({key_name}) rejected with code [{code}]: {msg}. Marking unhealthy and silently failing over...")
                    await KEY_POOL_MANAGER.mark_key_unhealthy(key_id, f"云端拒绝任务 [{code}]: {msg}")
                    excluded_key_ids.add(key_id)
                    continue # 【核心需求实现】：用户 100% 无感，静默跳过此 Key，无缝使用下一个正常健康的 Key！
                else:
                    # 真正的用户参数错误（如缺失必须的图片节点）
                    await KEY_POOL_MANAGER.release_key(key_id, temp_id)
                    if points_deducted and current_user:
                        db_refund_user_points(current_user["id"], task_cost, reason=f"云端拒绝任务退还: {msg}")
                    raise HTTPException(status_code=400, detail=msg or "创建任务失败")

            real_task_id = str(data.get("data", {}).get("taskId"))
            net_wss_url = data.get("data", {}).get("netWssUrl")
            assigned_key_id = key_id
            assigned_api_key = api_key
            break

    # 更新 key 占用的正式 task_id
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

    is_admin = bool(current_user and current_user.get("role") == "admin")
    for t in user_tasks:
        if not is_admin:
            t["outputs"] = [o for o in t.get("outputs", []) if not o.get("userHidden") and not o.get("isTakedown")]
        tid = str(t.get("taskId"))
        if api_key and t.get("status") in ["RUNNING", "QUEUED"] and tid not in ACTIVE_POLL_TASKS and tid not in CANCELLED_TASKS:
            ACTIVE_POLL_TASKS.add(tid)
            asyncio.create_task(poll_task_status(tid, api_key))
    
    return user_tasks

@app.get("/api/admin/tasks")
def admin_list_all_tasks(
    status: Optional[str] = None,
    user_id: Optional[str] = None,
    username: Optional[str] = None,
    limit: int = 500,
    _: Dict[str, Any] = Depends(get_current_admin)
):
    """管理员全量任务审计视图（支持按用户、状态进行过滤）"""
    return db_load_tasks(user_id=user_id, status=status, is_admin=True, limit=limit, search_user=username)

@app.post("/api/admin/tasks/{task_id}/cancel")
async def admin_force_cancel_task(task_id: str, _: Dict[str, Any] = Depends(get_current_admin)):
    """管理员强制取消全站任意进行中任务，并自动执行退费与通知"""
    task_id_str = str(task_id).strip()
    t = db_get_task(task_id_str)
    if not t:
        raise HTTPException(status_code=404, detail="任务不存在")
    
    CANCELLED_TASKS.add(task_id_str)
    await KEY_POOL_MANAGER.release_key_by_task_id(task_id_str)
    
    cloud_status = "已标记本地取消"
    cfg = load_config()
    api_key = get_active_api_key(cfg)
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
            cloud_status = f"云端取消异常: {str(e)}"
            
    cost_val = int(t.get("cost", 0) or 0)
    task_owner = str(t.get("userId") or "")
    refund_msg = ""
    if cost_val > 0 and task_owner and t.get("status") not in ("CANCELLED", "FAILED"):
        r_ok, new_bal = db_refund_user_points(
            user_id=task_owner,
            amount=cost_val,
            task_id=task_id_str,
            reason=f"管理员强制取消任务全额退款 (任务ID: {task_id_str})"
        )
        if r_ok:
            refund_msg = f"，已退还 {cost_val} 算力点至用户 (余额: {new_bal})"
            
    db_update_task(task_id_str, {
        "status": "CANCELLED",
        "error": f"管理员后台强制取消 ({cloud_status}){refund_msg}",
        "errorMessage": f"管理员后台强制取消 ({cloud_status}){refund_msg}",
        "updatedAt": int(time.time())
    })
    
    return {
        "status": "ok",
        "message": f"任务已强制取消{refund_msg}",
        "cloudStatus": cloud_status
    }

@app.delete("/api/admin/tasks/{task_id}")
def admin_delete_task(task_id: str, _: Dict[str, Any] = Depends(get_current_admin)):
    """管理员清理/删除单条任务记录"""
    db_delete_task(str(task_id).strip())
    return {"status": "ok", "message": f"任务 {task_id} 记录已清理"}

@app.post("/api/admin/tasks/clean-batch")
def admin_clean_tasks_batch(payload: Dict[str, Any], _: Dict[str, Any] = Depends(get_current_admin)):
    """管理员批量清理特定状态的任务记录（如已取消或失败任务）"""
    status_target = payload.get("status")
    if not status_target:
        raise HTTPException(status_code=400, detail="缺少清理目标状态")
    tasks = db_load_tasks(status=status_target, is_admin=True, limit=1000)
    tids = [t["taskId"] for t in tasks if t.get("taskId")]
    deleted_count = db_delete_tasks_batch(tids)
    return {"status": "ok", "deletedCount": deleted_count, "message": f"已成功清理 {deleted_count} 条状态为 {status_target} 的任务记录"}

# ==================== 全站实时广播与维护模式管控接口 ====================
@app.post("/api/admin/system/broadcast")
def admin_update_broadcast(payload: Dict[str, Any], _: Dict[str, Any] = Depends(get_current_admin)):
    """更新全站实时广播通知"""
    cfg = load_config()
    sys_cfg = cfg.setdefault("system", {})
    broadcast = {
        "enabled": bool(payload.get("enabled", False)),
        "message": str(payload.get("message", "")).strip(),
        "level": str(payload.get("level", "info")),
        "updatedAt": int(time.time())
    }
    sys_cfg["broadcast"] = broadcast
    save_config(cfg)
    return {"status": "ok", "broadcast": broadcast}

@app.post("/api/admin/system/maintenance")
def admin_update_maintenance(payload: Dict[str, Any], _: Dict[str, Any] = Depends(get_current_admin)):
    """切换全站维护模式开关及通知文案"""
    cfg = load_config()
    sys_cfg = cfg.setdefault("system", {})
    maint = {
        "enabled": bool(payload.get("enabled", False)),
        "message": str(payload.get("message", "系统正在维护中，暂停提交新任务，请稍后访问。")).strip(),
        "updatedAt": int(time.time())
    }
    sys_cfg["maintenance"] = maint
    save_config(cfg)
    return {"status": "ok", "maintenance": maint}

@app.get("/api/admin/gallery")
def admin_get_gallery(
    username: Optional[str] = None,
    file_type: Optional[str] = None,
    storage: Optional[str] = None,
    status: Optional[str] = None,
    _: Dict[str, Any] = Depends(get_current_admin)
):
    """管理员全站画廊视图（支持按用户、媒体类型、存储介质、管控状态多维聚合筛选）"""
    tasks = db_load_tasks(is_admin=True, limit=500)
    items = []
    seen = set()
    for t in tasks:
        t_user = t.get("username") or "guest"
        if username and username != "all" and t_user != username:
            continue
        created_at = t.get("createdAt", int(time.time()))
        for out in t.get("outputs", []):
            url = out.get("url") or out.get("remoteUrl")
            if url and "imgbed.2364498.xyz" in url and out.get("remoteUrl"):
                url = out.get("remoteUrl")
            imgbed_url = out.get("imgbedUrl") or (out.get("url") if "imgbed.2364498.xyz" in (out.get("url") or "") else "")
            if not url or url.startswith("data:"):
                continue
            fname = out.get("filename") or os.path.basename(url.split("?")[0])
            fp = f"{t.get('taskId')}_{fname}"
            if fp in seen:
                continue
            seen.add(fp)
            
            ext = os.path.splitext(fname)[1].lower()
            ft = out.get("fileType")
            if not ft or ft == "image":
                if ext in {".mp3", ".wav", ".flac", ".ogg", ".m4a", ".aac", ".wma", ".opus"}:
                    ft = "audio"
                elif ext in {".mp4", ".webm", ".mov"}:
                    ft = "video"
                else:
                    ft = "image"
            if file_type and file_type != "all" and ft != file_type:
                continue
                
            has_imgbed = bool(imgbed_url or out.get("storage") == "imgbed")
            out_storage = "imgbed" if has_imgbed else "remote"
            if storage and storage != "all":
                if storage == "imgbed" and not has_imgbed:
                    continue
                if storage == "remote" and has_imgbed:
                    continue

            is_takedown = bool(out.get("isTakedown"))
            user_hidden = bool(out.get("userHidden"))
            source_expired = bool(out.get("sourceExpired"))

            if status and status != "all":
                if status == "active" and (is_takedown or user_hidden):
                    continue
                elif status == "takedown" and not is_takedown:
                    continue
                elif status == "user_hidden" and not user_hidden:
                    continue
                elif status == "expired" and not source_expired:
                    continue
                    
            items.append({
                "filename": fname,
                "url": url,                           # 用户的原始 RunningHub 直链
                "remoteUrl": out.get("remoteUrl", url),# 用户的原始 RunningHub 直链
                "imgbedUrl": imgbed_url,               # 管理员专属图床归档直链
                "storage": out_storage,
                "isTakedown": is_takedown,
                "userHidden": user_hidden,
                "sourceExpired": source_expired,
                "imgbedFolder": out.get("imgbedFolder", f"RunComfyui/{t_user}"),
                "createdAt": created_at,
                "fileType": ft,
                "taskId": t.get("taskId"),
                "userId": t.get("userId"),
                "username": t_user,
                "positivePrompt": t.get("positivePrompt", ""),
                "workflowName": t.get("workflowName", "")
            })
    items.sort(key=lambda x: x["createdAt"], reverse=True)
    return items

@app.post("/api/admin/gallery/{task_id}/{filename}/takedown")
@app.delete("/api/admin/gallery/{task_id}/{filename}")
def admin_takedown_gallery_item(task_id: str, filename: str, _: Dict[str, Any] = Depends(get_current_admin)):
    """管理员违规下架成果（从前台用户端彻底隐藏，保留在后台【已下架】分类中，支持随时一键恢复）"""
    t = db_get_task(str(task_id))
    if not t:
        raise HTTPException(status_code=404, detail="任务不存在")
    safe_name = os.path.basename(filename)
    outs = t.get("outputs", [])
    modified = False
    new_outs = []
    for o in outs:
        fname = o.get("filename") or os.path.basename(o.get("url", "").split("?")[0])
        remote_fname = os.path.basename(o.get("remoteUrl", "").split("?")[0])
        if safe_name in (fname, remote_fname) or (o.get("url") and safe_name in o.get("url")):
            o_copy = dict(o)
            o_copy["isTakedown"] = True
            o_copy["takedownAt"] = int(time.time())
            new_outs.append(o_copy)
            modified = True
        else:
            new_outs.append(o)
    if modified:
        update_task_record(str(task_id), {
            "outputs": new_outs,
            "updatedAt": int(time.time())
        })
    return {"status": "ok", "message": "该成果已成功违规下架（对前台用户屏蔽，已归入后台【已违规下架】分类）"}

@app.post("/api/admin/gallery/{task_id}/{filename}/restore")
def admin_restore_gallery_item(task_id: str, filename: str, _: Dict[str, Any] = Depends(get_current_admin)):
    """管理员重新上架成果（恢复正常公开展示）"""
    t = db_get_task(str(task_id))
    if not t:
        raise HTTPException(status_code=404, detail="任务不存在")
    safe_name = os.path.basename(filename)
    outs = t.get("outputs", [])
    modified = False
    new_outs = []
    for o in outs:
        fname = o.get("filename") or os.path.basename(o.get("url", "").split("?")[0])
        remote_fname = os.path.basename(o.get("remoteUrl", "").split("?")[0])
        if safe_name in (fname, remote_fname) or (o.get("url") and safe_name in o.get("url")):
            o_copy = dict(o)
            o_copy["isTakedown"] = False
            o_copy["userHidden"] = False
            o_copy.pop("takedownAt", None)
            new_outs.append(o_copy)
            modified = True
        else:
            new_outs.append(o)
    if modified:
        update_task_record(str(task_id), {
            "outputs": new_outs,
            "updatedAt": int(time.time())
        })
    return {"status": "ok", "message": "该成果已重新上架，恢复正常前台展示"}

@app.get("/api/admin/imgbed")
def admin_get_imgbed_status(_: Dict[str, Any] = Depends(get_current_admin)):
    """获取图床运行配置与同步审计概览"""
    cfg = load_config()
    safe_info = get_imgbed_config(cfg)
    tasks = db_load_tasks(is_admin=True, limit=500)
    total_outputs = 0
    synced_count = 0
    for t in tasks:
        for o in t.get("outputs", []):
            total_outputs += 1
            if o.get("imgbedUrl") or "imgbed.2364498.xyz" in (o.get("url") or "") or o.get("storage") == "imgbed":
                synced_count += 1
    
    safe_info.pop("rawAuthHeader", None)
    safe_info["totalOutputs"] = total_outputs
    safe_info["syncedOutputs"] = synced_count
    safe_info["pendingSync"] = max(0, total_outputs - synced_count)
    return safe_info

@app.post("/api/admin/imgbed/test")
async def admin_test_imgbed(_: Dict[str, Any] = Depends(get_current_admin)):
    """管理员在线测试自建图床 API 连通性与 Token 有效性"""
    cfg = load_config()
    imgbed_cfg = get_imgbed_config(cfg)
    raw_auth = imgbed_cfg.get("rawAuthHeader")
    if not raw_auth:
        return {"status": "error", "message": "尚未配置图床 Authorization 密钥"}
    
    upload_url = f"{imgbed_cfg['uploadUrl']}?uploadFolder={imgbed_cfg['rootFolder']}/_health_check"
    headers = {"Authorization": raw_auth}
    dummy_png = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82'
    
    try:
        def _test():
            files = {"file": ("health.png", io.BytesIO(dummy_png), "image/png")}
            return requests.post(upload_url, headers=headers, files=files, timeout=15)
        resp = await asyncio.to_thread(_test)
        if resp.status_code == 200:
            return {"status": "ok", "message": "图床接口连通性极佳！已成功通过 Authorization 认证握手并完成隔离文件夹探测。"}
        else:
            return {"status": "error", "message": f"图床响应异常 (HTTP {resp.status_code}): {resp.text[:200]}"}
    except Exception as e:
        return {"status": "error", "message": f"连接异常: {str(e)}"}

SYNC_ALL_RUNNING = False

@app.post("/api/admin/imgbed/sync_all")
async def admin_sync_all_to_imgbed(_: Dict[str, Any] = Depends(get_current_admin)):
    """管理员一键将历史所有未备份的成果平滑转存至图床（按所属用户文件夹隔离）"""
    global SYNC_ALL_RUNNING
    if SYNC_ALL_RUNNING:
        return {"status": "busy", "message": "全量历史成果正在后台平稳转存中，请勿重复触发"}
    
    async def _batch_sync():
        global SYNC_ALL_RUNNING
        SYNC_ALL_RUNNING = True
        try:
            tasks = db_load_tasks(is_admin=True, limit=500)
            for t in tasks:
                tid = str(t.get("taskId"))
                outs = t.get("outputs", [])
                needs_sync = any(not o.get("imgbedUrl") for o in outs)
                if needs_sync:
                    await sync_task_outputs_to_imgbed(tid)
                    await asyncio.sleep(0.5)
        finally:
            SYNC_ALL_RUNNING = False
            
    asyncio.create_task(_batch_sync())
    return {"status": "ok", "message": "已成功启动历史成果后台平稳同步！任务将在后台按用户文件夹隔离分流转存。"}

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
    await KEY_POOL_MANAGER.release_key_by_task_id(task_id_str)

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
    """获取专属成果画廊（包含完整元信息，严格过滤用户已删除和管理员已下架的作品）"""
    if current_user:
        user_id_str = str(current_user["id"])
        tasks = db_load_tasks(user_id=user_id_str, limit=500)
    else:
        all_tasks = db_load_tasks(limit=100)
        tasks = [t for t in all_tasks if not t.get("userId")]

    items = []
    seen = set()
    for t in tasks:
        created_at = t.get("createdAt", int(time.time()))
        for out in t.get("outputs", []):
            if out.get("userHidden") or out.get("isTakedown"):
                continue
            url = out.get("url") or out.get("remoteUrl")
            if not url or url.startswith("data:"):
                continue
            fname = out.get("filename") or os.path.basename(url.split("?")[0])
            fp = f"{t.get('taskId')}_{fname}"
            if fp in seen:
                continue
            seen.add(fp)
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
                "username": t.get("username", ""),
                "positivePrompt": t.get("positivePrompt", ""),
                "workflowName": t.get("workflowName", "") or t.get("workflowId", ""),
                "workflowId": t.get("workflowId", ""),
                "duration": t.get("duration", 0),
                "cost": t.get("cost", 0),
                "consumeCoins": t.get("consumeCoins", "0")
            })
    items.sort(key=lambda x: x["createdAt"], reverse=True)
    return items

@app.delete("/api/gallery/{task_id}/{filename}")
@app.delete("/api/gallery/{filename}")
def delete_gallery_file(
    filename: str, 
    task_id: Optional[str] = None, 
    current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    """用户软删除成果：支持传入 taskId 精确定位，彻底对用户自身隐藏，管理员后台依然完整保留可见"""
    safe_name = os.path.basename(filename)
    user_id = str(current_user["id"]) if current_user else ""
    is_admin = bool(current_user and current_user.get("role") == "admin")
    
    # 优先基于精确 taskId 处理
    if task_id:
        t = db_get_task(str(task_id).strip())
        if t:
            task_owner = str(t.get("userId") or "")
            if task_owner and user_id and not is_admin and task_owner != user_id:
                raise HTTPException(status_code=403, detail="无权操作其他用户的成果文件")
            outs = t.get("outputs", [])
            modified = False
            new_outs = []
            for o in outs:
                fname = o.get("filename") or os.path.basename(o.get("url", "").split("?")[0])
                remote_fname = os.path.basename(o.get("remoteUrl", "").split("?")[0])
                if safe_name in (fname, remote_fname) or (o.get("url") and safe_name in o.get("url")) or (o.get("remoteUrl") and safe_name in o.get("remoteUrl")):
                    o_copy = dict(o)
                    o_copy["userHidden"] = True
                    o_copy["userHiddenAt"] = int(time.time())
                    new_outs.append(o_copy)
                    modified = True
                else:
                    new_outs.append(o)
            if modified:
                update_task_record(str(t.get("taskId")), {
                    "outputs": new_outs,
                    "updatedAt": int(time.time())
                })
                return {"status": "ok", "message": "该成果已成功从您的画廊中移除（前台已隐藏）"}
    
    # 兜底：遍历用户任务进行文件指纹匹配
    user_tasks = db_load_tasks(limit=500) if is_admin else (db_load_tasks(user_id=user_id, limit=500) if user_id else db_load_tasks(limit=100))
    for t in user_tasks:
        outs = t.get("outputs", [])
        modified = False
        new_outs = []
        for o in outs:
            fname = o.get("filename") or os.path.basename(o.get("url", "").split("?")[0])
            remote_fname = os.path.basename(o.get("remoteUrl", "").split("?")[0])
            if safe_name in (fname, remote_fname) or (o.get("url") and safe_name in o.get("url")) or (o.get("remoteUrl") and safe_name in o.get("remoteUrl")):
                task_owner = str(t.get("userId") or "")
                if user_id and not is_admin and task_owner and task_owner != user_id:
                    continue
                o_copy = dict(o)
                o_copy["userHidden"] = True
                o_copy["userHiddenAt"] = int(time.time())
                new_outs.append(o_copy)
                modified = True
            else:
                new_outs.append(o)
        if modified:
            update_task_record(str(t.get("taskId")), {
                "outputs": new_outs,
                "updatedAt": int(time.time())
            })
            
    return {"status": "ok", "message": "该成果已成功从您的画廊中移除（前台已隐藏）"}

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




# ----------------- 卡密发行与兑换充值 API 路由 -----------------

_REDEEM_COOLDOWN = {}

class RedeemCDKeyRequest(BaseModel):
    code: str

class GenerateCDKeysRequest(BaseModel):
    points: int
    count: int
    remark: Optional[str] = ""

@app.post("/api/user/redeem-cdkey")
async def user_redeem_cdkey(
    req: RedeemCDKeyRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    用户自主核销卡密兑换点数（高安全防线：防撞库限频 + 密码学清洗 + 数据库级原子核销）
    """
    clean_code = (req.code or "").strip().upper()
    if not clean_code:
        raise HTTPException(status_code=400, detail="请输入有效的卡密兑换码")

    # 轻量防刷与防重放 (1.5 秒冷却间隔，取消粗暴的 15 分钟冻结，保障打错字的买家丝滑重试)
    cooldown_key = f"redeem_cd_{current_user['id']}"
    now_ts = time.time()
    last_attempt = _REDEEM_COOLDOWN.get(cooldown_key, 0)
    if now_ts - last_attempt < 1.5:
        raise HTTPException(status_code=429, detail="操作过于频繁，请稍等 1 秒后再试")
    _REDEEM_COOLDOWN[cooldown_key] = now_ts

    ok, new_balance, msg = db_redeem_cdkey(
        raw_code=clean_code,
        user_id=current_user["id"],
        username=current_user["username"]
    )

    if not ok:
        raise HTTPException(status_code=400, detail=msg)

    await notify_user(
        user_id=current_user["id"],
        event_type="POINTS_UPDATED",
        data={"points": new_balance, "reason": f"卡密兑换到账 ({clean_code})"}
    )

    return {
        "status": "ok",
        "message": msg,
        "newPoints": new_balance,
        "code": clean_code
    }

@app.post("/api/admin/cdkeys/generate")
async def admin_generate_cdkeys(
    req: GenerateCDKeysRequest,
    _: Dict[str, Any] = Depends(get_current_admin)
):
    """管理员批量发行密码学高熵卡密"""
    if req.points <= 0:
        raise HTTPException(status_code=400, detail="卡密面额点数必须大于 0")
    if req.count <= 0 or req.count > 500:
        raise HTTPException(status_code=400, detail="单次生成数量必须在 1 ~ 500 张之间")

    codes = db_generate_cdkeys(
        points=req.points,
        count=req.count,
        remark=req.remark or ""
    )

    return {
        "status": "ok",
        "count": len(codes),
        "points": req.points,
        "remark": req.remark or "",
        "codes": codes
    }

@app.get("/api/admin/cdkeys")
async def admin_list_cdkeys(
    status: Optional[str] = "ALL",
    page: Optional[int] = 1,
    pageSize: Optional[int] = 50,
    search: Optional[str] = "",
    _: Dict[str, Any] = Depends(get_current_admin)
):
    """管理员分页查询卡密对账流水（支持按状态、用户、卡密号过滤）"""
    return db_list_cdkeys(
        status_filter=status or "ALL",
        page=max(1, int(page or 1)),
        page_size=min(200, max(10, int(pageSize or 50))),
        search=search or ""
    )

@app.post("/api/admin/cdkeys/{code}/void")
async def admin_void_cdkey(
    code: str,
    _: Dict[str, Any] = Depends(get_current_admin)
):
    """管理员作废未核销的卡密"""
    ok = db_void_cdkey(code)
    if not ok:
        raise HTTPException(status_code=400, detail="卡密不存在或已被使用，无法作废")
    return {"status": "ok", "message": f"卡密 {code} 已成功作废"}

@app.delete("/api/admin/cdkeys/{code}")
async def admin_delete_cdkey(
    code: str,
    _: Dict[str, Any] = Depends(get_current_admin)
):
    """管理员物理删除卡密记录"""
    ok = db_delete_cdkey(code)
    if not ok:
        raise HTTPException(status_code=404, detail="卡密不存在")
    return {"status": "ok", "message": f"卡密 {code} 已删除"}

@app.get("/api/admin/cdkeys/export")
async def admin_export_unused_cdkeys(
    remark: Optional[str] = "",
    _: Dict[str, Any] = Depends(get_current_admin)
):
    """导出未使用的卡密明细（供直接批量粘贴至闲管家/发卡网）"""
    items = db_get_unused_cdkeys_export(remark=remark or "")
    text_lines = [item["code"] for item in items]
    return {
        "count": len(items),
        "rawText": "\n".join(text_lines),
        "items": items
    }

@app.get("/api/admin/key-pool/status")
async def admin_get_key_pool_status(_: Dict[str, Any] = Depends(get_current_admin)):
    """管理员实时查看 RunningHub Key 并发轮询池运行状态"""
    stats = KEY_POOL_MANAGER.get_queue_stats()
    items = KEY_POOL_MANAGER.get_pool_status()
    return {
        "status": "ok",
        "stats": stats,
        "keys": items
    }

@app.post("/api/admin/key-pool/{key_id}/reset")
async def admin_reset_key_in_pool(key_id: str, _: Dict[str, Any] = Depends(get_current_admin)):
    """管理员紧急一键释放被占用的 Key"""
    await KEY_POOL_MANAGER.reset_key(key_id)
    return {"status": "ok", "message": f"Key {key_id} 运行状态已强制重置为空闲"}


# 挂载静态文件
@app.post("/api/admin/key-pool/inspect")
async def admin_inspect_all_keys(_: Dict[str, Any] = Depends(get_current_admin)):
    """管理员手动触发一键全池巡检"""
    results = await KEY_POOL_MANAGER.inspect_all_keys()
    healthy_cnt = sum(1 for r in results if r["isValid"])
    banned_cnt = len(results) - healthy_cnt
    return {
        "status": "ok",
        "healthyCount": healthy_cnt,
        "bannedCount": banned_cnt,
        "results": results
    }

@app.post("/api/admin/key-pool/{key_id}/resume")
async def admin_resume_key_in_pool(key_id: str, _: Dict[str, Any] = Depends(get_current_admin)):
    """管理员一键解除熔断隔离，恢复 Key 为健康可用状态"""
    await KEY_POOL_MANAGER.mark_key_healthy(key_id)
    return {"status": "ok", "message": f"Key {key_id} 已解除熔断，恢复加入调度池"}

class SmtpConfigRequest(BaseModel):
    enabled: bool = False
    host: str = ""
    port: int = 465
    user: str = ""
    password: Optional[str] = None
    adminEmail: str = ""

@app.get("/api/admin/system/smtp")
async def admin_get_smtp_config(_: Dict[str, Any] = Depends(get_current_admin)):
    """获取当前系统 SMTP 告警邮箱配置"""
    cfg = load_config()
    smtp_cfg = cfg.get("system", {}).get("smtp", {})
    return {
        "status": "ok",
        "enabled": bool(smtp_cfg.get("enabled")),
        "host": smtp_cfg.get("host", ""),
        "port": smtp_cfg.get("port", 465),
        "user": smtp_cfg.get("user", ""),
        "hasPassword": bool(smtp_cfg.get("passwordEncrypted")),
        "adminEmail": smtp_cfg.get("adminEmail", "")
    }

@app.post("/api/admin/system/smtp")
async def admin_save_smtp_config(req: SmtpConfigRequest, _: Dict[str, Any] = Depends(get_current_admin)):
    """保存管理员 SMTP 告警邮箱配置（密码高强度对称加密存储）"""
    cfg = load_config()
    if "system" not in cfg:
        cfg["system"] = {}
    smtp_cfg = cfg["system"].get("smtp", {})
    
    smtp_cfg["enabled"] = req.enabled
    smtp_cfg["host"] = req.host.strip()
    smtp_cfg["port"] = req.port
    smtp_cfg["user"] = req.user.strip()
    smtp_cfg["adminEmail"] = req.adminEmail.strip()
    
    if req.password is not None and req.password.strip():
        smtp_cfg["passwordEncrypted"] = encrypt_key(req.password.strip())
        
    cfg["system"]["smtp"] = smtp_cfg
    save_config(cfg)
    return {"status": "ok", "message": "SMTP 告警邮箱设置已成功保存"}

@app.post("/api/admin/system/smtp/test")
async def admin_test_smtp_email(_: Dict[str, Any] = Depends(get_current_admin)):
    """发送测试邮件验证 SMTP 配置连通性"""
    html = f"""
    <div style="font-family: sans-serif; background-color: #0b0f19; color: #e2e8f0; padding: 24px; border-radius: 16px; max-width: 600px; margin: 0 auto; border: 1px solid #334155;">
      <h2 style="color: #38bdf8; margin-top: 0;">🎉 RunComfyUI 运维告警邮箱测试成功</h2>
      <p style="font-size: 14px; color: #cbd5e1; line-height: 1.6;">
        这是一封来自您的 RunComfyUI 商业部署系统的测试邮件。
      </p>
      <div style="background-color: #1e293b; padding: 12px 16px; border-radius: 8px; font-size: 13px; margin: 16px 0;">
        <p style="margin: 4px 0;"><b>SMTP 服务状态：</b> <span style="color: #34d399;">正常通信中</span></p>
        <p style="margin: 4px 0;"><b>发送测试时间：</b> {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}</p>
      </div>
      <p style="font-size: 12px; color: #94a3b8;">
        当 RunningHub 算力账号发生封禁、失效、欠费或被限制等异常时，系统将第一时间向此邮箱发送熔断告警。
      </p>
    </div>
    """
    ok, msg = send_admin_alert_email("【测试邮件】RunComfyUI 运维告警通道连接测试", html)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "ok", "message": "测试邮件已成功发送至管理员接收邮箱，请检查收件箱或垃圾箱"}

app.mount("/outputs", StaticFiles(directory=OUTPUTS_DIR), name="outputs")
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")


if __name__ == "__main__":
    import uvicorn
    # host 0.0.0.0 允许局域网或公网通过服务器 IP / 域名访问
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
