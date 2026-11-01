import os
import json
import time
import base64
import hmac
import hashlib
import uuid
import asyncio
import aiohttp
from typing import Optional, List, Dict, Any, Tuple, Set
from fastapi import Request, HTTPException, Depends
from core.security import SECRET_KEY_FILE
from core.database import get_db_connection, db_bump_token_version, db_delete_user_completely
from core.http_client import HTTP_SESSION

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def _get_jwt_secret() -> bytes:
    env_secret = os.getenv("JWT_SECRET_KEY")
    if env_secret and len(env_secret.strip()) >= 16:
        return hashlib.sha256(env_secret.strip().encode("utf-8")).digest()
    if os.path.exists(SECRET_KEY_FILE):
        try:
            with open(SECRET_KEY_FILE, "rb") as f:
                content = f.read().strip()
                if content:
                    return hashlib.sha256(content + b"::JWT_SALT_2026_RUNNINGHUB").digest()
        except Exception as e:
            raise RuntimeError(f"[Security Fail-Fast] 无法读取安全密钥文件 {SECRET_KEY_FILE}: {e}")
    raise RuntimeError("[Security Fail-Fast] 未检测到有效 JWT_SECRET_KEY 环境变量或 .secret.key 主加密凭证！")

_JWT_SECRET = _get_jwt_secret()

# ----------------- 数据字段安全脱敏 -----------------

def sanitize_user(row: Any) -> Dict[str, Any]:
    """将数据库行转换为安全的前端用户字典，彻底剥离 password_hash 与 salt"""
    if not row:
        return {}
    if hasattr(row, "keys"):
        d = dict(row)
    elif isinstance(row, dict):
        d = dict(row)
    else:
        return {}
    
    return {
        "id": d.get("id"),
        "username": d.get("username"),
        "email": d.get("email") or "",
        "role": d.get("role", "user"),
        "points": d.get("points", 0),
        "isActive": bool(d.get("is_active", 1)),
        "tokenVersion": d.get("token_version", 1),
        "createdAt": d.get("created_at", 0),
        "lastLogin": d.get("last_login", 0),
        "taskCount": d.get("task_count", 0)
    }

def db_row_to_user(row: Any) -> Optional[Dict[str, Any]]:
    if not row:
        return None
    d = dict(row)
    return {
        "id": d.get("id"),
        "username": d.get("username"),
        "email": d.get("email") or "",
        "passwordHash": d.get("password_hash") or d.get("passwordHash", ""),
        "password_hash": d.get("password_hash") or d.get("passwordHash", ""),
        "salt": d.get("salt", ""),
        "role": d.get("role", "user"),
        "points": d.get("points", 0),
        "isActive": bool(d.get("is_active", 1)),
        "is_active": bool(d.get("is_active", 1)),
        "token_version": d.get("token_version", 1),
        "tokenVersion": d.get("token_version", 1),
        "createdAt": d.get("created_at", 0),
        "created_at": d.get("created_at", 0),
        "lastLogin": d.get("last_login", 0),
        "last_login": d.get("last_login", 0),
        "taskCount": d.get("task_count", 0),
        "task_count": d.get("task_count", 0)
    }

def get_user_count() -> int:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users;")
        return cursor.fetchone()[0]

def load_users() -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users ORDER BY created_at DESC;")
        rows = cursor.fetchall()
        return [db_row_to_user(r) for r in rows if r]

def save_users(users: Optional[List[Dict[str, Any]]] = None):
    pass

def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    if not user_id:
        return None
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?;", (str(user_id),))
        row = cursor.fetchone()
        return db_row_to_user(row)

def get_user_by_identifier(identifier: str) -> Optional[Dict[str, Any]]:
    if not identifier:
        return None
    ident = str(identifier).strip().lower()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE LOWER(username) = ? OR (email IS NOT NULL AND LOWER(email) = ?);",
            (ident, ident)
        )
        row = cursor.fetchone()
        return db_row_to_user(row)

# ----------------- 密码与哈希安全 (PBKDF2-HMAC-SHA256) -----------------

def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    if not salt:
        salt = os.urandom(16).hex()
    pwd_bytes = password.encode("utf-8")
    salt_bytes = salt.encode("utf-8")
    pwd_hash = hashlib.pbkdf2_hmac("sha256", pwd_bytes, salt_bytes, 100000).hex()
    return pwd_hash, salt

def verify_password(password: str, password_hash: str, salt: str) -> bool:
    computed_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(computed_hash, password_hash)

# ----------------- JWT 鉴权令牌 -----------------

def create_jwt_token(payload: Dict[str, Any], expires_in_seconds: int = 86400 * 7) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    
    p = dict(payload)
    now = int(time.time())
    p["iat"] = now
    p["exp"] = now + expires_in_seconds
    p_b64 = base64.urlsafe_b64encode(json.dumps(p).encode()).decode().rstrip("=")
    
    signing_input = f"{h_b64}.{p_b64}".encode("utf-8")
    signature = hmac.new(_JWT_SECRET, signing_input, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    
    return f"{h_b64}.{p_b64}.{sig_b64}"

def decode_jwt_token(token: str) -> Optional[Dict[str, Any]]:
    if not token or not isinstance(token, str):
        return None
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    h_b64, p_b64, sig_b64 = parts
    
    signing_input = f"{h_b64}.{p_b64}".encode("utf-8")
    expected_sig = hmac.new(_JWT_SECRET, signing_input, hashlib.sha256).digest()
    expected_sig_b64 = base64.urlsafe_b64encode(expected_sig).decode().rstrip("=")
    
    if not hmac.compare_digest(sig_b64, expected_sig_b64):
        return None
    
    try:
        p_padded = p_b64 + "=" * ((4 - len(p_b64) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode(p_padded.encode()).decode("utf-8"))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None

# ----------------- Cloudflare Turnstile 人机验证 -----------------

async def verify_turnstile_token(token: str, secret_key: str, remote_ip: str = "") -> Tuple[bool, str]:
    if not secret_key:
        return True, "未配置 Turnstile SecretKey，默认放行"
    if secret_key.startswith("1x0000000000000000000000000000000"):
        return True, "测试密钥验证通过"
    if not token:
        return False, "请先完成 Cloudflare 人机安全验证"
    
    url = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    payload = {"secret": secret_key, "response": token}
    if remote_ip:
        payload["remoteip"] = remote_ip
    
    try:
        resp = await asyncio.to_thread(HTTP_SESSION.post, url, data=payload, timeout=4.0)
        data = resp.json()
        if data.get("success"):
            return True, "人机验证通过"
        codes = data.get("error-codes", [])
        err_msg = ", ".join(codes) if codes else "人机安全验证未通过"
        return False, f"Turnstile 校验未通过: {err_msg}"
    except Exception as e:
        print(f"[Turnstile Warning] 无法连通 Cloudflare 验签服务器 ({e})，触发降级放行")
        return True, "Cloudflare 网络连通异常，降级放行"

# ----------------- 用户创建与管理逻辑 -----------------

def create_user(
    username: str, 
    email: str, 
    password: str, 
    role: str = "user", 
    points: int = 100
) -> Dict[str, Any]:
    username_clean = username.strip()
    email_clean = email.strip()

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE LOWER(username) = ?;", (username_clean.lower(),))
        if cursor.fetchone():
            raise ValueError("该用户名已被注册，请尝试其他名称")
        
        if email_clean:
            cursor.execute("SELECT id FROM users WHERE LOWER(email) = ?;", (email_clean.lower(),))
            if cursor.fetchone():
                raise ValueError("该邮箱已被绑定，请直接登录")
        
        cursor.execute("SELECT COUNT(*) FROM users;")
        user_count = cursor.fetchone()[0]
        if user_count == 0:
            role = "admin"
            points = max(points, 1000)

        pwd_hash, salt = hash_password(password)
        now = int(time.time())
        user_id = f"usr_{uuid.uuid4().hex[:10]}"

        cursor.execute("""
        INSERT INTO users (id, username, email, password_hash, salt, role, points, is_active, created_at, last_login, task_count)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, 0);
        """, (user_id, username_clean, email_clean, pwd_hash, salt, role, points, now, now))
        conn.commit()

        return {
            "id": user_id,
            "username": username_clean,
            "email": email_clean,
            "passwordHash": pwd_hash,
            "salt": salt,
            "role": role,
            "points": points,
            "isActive": True,
            "createdAt": now,
            "lastLogin": now,
            "taskCount": 0
        }

def update_user_fields(user_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    field_map = {
        "role": "role",
        "points": "points",
        "isActive": "is_active",
        "lastLogin": "last_login",
        "taskCount": "task_count",
        "email": "email"
    }
    
    set_clauses = []
    values = []
    for k, v in updates.items():
        if k in field_map:
            col = field_map[k]
            if k == "isActive":
                v = 1 if v else 0
            set_clauses.append(f"{col} = ?")
            values.append(v)
            
    if not set_clauses:
        return get_user_by_id(user_id)
        
    values.append(str(user_id))
    sql = f"UPDATE users SET {', '.join(set_clauses)} WHERE id = ?;"
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(sql, tuple(values))
        conn.commit()

    if "isActive" in updates and not updates["isActive"]:
        db_bump_token_version(str(user_id))
    elif "role" in updates:
        db_bump_token_version(str(user_id))
        
    return get_user_by_id(user_id)

def set_user_password(user_id: str, new_password: str) -> bool:
    pwd_hash, salt = hash_password(new_password)
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET password_hash = ?, salt = ? WHERE id = ?;",
            (pwd_hash, salt, str(user_id))
        )
        conn.commit()
        ok = cursor.rowcount > 0
    if ok:
        db_bump_token_version(str(user_id))
    return ok

def delete_user_by_id(user_id: str) -> bool:
    stats = db_delete_user_completely(str(user_id))
    return stats.get("user", 0) > 0

# ----------------- 实时 SSE 事件下发通道 -----------------

USER_EVENT_CHANNELS: Dict[str, List[asyncio.Queue]] = {}

async def notify_user(user_id: str, event_type: str, data: Dict[str, Any]):
    queues = USER_EVENT_CHANNELS.get(str(user_id), [])
    if not queues:
        return
    msg = json.dumps({"type": event_type, "data": data, "timestamp": int(time.time())}, ensure_ascii=False)
    for q in list(queues):
        try:
            await q.put(msg)
        except Exception:
            pass

# ----------------- FastAPI 鉴权依赖注入 -----------------

async def get_current_user_optional(request: Request) -> Optional[Dict[str, Any]]:
    auth_header = request.headers.get("Authorization")
    token = None
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    if not token:
        token = request.cookies.get("auth_token")
    if not token and (request.url.path == "/api/events/user" or request.url.path.startswith("/api/admin/system/backup/download")):
        # 允许原生 SSE 长连接与文件下载流通过 query 参数传递 token
        token = request.query_params.get("token")
    if not token:
        return None
    
    payload = decode_jwt_token(token)
    if not payload or not payload.get("sub"):
        return None
    
    user = get_user_by_id(payload["sub"])
    if not user or not user.get("isActive", True):
        return None
    
    expected_ver = user.get("token_version", 1)
    token_ver = payload.get("ver", 1)
    if expected_ver != token_ver:
        return None

    user_id_str = str(user.get("id") or "")
    if user_id_str:
        record_user_activity(user_id_str)

    return sanitize_user(user)

async def get_current_user(user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)) -> Dict[str, Any]:
    if not user:
        raise HTTPException(status_code=401, detail="请先登录后再进行此操作")
    return user

async def get_current_admin(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="权限不足：仅管理员可访问此接口")
    return user


# ----------------- 用户在线状态感知 (方案 B) -----------------
_USER_LAST_ACTIVE: Dict[str, float] = {}  # user_id -> timestamp

def record_user_activity(user_id: str):
    """记录用户最近活跃时间戳"""
    if user_id:
        _USER_LAST_ACTIVE[str(user_id)] = time.time()

def record_user_offline(user_id: str):
    """用户主动登出时立即置为离线"""
    if user_id:
        _USER_LAST_ACTIVE.pop(str(user_id), None)

def get_user_online_status(user_id: str, running_tasks_count: int = 0) -> Dict[str, Any]:
    """
    方案 B：双重智能活跃判定
    1. 用户在最近 300 秒内有访问或心跳记录 -> 在线
    2. 用户名下有正在运行/排队的生图任务 (running_tasks_count > 0) -> 即使关闭网页也判定为挂机渲染中
    """
    now = time.time()
    last_active = _USER_LAST_ACTIVE.get(str(user_id), 0.0)
    has_heartbeat = (now - last_active) <= 300
    has_tasks = running_tasks_count > 0

    if has_heartbeat and has_tasks:
        status_key = "ONLINE_RUNNING"
        text = f"在线 · 渲染中 ({running_tasks_count})"
        badge_type = "success"
    elif has_heartbeat:
        status_key = "ONLINE"
        text = "在线"
        badge_type = "success"
    elif has_tasks:
        status_key = "HOSTING_RUNNING"
        text = f"挂机渲染中 ({running_tasks_count})"
        badge_type = "running"
    else:
        status_key = "OFFLINE"
        if last_active > 0:
            diff = int(now - last_active)
            if diff < 3600:
                text = f"离线 ({max(1, diff // 60)}分钟前)"
            elif diff < 86400:
                text = f"离线 ({diff // 3600}小时前)"
            else:
                text = f"离线 ({diff // 86400}天前)"
        else:
            text = "离线"
        badge_type = "offline"

    return {
        "isOnline": (has_heartbeat or has_tasks),
        "statusKey": status_key,
        "statusText": text,
        "badgeType": badge_type,
        "lastActiveAt": int(last_active) if last_active > 0 else None,
        "runningTasksCount": running_tasks_count
    }

def get_online_user_ids(active_task_user_ids: Optional[Set[str]] = None) -> Set[str]:
    """获取当前全部在线（心跳有效或长任务挂机）的用户 ID 集合"""
    now = time.time()
    online_set = {uid for uid, t in _USER_LAST_ACTIVE.items() if (now - t) <= 300}
    if active_task_user_ids:
        online_set.update(str(uid) for uid in active_task_user_ids if uid)
    return online_set

def count_online_users(active_task_user_ids: Optional[Set[str]] = None) -> int:
    """计算当前在线总人数"""
    return len(get_online_user_ids(active_task_user_ids))
