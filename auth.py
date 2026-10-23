import os
import json
import time
import base64
import hmac
import hashlib
import uuid
import aiohttp
from typing import Optional, List, Dict, Any, Tuple
from security import SECRET_KEY_FILE
from database import get_db_connection, db_bump_token_version

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 从安全加密密钥派生 JWT 签名密钥（严格 fail-fast 启动门禁，严禁源码内嵌硬编码弱密钥）
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
    raise RuntimeError("[Security Fail-Fast] 未检测到有效的 JWT_SECRET_KEY 环境变量或 .secret.key 主加密凭证，为防账号伪造系统强制拒绝启动！")

_JWT_SECRET = _get_jwt_secret()

# ----------------- 数据字段安全脱敏 -----------------

def sanitize_user(row: Any) -> Dict[str, Any]:
    """将数据库行转换为安全的前端用户字典，彻底剥离 password_hash 和 salt"""
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

# ----------------- SQLite 数据库用户操作 (高并发与事务保护) -----------------

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
    """兼容旧接口占位函数 (当前已由 SQLite 事务自动落盘保障)"""
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
    """支持以用户名或绑定邮箱查找（不区分大小写）"""
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
    """PBKDF2-HMAC-SHA256 工业级密码哈希，10万次迭代，防彩虹表与硬件暴力破解"""
    if not salt:
        salt = os.urandom(16).hex()
    pwd_bytes = password.encode("utf-8")
    salt_bytes = salt.encode("utf-8")
    pwd_hash = hashlib.pbkdf2_hmac("sha256", pwd_bytes, salt_bytes, 100000).hex()
    return pwd_hash, salt

def verify_password(password: str, password_hash: str, salt: str) -> bool:
    """常量时间对比密码，免疫时序侧信道攻击"""
    computed_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(computed_hash, password_hash)

# ----------------- JWT 鉴权令牌 -----------------

def create_jwt_token(payload: Dict[str, Any], expires_in_seconds: int = 86400 * 7) -> str:
    """生成带有过期时间戳的 HS256 JWT Token"""
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
    """校验并解码 JWT Token，若篡改或过期返回 None"""
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
    if not token:
        return False, "请先勾选并完成 Cloudflare 人机安全验证"
    
    url = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    payload = {
        "secret": secret_key,
        "response": token
    }
    if remote_ip:
        payload["remoteip"] = remote_ip
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=payload, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                data = await resp.json()
                if data.get("success"):
                    return True, "人机验证通过"
                codes = data.get("error-codes", [])
                err_msg = ", ".join(codes) if codes else "人机安全验证未通过"
                return False, f"Turnstile 校验失败: {err_msg}"
    except Exception as e:
        return False, f"无法连接 Cloudflare Turnstile 验证服务器: {str(e)}"

# ----------------- 用户创建与管理逻辑 (SQLite 事务原子操作) -----------------

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
        
        # 唯一性检查
        cursor.execute("SELECT id FROM users WHERE LOWER(username) = ?;", (username_clean.lower(),))
        if cursor.fetchone():
            raise ValueError("该用户名已被注册，请尝试其他名称")
        
        if email_clean:
            cursor.execute("SELECT id FROM users WHERE LOWER(email) = ?;", (email_clean.lower(),))
            if cursor.fetchone():
                raise ValueError("该邮箱已被绑定，请直接登录")
        
        # 系统首位注册者自动成为超级管理员
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
    """原子更新用户字段"""
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

    # 若修改了用户状态（如封禁）或角色权限，立即自增 token_version 强制吊销旧 Token，实现 0.1 秒秒级踢出
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
        # 修改密码后立即吊销旧会话 Token
        db_bump_token_version(str(user_id))
    return ok

def delete_user_by_id(user_id: str) -> bool:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = ?;", (str(user_id),))
        conn.commit()
        return cursor.rowcount > 0
