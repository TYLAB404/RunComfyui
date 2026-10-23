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

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
USERS_PATH = os.path.join(DATA_DIR, "users.json")
CONFIG_PATH = os.path.join(DATA_DIR, "config.json")

os.makedirs(DATA_DIR, exist_ok=True)

# 从加密套件派生 JWT 签名密钥（保持长期稳定，跨重启不丢失）
def _get_jwt_secret() -> bytes:
    env_secret = os.getenv("JWT_SECRET_KEY")
    if env_secret:
        return env_secret.encode("utf-8")
    if os.path.exists(SECRET_KEY_FILE):
        try:
            with open(SECRET_KEY_FILE, "rb") as f:
                content = f.read().strip()
                if content:
                    return hashlib.sha256(content + b"::JWT_SALT").digest()
        except Exception:
            pass
    return b"RUNNINGHUB_WEB_DEFAULT_JWT_SECRET_SALT_2026"

_JWT_SECRET = _get_jwt_secret()

# ----------------- 用户数据存取 -----------------

def load_users() -> List[Dict[str, Any]]:
    if not os.path.exists(USERS_PATH):
        return []
    try:
        with open(USERS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def save_users(users: List[Dict[str, Any]]):
    with open(USERS_PATH, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2, ensure_ascii=False)

def sanitize_user(user: Dict[str, Any]) -> Dict[str, Any]:
    """移除敏感字段后返回前端安全的用户对象"""
    safe = dict(user)
    safe.pop("passwordHash", None)
    safe.pop("salt", None)
    return safe

def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    users = load_users()
    for u in users:
        if str(u.get("id")) == str(user_id):
            return u
    return None

def get_user_by_identifier(identifier: str) -> Optional[Dict[str, Any]]:
    """通过用户名或邮箱查找（忽略大小写）"""
    if not identifier:
        return None
    ident = str(identifier).strip().lower()
    users = load_users()
    for u in users:
        if u.get("username", "").lower() == ident or u.get("email", "").lower() == ident:
            return u
    return None

# ----------------- 密码与哈希安全 -----------------

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
        # 补齐 base64 padding
        p_padded = p_b64 + "=" * ((4 - len(p_b64) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode(p_padded.encode()).decode("utf-8"))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None

# ----------------- Cloudflare Turnstile 人机验证 -----------------

async def verify_turnstile_token(token: str, secret_key: str, remote_ip: str = "") -> Tuple[bool, str]:
    """
    向 Cloudflare Turnstile 官方接口验证客户端人机令牌
    如果系统未开启验证或 secret_key 为空，自动视为放行（开发测试模式）
    """
    if not secret_key:
        return True, "未配置 Turnstile SecretKey，默认放行"
    if not token:
        return False, "请先完成 Cloudflare 人机安全验证"
    
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
        # 网络异常时提示具体原因
        return False, f"无法连接 Cloudflare Turnstile 验证服务器: {str(e)}"

# ----------------- 用户创建与管理逻辑 -----------------

def create_user(
    username: str, 
    email: str, 
    password: str, 
    role: str = "user", 
    points: int = 100
) -> Dict[str, Any]:
    users = load_users()
    
    # 唯一性检查
    username_clean = username.strip()
    email_clean = email.strip()
    for u in users:
        if u.get("username", "").lower() == username_clean.lower():
            raise ValueError("该用户名已被注册，请尝试其他名称")
        if email_clean and u.get("email", "").lower() == email_clean.lower():
            raise ValueError("该邮箱已被绑定，请直接登录")
    
    # 核心机制：如果当前系统没有任何用户，首个注册者自动晋升为超级管理员（admin）
    if len(users) == 0:
        role = "admin"
        points = max(points, 1000)
    
    pwd_hash, salt = hash_password(password)
    new_user = {
        "id": f"usr_{uuid.uuid4().hex[:10]}",
        "username": username_clean,
        "email": email_clean,
        "passwordHash": pwd_hash,
        "salt": salt,
        "role": role,
        "points": points,
        "isActive": True,
        "createdAt": int(time.time()),
        "lastLogin": int(time.time()),
        "taskCount": 0
    }
    users.append(new_user)
    save_users(users)
    return new_user

def update_user_fields(user_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    users = load_users()
    target = None
    for u in users:
        if str(u.get("id")) == str(user_id):
            # 不允许直接通过普通 update 篡改 passwordHash 或 salt
            clean_updates = {k: v for k, v in updates.items() if k not in ("passwordHash", "salt", "id")}
            u.update(clean_updates)
            target = u
            break
    if target:
        save_users(users)
    return target

def set_user_password(user_id: str, new_password: str) -> bool:
    users = load_users()
    found = False
    for u in users:
        if str(u.get("id")) == str(user_id):
            pwd_hash, salt = hash_password(new_password)
            u["passwordHash"] = pwd_hash
            u["salt"] = salt
            found = True
            break
    if found:
        save_users(users)
    return found

def delete_user_by_id(user_id: str) -> bool:
    users = load_users()
    initial_len = len(users)
    users = [u for u in users if str(u.get("id")) != str(user_id)]
    if len(users) != initial_len:
        save_users(users)
        return True
    return False
