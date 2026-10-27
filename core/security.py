import os
import base64
import requests
from typing import Tuple, Optional
from cryptography.fernet import Fernet
from core.http_client import HTTP_SESSION

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
SECRET_KEY_FILE = os.path.join(DATA_DIR, ".secret.key")

os.makedirs(DATA_DIR, exist_ok=True)

def _init_master_cipher() -> Fernet:
    """
    初始化主加密套件：
    1. 优先读取系统环境变量 RUNNINGHUB_MASTER_SECRET / RUNNINGHUB_SECRET_KEY
    2. 若无环境变量，从本地 data/.secret.key 读取
    3. 若本地文件不存在，自动生成高强度 256 位随机密钥并持久化
    """
    env_secret = os.getenv("RUNNINGHUB_MASTER_SECRET") or os.getenv("RUNNINGHUB_SECRET_KEY")
    if env_secret:
        import hashlib
        key_hash = hashlib.sha256(env_secret.encode("utf-8")).digest()
        fernet_key = base64.urlsafe_b64encode(key_hash)
        return Fernet(fernet_key)

    if os.path.exists(SECRET_KEY_FILE):
        try:
            with open(SECRET_KEY_FILE, "rb") as f:
                content = f.read().strip()
                if content:
                    return Fernet(content)
        except Exception:
            pass

    new_key = Fernet.generate_key()
    try:
        with open(SECRET_KEY_FILE, "wb") as f:
            f.write(new_key)
        try:
            os.chmod(SECRET_KEY_FILE, 0o600)
        except Exception:
            pass
    except Exception as e:
        print(f"[Security Warning] Failed to persist .secret.key: {e}")
    return Fernet(new_key)

_CIPHER = _init_master_cipher()

def encrypt_key(plain_key: str) -> str:
    """将明文 API Key 加密为 Fernet 密文"""
    if not plain_key:
        return ""
    plain_key = str(plain_key).strip()
    if plain_key.startswith("gAAAAA") and len(plain_key) > 40:
        return plain_key
    try:
        token = _CIPHER.encrypt(plain_key.encode("utf-8"))
        return token.decode("utf-8")
    except Exception as e:
        print(f"[Security Error] Encryption failed: {e}")
        raise RuntimeError(f"Data encryption failed securely: {e}")

def decrypt_key(encrypted_key: str) -> str:
    """将 Fernet 密文解密为明文 API Key"""
    if not encrypted_key:
        return ""
    encrypted_key = str(encrypted_key).strip()
    if not encrypted_key.startswith("gAAAAA"):
        return encrypted_key
    try:
        raw_bytes = _CIPHER.decrypt(encrypted_key.encode("utf-8"))
        return raw_bytes.decode("utf-8")
    except Exception as e:
        print(f"[Security Error] Decryption failed: {e}")
        return ""

def mask_key(raw_key: str) -> str:
    """将 API Key 转换为脱敏形式，例如 e565****8043"""
    if not raw_key:
        return ""
    if raw_key.startswith("gAAAAA"):
        raw_key = decrypt_key(raw_key)
    
    raw_key = raw_key.strip()
    if len(raw_key) <= 8:
        return "****"
    return f"{raw_key[:4]}****{raw_key[-4:]}"

def verify_key_with_runninghub(raw_key: str) -> Tuple[bool, str]:
    """
    轻量级校验 API Key 是否有效：
    请求 RunningHub 接口，验证 API Key 合法性，并精准识别账号是否被封禁/注销/欠费
    使用连接池 Session 避免高频 TLS 握手
    """
    if not raw_key:
        return False, "API Key 为空"
    
    url = "https://www.runninghub.cn/task/openapi/outputs"
    payload = {"apiKey": raw_key, "taskId": "1"}
    try:
        res = HTTP_SESSION.post(url, json=payload, timeout=8)
        data = res.json()
        code = data.get("code")
        msg = str(data.get("msg") or "").strip()

        # 807 代表 APIKEY_TASK_NOT_FOUND，说明 Key 用户完全合法，只是 task 不存在，校验成功
        if code in (807, 0):
            return True, "API Key 校验成功，账号正常可用"
        
        # 1. 明确的账号封禁/冻结风控
        msg_lower = msg.lower()
        if code in (403, 302) or any(k in msg for k in ["封禁", "限制", "冻结", "违规", "风险"]) or "disabled" in msg_lower or "forbidden" in msg_lower:
            return False, f"账号已被 RunningHub 官方封禁/限制使用 (官方提示: {msg}, code: {code})"

        # 2. 账号注销/Key 不存在
        elif code in (806, 301, 401) or any(k in msg_lower for k in ["user_not_found", "not found", "not exist", "invalid", "不存在"]):
            return False, f"API Key 无效或账号已被注销 (官方提示: {msg}, code: {code})"

        # 3. 算力余额不足
        elif code == 402 or any(k in msg for k in ["余额不足", "欠费", "算力不足"]) or "insufficient" in msg_lower:
            return False, f"账号算力余额不足/已耗尽 (官方提示: {msg}, code: {code})"

        else:
            return False, f"RunningHub 接口异常: {msg} (code: {code})"
    except requests.exceptions.Timeout:
        return False, "连接 RunningHub 服务器超时，请检查网络"
    except Exception as e:
        return False, f"网络请求异常: {str(e)}"

def is_key_fatal_error(code: Optional[int], msg: str) -> bool:
    """
    判断 RunningHub 返回的错误是否属于 Key 级故障（如封禁、注销、欠费、未授权或被限制）
    若是 Key 故障，系统必须自动触发无感故障转移 (Failover) 与熔断隔离，杜绝向终端用户暴露
    """
    if code in (403, 301, 302, 401, 806):
        return True
    m = (msg or "").lower()
    banned_keywords = [
        "封禁", "限制", "冻结", "违规", "风险", "disabled", "forbidden", 
        "user_not_found", "not found", "not exist", "invalid", "不存在", 
        "余额不足", "欠费", "算力不足", "insufficient", "apikey"
    ]
    return any(k in m for k in banned_keywords)
