import os
import base64
import requests
from typing import Tuple, Optional
from cryptography.fernet import Fernet

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
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
        # 如果用户提供了普通字符串，补齐或哈希为 32 字节 base64
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

    # 首次自动生成持久化加密密钥
    new_key = Fernet.generate_key()
    try:
        with open(SECRET_KEY_FILE, "wb") as f:
            f.write(new_key)
        # Windows / Linux 权限处理
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
    # 如果已经是 Fernet 格式密文则不重复加密
    if plain_key.startswith("gAAAAA") and len(plain_key) > 40:
        return plain_key
    try:
        token = _CIPHER.encrypt(plain_key.encode("utf-8"))
        return token.decode("utf-8")
    except Exception as e:
        print(f"[Security Error] Encryption failed: {e}")
        return plain_key

def decrypt_key(encrypted_key: str) -> str:
    """将 Fernet 密文解密为明文 API Key"""
    if not encrypted_key:
        return ""
    encrypted_key = str(encrypted_key).strip()
    # 如果未加密（旧数据未迁移情况），直接返回
    if not encrypted_key.startswith("gAAAAA"):
        return encrypted_key
    try:
        raw_bytes = _CIPHER.decrypt(encrypted_key.encode("utf-8"))
        return raw_bytes.decode("utf-8")
    except Exception as e:
        print(f"[Security Error] Decryption failed: {e}")
        # 解密失败说明密钥不匹配或被篡改
        return ""

def mask_key(raw_key: str) -> str:
    """将 API Key 转换为脱敏形式，例如 e565****8043，防止在前端或日志泄露"""
    if not raw_key:
        return ""
    # 若传入的是密文，先尝试解密再脱敏，避免泄露密文特征
    if raw_key.startswith("gAAAAA"):
        raw_key = decrypt_key(raw_key)
    
    raw_key = raw_key.strip()
    if len(raw_key) <= 8:
        return "****"
    return f"{raw_key[:4]}****{raw_key[-4:]}"

def verify_key_with_runninghub(raw_key: str) -> Tuple[bool, str]:
    """
    轻量级校验 API Key 是否有效：
    请求 RunningHub 接口，验证 API Key 合法性
    """
    if not raw_key:
        return False, "API Key 为空"
    
    url = "https://www.runninghub.cn/task/openapi/outputs"
    payload = {"apiKey": raw_key, "taskId": "1"}
    try:
        res = requests.post(url, json=payload, timeout=6)
        data = res.json()
        code = data.get("code")
        msg = data.get("msg") or ""

        # 807 代表 APIKEY_TASK_NOT_FOUND，说明 Key 用户完全合法，只是 task 不存在，校验成功
        if code == 807:
            return True, "API Key 校验成功，账户有效"
        elif code in (806, 301) or "USER_NOT_FOUND" in msg or "not exist" in msg:
            return False, f"API Key 无效或用户不存在 ({msg})"
        elif code == 0:
            return True, "API Key 校验成功"
        else:
            # 其它错误码
            return False, f"RunningHub 响应: {msg} (code: {code})"
    except requests.exceptions.Timeout:
        return False, "连接 RunningHub 超时，请检查网络"
    except Exception as e:
        return False, f"验证请求异常: {str(e)}"
