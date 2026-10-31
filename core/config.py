import os
import json
import copy
import random
import threading
from typing import Dict, Any, Optional, List, Tuple

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
CONFIG_PATH = os.path.join(DATA_DIR, "config.json")
STATIC_DIR = os.path.join(BASE_DIR, "static")
OUTPUTS_DIR = os.path.join(BASE_DIR, "outputs")
WORKFLOWS_DIR = os.path.join(DATA_DIR, "workflows")
TASKS_PATH = os.path.join(DATA_DIR, "tasks.json")
RUNNINGHUB_API_URL = "https://www.runninghub.cn"

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(OUTPUTS_DIR, exist_ok=True)
os.makedirs(WORKFLOWS_DIR, exist_ok=True)

_CONFIG_CACHE: Optional[Dict[str, Any]] = None
_CONFIG_MTIME: float = 0.0
_CONFIG_LOCK = threading.RLock()

def sort_workflows(workflows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
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

import hashlib

def get_virtual_workflow_id(real_id: str) -> str:
    """对普通用户隐藏真实云端工作流 ID，生成安全不可逆的单向虚拟代号"""
    real_str = str(real_id).strip()
    if not real_str or real_str.startswith("wf_v_") or real_str.startswith("custom_"):
        return real_str
    h = hashlib.sha256(f"rh_wf_secure_salt_{real_str}".encode()).hexdigest()[:10]
    return f"wf_v_{h}"

def resolve_real_workflow_id(wf_id: str, cfg: Dict[str, Any]) -> str:
    """安全反向解析：无论传入虚拟 ID 还是真实 ID，均可安全还原真实云端工作流 ID"""
    wf_str = str(wf_id).strip()
    for w in cfg.get("workflows", []):
        real_id = str(w.get("id"))
        if real_id == wf_str:
            return real_id
        if get_virtual_workflow_id(real_id) == wf_str:
            return real_id
    return wf_str

def filter_workflows_for_user(workflows: List[Dict[str, Any]], current_user: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    sorted_all = sort_workflows(workflows)
    if current_user and current_user.get("role") == "admin":
        admin_res = []
        for w in sorted_all:
            cw = dict(w)
            cw["minPointsEnabled"] = bool(w.get("minPointsEnabled", False))
            cw["minPoints"] = int(w.get("minPoints") or 0)
            admin_res.append(cw)
        return admin_res
    
    res = []
    user_id_str = str(current_user["id"]) if current_user else ""
    for w in sorted_all:
        is_official = bool(w.get("isOfficial", False))
        is_active = bool(w.get("isActive", True))
        owner_id = str(w.get("ownerId", ""))
        
        target_w = None
        if is_official and is_active:
            target_w = dict(w)
            target_w["id"] = get_virtual_workflow_id(str(w.get("id")))
        elif user_id_str and owner_id == user_id_str and is_active:
            target_w = dict(w)
            target_w["id"] = get_virtual_workflow_id(str(w.get("id")))
            
        if target_w:
            target_w["minPointsEnabled"] = bool(w.get("minPointsEnabled", False))
            target_w["minPoints"] = int(w.get("minPoints") or 0)
            res.append(target_w)
            
    return res

def _sanitize_and_migrate_config(cfg: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    from core.security import encrypt_key
    needs_save = False

    if "apiKeys" not in cfg or not isinstance(cfg["apiKeys"], list):
        cfg["apiKeys"] = []

    legacy_key = cfg.pop("apiKey", None)
    if legacy_key and str(legacy_key).strip():
        legacy_key_str = str(legacy_key).strip()
        has_it = any(k.get("keyEncrypted") == legacy_key_str for k in cfg["apiKeys"])
        if not has_it:
            import uuid, time
            first_key_id = str(uuid.uuid4())
            cfg["apiKeys"].append({
                "id": first_key_id,
                "name": "默认主密钥",
                "keyEncrypted": encrypt_key(legacy_key_str),
                "isActive": True,
                "createdAt": int(time.time()),
                "note": "系统自动从旧版本配置平滑迁移"
            })
            cfg["activeKeyId"] = first_key_id
            needs_save = True

    for k in cfg["apiKeys"]:
        if "keyEncrypted" in k:
            enc = k["keyEncrypted"]
            if not enc.startswith("gAAAAA"):
                k["keyEncrypted"] = encrypt_key(enc)
                needs_save = True

    if cfg["apiKeys"]:
        active_ids = [k["id"] for k in cfg["apiKeys"]]
        if cfg.get("activeKeyId") not in active_ids:
            cfg["activeKeyId"] = active_ids[0]
            needs_save = True
    else:
        cfg["activeKeyId"] = ""

    if "system" not in cfg or not isinstance(cfg["system"], dict):
        cfg["system"] = {}
        needs_save = True

    sys_cfg = cfg["system"]
    defaults = {
        "siteTitle": "RunComfyui 智能创作平台",
        "turnstileEnabled": False,
        "turnstileSiteKey": "",
        "turnstileSecretKeyEncrypted": "",
        "allowRegistration": True,
        "defaultUserPoints": 100,
        "requireLoginToGenerate": False,
        "hideAuxiliaryAudioChain": True,
        "broadcast": {"enabled": False, "message": "", "level": "info"},
        "maintenance": {"enabled": False, "message": "系统维护中"},
        "maintenanceMode": False,
        "maintenanceReason": "系统正在例行升级维护中，请稍后再试",
        "smtp": {
            "enabled": False,
            "host": "smtp.qq.com",
            "port": 465,
            "user": "",
            "fromEmail": "",
            "passwordEncrypted": "",
            "adminEmail": ""
        },
        "pricing": {
            "standardRate": 0.2,
            "plusRate": 0.4,
            "minBalanceRequired": 5.0
        }
    }
    for k, v in defaults.items():
        if k not in sys_cfg:
            sys_cfg[k] = v
            needs_save = True

    return cfg, needs_save

def load_config() -> Dict[str, Any]:
    global _CONFIG_CACHE, _CONFIG_MTIME
    with _CONFIG_LOCK:
        try:
            if os.path.exists(CONFIG_PATH):
                mtime = os.path.getmtime(CONFIG_PATH)
                if _CONFIG_CACHE is not None and mtime <= _CONFIG_MTIME:
                    return copy.deepcopy(_CONFIG_CACHE)
                
                with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                
                cfg, needs_save = _sanitize_and_migrate_config(cfg)
                _CONFIG_CACHE = cfg
                _CONFIG_MTIME = mtime
                
                if needs_save:
                    save_config(cfg)
                    
                return copy.deepcopy(_CONFIG_CACHE)
        except Exception as e:
            print(f"[Config Error] Error loading config: {e}")
            if _CONFIG_CACHE is not None:
                return copy.deepcopy(_CONFIG_CACHE)

    default_cfg = {
        "activeKeyId": "",
        "apiKeys": [],
        "workflows": [],
        "system": {
            "allowRegistration": True,
            "defaultUserPoints": 100,
            "smtp": {"enabled": False, "host": "smtp.qq.com", "port": 465, "user": "", "adminEmail": ""}
        }
    }
    return default_cfg

def save_config(cfg: Dict[str, Any]):
    global _CONFIG_CACHE, _CONFIG_MTIME
    with _CONFIG_LOCK:
        tmp_file = f"{CONFIG_PATH}.tmp.{os.getpid()}_{random.randint(1000, 9999)}"
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_file, CONFIG_PATH)
        _CONFIG_CACHE = copy.deepcopy(cfg)
        _CONFIG_MTIME = os.path.getmtime(CONFIG_PATH)

def get_active_api_key(cfg: Optional[Dict[str, Any]] = None) -> str:
    from core.security import decrypt_key
    if cfg is None:
        cfg = load_config()
    active_id = cfg.get("activeKeyId")
    for item in cfg.get("apiKeys", []):
        if item.get("id") == active_id:
            raw = decrypt_key(item.get("keyEncrypted", ""))
            if raw:
                return raw
    for item in cfg.get("apiKeys", []):
        raw = decrypt_key(item.get("keyEncrypted", ""))
        if raw:
            return raw
    return ""

def get_system_config_safe(cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    from core.security import decrypt_key, mask_key
    if cfg is None:
        cfg = load_config()
    sys_cfg = dict(cfg.get("system", {}))
    secret_enc = sys_cfg.pop("turnstileSecretKeyEncrypted", "")
    secret_raw = decrypt_key(secret_enc) if secret_enc else ""
    sys_cfg["turnstileSecretKeyMasked"] = mask_key(secret_raw) if secret_raw else ""
    sys_cfg["hasTurnstileSecret"] = bool(secret_raw)

    imgbed_enc = sys_cfg.pop("imgbedAuthHeaderEncrypted", "")
    imgbed_raw = decrypt_key(imgbed_enc) if imgbed_enc else ""
    sys_cfg["imgbedAuthHeaderMasked"] = mask_key(imgbed_raw) if imgbed_raw else ""
    sys_cfg["hasImgbedAuthHeader"] = bool(imgbed_raw)
    return sys_cfg

def get_imgbed_config(cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    from core.security import decrypt_key, mask_key
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

def get_api_keys_safe(cfg: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    from core.security import decrypt_key, mask_key
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
            "isActive": k.get("id") == active_id,
            "createdAt": k.get("createdAt", 0),
            "note": k.get("note", "")
        })
    return safe_list
