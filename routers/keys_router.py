import time
import uuid
from typing import Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel

from core.config import (
    load_config, save_config, get_active_api_key,
    get_system_config_safe, get_api_keys_safe, filter_workflows_for_user
)
from core.security import encrypt_key, decrypt_key, mask_key, verify_key_with_runninghub
from core.auth import get_current_user_optional, get_current_admin

router = APIRouter(tags=["Keys & System Config"])

class ConfigUpdateModel(BaseModel):
    apiKey: Optional[str] = ""

class AddKeyModel(BaseModel):
    name: str
    apiKey: str
    note: Optional[str] = ""
    setActive: Optional[bool] = False

@router.get("/api/config")
def get_config(current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)):
    """获取系统运行配置（严格鉴权隔离：普通用户绝不泄露 API 密钥列表）"""
    cfg = load_config()
    active_key_str = get_active_api_key(cfg)
    is_admin = current_user and current_user.get("role") == "admin"
    
    base_res = {
        "hasKey": bool(active_key_str),
        "workflows": filter_workflows_for_user(cfg.get("workflows", []), current_user),
        "system": get_system_config_safe(cfg) if is_admin else {
            "siteTitle": cfg.get("system", {}).get("siteTitle", "RunningHub 智能创作平台"),
            "allowRegistration": bool(cfg.get("system", {}).get("allowRegistration", True)),
            "requireLoginToGenerate": bool(cfg.get("system", {}).get("requireLoginToGenerate", False)),
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

@router.post("/api/config")
def update_config(data: ConfigUpdateModel, _: Dict[str, Any] = Depends(get_current_admin)):
    """向下兼容的旧版单 Key 更新接口（仅限管理员访问）"""
    cfg = load_config()
    if data.apiKey and data.apiKey.strip():
        raw_key = data.apiKey.strip()
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

@router.get("/api/keys")
def list_keys(_: Dict[str, Any] = Depends(get_current_admin)):
    """获取所有已存储的 API Key 列表（仅限管理员）"""
    cfg = load_config()
    return {
        "status": "ok",
        "keys": get_api_keys_safe(cfg),
        "activeKeyId": cfg.get("activeKeyId", "")
    }

@router.post("/api/keys")
def add_key(data: AddKeyModel, _: Dict[str, Any] = Depends(get_current_admin)):
    """添加新的 API Key（仅限管理员，后端即时 Fernet 加密落盘）"""
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

@router.post("/api/keys/{key_id}/activate")
def activate_key(key_id: str, _: Dict[str, Any] = Depends(get_current_admin)):
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

@router.delete("/api/keys/{key_id}")
def delete_key(key_id: str, _: Dict[str, Any] = Depends(get_current_admin)):
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

@router.post("/api/keys/{key_id}/test")
def test_key(key_id: str, _: Dict[str, Any] = Depends(get_current_admin)):
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
