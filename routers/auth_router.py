import time
import json
import asyncio
from typing import Optional, Dict, Any
from fastapi import APIRouter, Request, Response, HTTPException, Depends
from fastapi.responses import StreamingResponse, RedirectResponse
from pydantic import BaseModel

from core.config import load_config
from core.security import decrypt_key
from core.database import (
    is_rate_limited, record_failed_attempt, clear_failed_attempts
)
from core.auth import (
    get_user_count, create_user, get_user_by_id, get_user_by_identifier,
    update_user_fields, set_user_password, verify_password,
    create_jwt_token, verify_turnstile_token, sanitize_user,
    get_current_user, get_current_user_optional,
    USER_EVENT_CHANNELS
)

router = APIRouter(tags=["Authentication"])

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

@router.get("/api/auth/public-config")
def get_public_auth_config():
    """面向前端登录注册界面的公开基础配置（无任何私钥敏感数据）"""
    cfg = load_config()
    sys_cfg = cfg.get("system", {})
    return {
        "siteTitle": sys_cfg.get("siteTitle", "RunningHub 智能调度中心"),
        "turnstileEnabled": bool(sys_cfg.get("turnstileEnabled", False)),
        "turnstileSiteKey": sys_cfg.get("turnstileSiteKey", ""),
        "allowRegistration": bool(sys_cfg.get("allowRegistration", True)),
        "requireLoginToGenerate": bool(sys_cfg.get("requireLoginToGenerate", False)),
        "broadcast": sys_cfg.get("broadcast", {"enabled": False, "message": "", "level": "info"}),
        "maintenance": sys_cfg.get("maintenance", {"enabled": False, "message": "系统维护中"}),
        "isFirstUser": get_user_count() == 0
    }

@router.post("/api/auth/register")
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

@router.post("/api/auth/login")
async def login_user(req: LoginRequest, request: Request, response: Response):
    cfg = load_config()
    sys_cfg = cfg.get("system", {})
    
    client_ip = request.client.host if request.client else "unknown"
    rate_key = f"{client_ip}:{req.identifier.strip().lower()}"
    if is_rate_limited(rate_key):
        raise HTTPException(status_code=429, detail="密码连续错误次数过多，账户已被临时锁定 15 分钟以防暴力破解，请稍后再试")
    
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

@router.get("/api/auth/me")
def get_me(user: Dict[str, Any] = Depends(get_current_user)):
    fresh = get_user_by_id(user["id"])
    if not fresh:
        raise HTTPException(status_code=404, detail="用户不存在")
    return sanitize_user(fresh)

@router.get("/api/events/user")
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
            yield f"data: {json.dumps({'type': 'CONNECTED', 'data': {'userId': user_id, 'points': current_user.get('points', 0)}})}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
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

@router.post("/api/auth/logout")
def logout_user(response: Response):
    response.delete_cookie("auth_token")
    return {"status": "ok", "message": "已安全退出登录"}

@router.post("/api/auth/change-password")
def change_user_password(req: ChangePasswordRequest, user: Dict[str, Any] = Depends(get_current_user)):
    u = get_user_by_id(user["id"])
    if not u:
        raise HTTPException(status_code=404, detail="用户不存在")
    if not verify_password(req.oldPassword, u.get("passwordHash", ""), u.get("salt", "")):
        raise HTTPException(status_code=400, detail="原密码验证失败，请重新输入")
    if len(req.newPassword) < 6:
        raise HTTPException(status_code=400, detail="新密码长度不能少于 6 位")
    set_user_password(user["id"], req.newPassword)
    return {"status": "ok", "message": "密码修改成功，请重新登录"}

@router.post("/api/admin/auth/login")
async def admin_portal_login(req: LoginRequest, request: Request, response: Response):
    cfg = load_config()
    sys_cfg = cfg.get("system", {})
    
    client_ip = request.client.host if request.client else "unknown"
    rate_key = f"admin:{client_ip}:{req.identifier.strip().lower()}"
    if is_rate_limited(rate_key):
        raise HTTPException(status_code=429, detail="管理员登录密码错误过多，锁定 15 分钟，请稍后再试")
    
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
        raise HTTPException(status_code=400, detail="账号不存在")
    if user.get("role") != "admin":
        record_failed_attempt(rate_key)
        raise HTTPException(status_code=403, detail="该账号不具备管理员权限，禁止登录管理后台")
    if not user.get("isActive", True):
        raise HTTPException(status_code=403, detail="管理员账户已被禁用")
    
    if not verify_password(req.password, user.get("passwordHash", ""), user.get("salt", "")):
        record_failed_attempt(rate_key)
        raise HTTPException(status_code=400, detail="管理密码错误")
    
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

@router.get("/sign-in")
def route_sign_in():
    return RedirectResponse(url="/login.html", status_code=302)

@router.get("/login")
def route_login():
    return RedirectResponse(url="/login.html", status_code=302)

@router.get("/register")
def route_register():
    return RedirectResponse(url="/login.html?tab=register", status_code=302)

@router.get("/admin")
def route_admin_portal():
    return RedirectResponse(url="/admin.html", status_code=302)
