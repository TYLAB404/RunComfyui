import os
import time
import json
import asyncio
import random
import re
from typing import Optional, Dict, Any, Tuple
from fastapi import APIRouter, Request, Response, HTTPException, Depends
from fastapi.responses import StreamingResponse, RedirectResponse, FileResponse
from pydantic import BaseModel

from core.config import load_config, BASE_DIR, STATIC_DIR
from core.security import decrypt_key
from core.database import (
    is_rate_limited, record_failed_attempt, clear_failed_attempts, get_db_connection
)
from core.auth import (
    get_user_count, create_user, get_user_by_id, get_user_by_identifier,
    update_user_fields, set_user_password, verify_password,
    create_jwt_token, decode_jwt_token, verify_turnstile_token, sanitize_user,
    get_current_user, get_current_user_optional,
    USER_EVENT_CHANNELS
)
from services.email_service import send_verification_code_email

router = APIRouter(tags=["Authentication"])

# 内存验证码缓存池: email.lower() -> {code, purpose, expires_at, last_sent_at, attempts}
VERIFY_CODES: Dict[str, Dict[str, Any]] = {}

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USERNAME_REGEX = re.compile(r"^[\u4e00-\u9fa5a-zA-Z0-9_\-]+$")
RESERVED_USERNAMES = {
    "admin", "administrator", "root", "system", "sys", "official",
    "runninghub", "RunComfyui", "support", "help", "bot", "vip", "null", "undefined",
    "官方", "管理员", "系统", "客服", "管家", "超级管理员"
}

def store_verify_code(email: str, code: str, purpose: str = "register"):
    now = time.time()
    VERIFY_CODES[email.lower()] = {
        "code": str(code).strip(),
        "purpose": purpose,
        "expires_at": now + 300,  # 5 分钟有效
        "last_sent_at": now,
        "attempts": 0
    }

def check_verify_code_cooldown(email: str) -> Optional[int]:
    now = time.time()
    entry = VERIFY_CODES.get(email.lower())
    if entry:
        remaining = 60 - int(now - entry.get("last_sent_at", 0))
        if remaining > 0:
            return remaining
    return None

def check_and_consume_verify_code(email: str, code: str, purpose: str = "register") -> Tuple[bool, str]:
    now = time.time()
    entry = VERIFY_CODES.get(email.lower())
    if not entry:
        return False, "验证码不存在或已过期，请重新点击发送"
    if entry.get("purpose") != purpose:
        return False, "验证码类型不匹配，请重新获取"
    if now > entry.get("expires_at", 0):
        VERIFY_CODES.pop(email.lower(), None)
        return False, "验证码已超时过期（有效期5分钟），请重新获取"
    if entry.get("attempts", 0) >= 5:
        VERIFY_CODES.pop(email.lower(), None)
        return False, "验证码输错次数过多已作废，请重新获取"
    
    if str(entry.get("code")).strip() != str(code).strip():
        entry["attempts"] = entry.get("attempts", 0) + 1
        return False, f"验证码输入错误，剩余重试次数: {5 - entry['attempts']}"
    
    # 验证正确，核销验证码防二次重放
    VERIFY_CODES.pop(email.lower(), None)
    return True, "验证通过"


# ----------------- 请求模型 -----------------

class SendCodeRequest(BaseModel):
    email: str
    purpose: str = "register"  # "register" 或 "reset"
    turnstileToken: Optional[str] = ""

class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    confirmPassword: Optional[str] = ""
    code: Optional[str] = ""
    agreeTerms: Optional[bool] = True
    turnstileToken: Optional[str] = ""

class LoginRequest(BaseModel):
    identifier: str
    password: str
    agreeTerms: Optional[bool] = True
    turnstileToken: Optional[str] = ""

class ResetPasswordRequest(BaseModel):
    email: str
    code: str
    newPassword: str
    confirmPassword: Optional[str] = ""
    agreeTerms: Optional[bool] = True
    turnstileToken: Optional[str] = ""

class ChangePasswordRequest(BaseModel):
    oldPassword: str
    newPassword: str


# ----------------- 接口实现 -----------------

@router.get("/api/auth/public-config")
def get_public_auth_config():
    """面向前端登录注册界面的公开基础配置（无任何私钥敏感数据）"""
    cfg = load_config()
    sys_cfg = cfg.get("system", {})
    smtp_enabled = bool(sys_cfg.get("smtp", {}).get("enabled", False))
    cdkey_url = sys_cfg.get("cdkeyPurchaseUrl", "").strip()
    if cdkey_url and not (cdkey_url.startswith("http://") or cdkey_url.startswith("https://")):
        cdkey_url = f"https://{cdkey_url}"

    return {
        "siteTitle": sys_cfg.get("siteTitle", "RunComfyui 智能创作平台"),
        "turnstileEnabled": bool(sys_cfg.get("turnstileEnabled", False)),
        "turnstileSiteKey": sys_cfg.get("turnstileSiteKey", ""),
        "allowRegistration": bool(sys_cfg.get("allowRegistration", True)),
        "requireLoginToGenerate": bool(sys_cfg.get("requireLoginToGenerate", False)),
        "emailVerifyEnabled": smtp_enabled,
        "broadcast": sys_cfg.get("broadcast", {"enabled": False, "message": "", "level": "info"}),
        "maintenance": sys_cfg.get("maintenance", {"enabled": False, "message": "系统维护中"}),
        "isFirstUser": get_user_count() == 0,
        "cdkeyPurchaseUrl": cdkey_url,
        "cdkeyPurchaseText": sys_cfg.get("cdkeyPurchaseText", "前往爱发电购买卡密"),
        "workflowCategories": sys_cfg.get("workflowCategories") or ["文生图", "图生图", "视频生成", "声音音频", "画质增强", "其他"]
    }

@router.post("/api/auth/send-code")
async def send_verify_code(req: SendCodeRequest, request: Request):
    """
    发送 6 位数邮箱验证码（注册验证或密码重置）
    包含 Cloudflare Turnstile 人机防刷、60秒冷却限制、5分钟有效
    """
    cfg = load_config()
    sys_cfg = cfg.get("system", {})
    
    # 1. 检查发信功能是否可用
    smtp_cfg = sys_cfg.get("smtp", {})
    if not smtp_cfg.get("enabled"):
        raise HTTPException(status_code=400, detail="系统管理员尚未启用 SMTP 邮件服务，暂无法发送邮件验证码")
    
    # 2. 邮箱格式校验
    email = req.email.strip().lower()
    if not EMAIL_REGEX.match(email):
        raise HTTPException(status_code=400, detail="请输入格式正确的电子邮箱地址（例如 name@example.com）")
    
    # 3. 业务逻辑检测
    purpose = req.purpose.strip().lower() if req.purpose else "register"
    user = get_user_by_identifier(email)
    
    if purpose == "register":
        if not sys_cfg.get("allowRegistration", True):
            raise HTTPException(status_code=403, detail="管理员已关闭新用户注册通道")
        if user:
            raise HTTPException(status_code=400, detail="该电子邮箱已被注册，请直接登录或找回密码")
    elif purpose == "reset":
        if not user:
            raise HTTPException(status_code=400, detail="该电子邮箱尚未注册账户，请先注册")
        if not user.get("isActive", True):
            raise HTTPException(status_code=403, detail="该账户已被管理员封禁，无法重置密码")
    else:
        raise HTTPException(status_code=400, detail="未知的验证码用途")
    
    # 4. Cloudflare Turnstile 人机验证（防恶意机器人批量刷发信接口）
    if sys_cfg.get("turnstileEnabled"):
        secret_enc = sys_cfg.get("turnstileSecretKeyEncrypted", "")
        secret_key = decrypt_key(secret_enc) if secret_enc else ""
        if secret_key:
            if not req.turnstileToken:
                raise HTTPException(status_code=400, detail="请先勾选并完成下方人机安全验证，再发送验证码")
            client_ip = request.client.host if request.client else ""
            ok, msg = await verify_turnstile_token(req.turnstileToken, secret_key, client_ip)
            if not ok:
                raise HTTPException(status_code=400, detail=msg)
    
    # 5. 60 秒冷却检测
    cooldown = check_verify_code_cooldown(email)
    if cooldown:
        raise HTTPException(status_code=429, detail=f"验证码发送过于频繁，请等待 {cooldown} 秒后再试")
    
    # 6. 生成 6 位随机验证码并持久到缓存
    code = f"{random.randint(100000, 999999)}"
    store_verify_code(email, code, purpose)
    
    # 7. 异步发送邮件
    ok, err_msg = await asyncio.to_thread(send_verification_code_email, email, code, purpose)
    if not ok:
        raise HTTPException(status_code=500, detail=f"发送验证邮件失败: {err_msg}")
    
    return {
        "status": "ok",
        "message": f"验证码已发送至您的邮箱，5分钟内有效",
        "cooldown": 60
    }

@router.post("/api/auth/register")
async def register_user(req: RegisterRequest, request: Request, response: Response):
    """
    新用户注册接口
    支持：用户名规范（3-25位字母数字中文下划线）、8-20位密码复杂度校验、二次密码核验、强制邮箱验证码核销、协议同意校验
    """
    cfg = load_config()
    sys_cfg = cfg.get("system", {})
    if not sys_cfg.get("allowRegistration", True):
        raise HTTPException(status_code=403, detail="管理员已关闭新用户注册通道")
    
    # 1. 用户协议强制勾选
    if not req.agreeTerms:
        raise HTTPException(status_code=400, detail="请阅读并勾选同意《用户协议》和《隐私政策》")
    
    # 2. 用户名格式与敏感词校验
    username = req.username.strip()
    if len(username) < 3 or len(username) > 25:
        raise HTTPException(status_code=400, detail="用户名长度需在 3 到 25 个字符之间")
    if not USERNAME_REGEX.match(username):
        raise HTTPException(status_code=400, detail="用户名仅支持英文字母、数字、中文字符、下划线及连字符")
    if username.lower() in RESERVED_USERNAMES:
        raise HTTPException(status_code=400, detail="该用户名属于系统保留标识，请更换其他名称")
    
    # 3. 密码格式与二次核对（对标 RunComfyui: 8-20 个字符）
    if len(req.password) < 8 or len(req.password) > 20:
        raise HTTPException(status_code=400, detail="密码长度必须在 8 到 20 个字符之间")
    if req.confirmPassword and req.password != req.confirmPassword:
        raise HTTPException(status_code=400, detail="两次输入的密码不一致，请仔细核对")
    
    # 4. 电子邮箱格式校验（验证必需）
    email = req.email.strip().lower()
    if not EMAIL_REGEX.match(email):
        raise HTTPException(status_code=400, detail="请输入格式正确的电子邮箱地址（例如 name@example.com）")
    
    # 5. 邮箱验证码校验（若系统开启了 SMTP 则必须验证）
    smtp_enabled = bool(sys_cfg.get("smtp", {}).get("enabled", False))
    if smtp_enabled:
        if not req.code:
            raise HTTPException(status_code=400, detail="请输入邮箱收到的 6 位数字验证码")
        ok, code_msg = check_and_consume_verify_code(email, req.code, purpose="register")
        if not ok:
            raise HTTPException(status_code=400, detail=code_msg)
    
    # 6. Cloudflare Turnstile 人机验证
    if sys_cfg.get("turnstileEnabled"):
        secret_enc = sys_cfg.get("turnstileSecretKeyEncrypted", "")
        secret_key = decrypt_key(secret_enc) if secret_enc else ""
        if secret_key:
            client_ip = request.client.host if request.client else ""
            if req.turnstileToken:
                ok, msg = await verify_turnstile_token(req.turnstileToken, secret_key, client_ip)
                if not ok and not smtp_enabled:
                    raise HTTPException(status_code=400, detail=msg)
            elif not smtp_enabled:
                raise HTTPException(status_code=400, detail="请完成人机安全验证")
    
    # 7. 写入数据库创建用户
    default_points = sys_cfg.get("defaultUserPoints", 100)
    try:
        user = create_user(
            username=username,
            email=email,
            password=req.password,
            role="user",
            points=default_points
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    # 8. 签发登录态令牌
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

@router.post("/api/auth/reset-password")
async def reset_password_with_code(req: ResetPasswordRequest, request: Request):
    """
    使用邮箱验证码重置登录密码
    """
    cfg = load_config()
    sys_cfg = cfg.get("system", {})
    
    # 1. 协议同意检查
    if not req.agreeTerms:
        raise HTTPException(status_code=400, detail="请勾选同意用户协议与隐私政策")
    
    # 2. 邮箱地址核验
    email = req.email.strip().lower()
    if not EMAIL_REGEX.match(email):
        raise HTTPException(status_code=400, detail="请输入正确的电子邮箱地址")
    
    user = get_user_by_identifier(email)
    if not user:
        raise HTTPException(status_code=400, detail="该电子邮箱尚未注册账户")
    if not user.get("isActive", True):
        raise HTTPException(status_code=403, detail="该账号已被管理员封禁停用")
    
    # 3. 密码格式与比对
    if len(req.newPassword) < 8 or len(req.newPassword) > 20:
        raise HTTPException(status_code=400, detail="新密码长度必须在 8 到 20 个字符之间")
    if req.confirmPassword and req.newPassword != req.confirmPassword:
        raise HTTPException(status_code=400, detail="两次输入的新密码不一致，请仔细核对")
    
    # 4. 验证码校验
    if not req.code:
        raise HTTPException(status_code=400, detail="请输入邮箱收到的 6 位数重置验证码")
    ok, code_msg = check_and_consume_verify_code(email, req.code, purpose="reset")
    if not ok:
        raise HTTPException(status_code=400, detail=code_msg)
    
    # 5. Turnstile 校验
    if sys_cfg.get("turnstileEnabled"):
        secret_enc = sys_cfg.get("turnstileSecretKeyEncrypted", "")
        secret_key = decrypt_key(secret_enc) if secret_enc else ""
        if secret_key:
            client_ip = request.client.host if request.client else ""
            smtp_enabled = bool(sys_cfg.get("smtp", {}).get("enabled", False))
            if req.turnstileToken:
                ok, msg = await verify_turnstile_token(req.turnstileToken, secret_key, client_ip)
                if not ok and not smtp_enabled:
                    raise HTTPException(status_code=400, detail=msg)
            elif not smtp_enabled:
                raise HTTPException(status_code=400, detail="请完成人机安全验证")
    
    # 6. 更新用户密码并吊销旧 Session Token
    set_user_password(user["id"], req.newPassword)
    return {"status": "ok", "message": "您的账户密码已成功重置，请返回登录页使用新密码登录！"}

@router.post("/api/auth/login")
async def login_user(req: LoginRequest, request: Request, response: Response):
    """
    用户登录接口（支持用户名或邮箱登录）
    """
    cfg = load_config()
    sys_cfg = cfg.get("system", {})
    
    # 协议勾选
    if not req.agreeTerms:
        raise HTTPException(status_code=400, detail="请阅读并勾选同意《用户协议》和《隐私政策》")
    
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
    if len(req.newPassword) < 8 or len(req.newPassword) > 20:
        raise HTTPException(status_code=400, detail="新密码长度必须在 8 到 20 个字符之间")
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
@router.get("/admin.html")
@router.get("/admin/")
async def route_secure_admin_portal(request: Request):
    """
    管理控制台页面入口：
    向用户交付 admin.html。前端自带管理员身份校验与独立超级管理员登录门户；
    所有敏感操作接口均在服务端通过 Depends(get_current_admin) 进行绝对权限拦截。
    """
    admin_file = os.path.join(BASE_DIR, "templates", "admin.html")
    if not os.path.exists(admin_file):
        admin_file = os.path.join(STATIC_DIR, "admin.html")
    if not os.path.exists(admin_file):
        raise HTTPException(status_code=404, detail="Admin template not found")

    return FileResponse(admin_file, media_type="text/html")
