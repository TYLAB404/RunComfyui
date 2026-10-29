"""
Admin Router for RunComfyui
Provides full control over users, system configuration, announcements,
task audits & force cancellations, gallery takedowns, Cloudflare image bed,
RunningHub Key pool health, and SMTP alert configuration.
"""
import io
import os
import time
import asyncio
from typing import Optional, Dict, Any, List
import requests
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, Request, Response

from core.auth import (
    get_current_admin,
    notify_user,
    sanitize_user,
    load_users,
    get_user_by_id,
    update_user_fields,
    set_user_password,
    delete_user_by_id,
)
from core.config import (
    load_config,
    save_config,
    get_active_api_key,
    get_imgbed_config,
    get_system_config_safe,
)
from core.database import (
    load_tasks,
    db_refund_user_points,
    db_get_task,
    db_update_task,
    db_delete_task,
    db_delete_tasks_batch,
    db_clean_tasks_by_status,
    db_get_user_task_counts,
    db_load_tasks,
    update_task_record,
    db_get_announcements,
    db_save_announcement,
    db_update_announcement,
    db_delete_announcement,
    db_get_admin_overview_stats,
    db_record_points_ledger,
    db_atomic_cancel_and_refund,
)
from core.security import decrypt_key, encrypt_key, mask_key
from core.http_client import http_session
from services.key_pool import KEY_POOL_MANAGER
from services.email_service import send_admin_alert_email
from services.imgbed_service import (
    sync_task_outputs_to_imgbed,
    sync_single_file_to_imgbed,
    _sanitize_folder_name,
    infer_media_type,
    get_sync_progress,
    start_pending_sync,
    start_all_history_sync,
)
from services.runninghub import RUNNINGHUB_API_URL, ACTIVE_TASK_PREVIEWS, execute_task_cancellation

router = APIRouter(tags=["Admin"])


# ==================== 请求模型 ====================

class AdminUpdateUserRequest(BaseModel):
    role: Optional[str] = None
    points: Optional[int] = None
    isActive: Optional[bool] = None
    newPassword: Optional[str] = None


class AdminResetPasswordRequest(BaseModel):
    newPassword: str


class AdminSystemConfigRequest(BaseModel):
    siteTitle: Optional[str] = None
    turnstileEnabled: Optional[bool] = None
    turnstileSiteKey: Optional[str] = None
    turnstileSecretKey: Optional[str] = None
    allowRegistration: Optional[bool] = None
    defaultUserPoints: Optional[int] = None
    requireLoginToGenerate: Optional[bool] = None
    hideAuxiliaryAudioChain: Optional[bool] = None
    imgbedEnabled: Optional[bool] = None
    imgbedUploadUrl: Optional[str] = None
    imgbedAuthHeader: Optional[str] = None
    imgbedRootFolder: Optional[str] = None
    imgbedIsolateByUser: Optional[bool] = None
    imgbedConcurrency: Optional[int] = None


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


class SmtpConfigRequest(BaseModel):
    enabled: bool = False
    host: str = ""
    port: int = 465
    user: str = ""
    password: Optional[str] = None
    adminEmail: str = ""
    fromEmail: Optional[str] = ""


# ==================== 1. 概览大盘 ====================

@router.get("/api/admin/overview")
def admin_overview(_: Dict[str, Any] = Depends(get_current_admin)):
    """管理员系统全量概览指标（利用高性能 SQL 聚合替代内存循环）"""
    stats = db_get_admin_overview_stats()
    cfg = load_config()
    sys_cfg = cfg.get("system", {})
    now = time.time()

    secret_enc = sys_cfg.get("turnstileSecretKeyEncrypted", "")
    secret_raw = decrypt_key(secret_enc) if secret_enc else ""

    return {
        "totalUsers": stats["totalUsers"],
        "adminCount": stats["adminCount"],
        "activeUsers": stats["activeUsers"],
        "totalTasks": stats["totalTasks"],
        "todayTasks": stats["todayTasks"],
        "successTasks": stats["successTasks"],
        "failedTasks": stats["failedTasks"],
        "totalCoinsUsed": stats["totalCoinsUsed"],
        "turnstileEnabled": bool(sys_cfg.get("turnstileEnabled")),
        "turnstileConfigured": bool(secret_raw and sys_cfg.get("turnstileSiteKey")),
        "turnstileSiteKey": sys_cfg.get("turnstileSiteKey", ""),
        "activeKeyMasked": mask_key(get_active_api_key(cfg)),
        "serverTime": int(now),
    }


# ==================== 2. 用户管理 ====================

@router.get("/api/admin/users")
def admin_list_users(_: Dict[str, Any] = Depends(get_current_admin)):
    """全量用户列表及其累计任务统计（采用 SQL GROUP BY 索引聚合，避免全量任务反序列化）"""
    users = load_users()
    task_counts = db_get_user_task_counts()

    result = []
    for u in users:
        safe = sanitize_user(u)
        safe["taskCount"] = task_counts.get(str(u["id"]), u.get("taskCount", 0))
        result.append(safe)
    result.sort(key=lambda x: x.get("createdAt", 0), reverse=True)
    return result


@router.put("/api/admin/users/{user_id}")
async def admin_update_user(
    user_id: str,
    req: AdminUpdateUserRequest,
    admin: Dict[str, Any] = Depends(get_current_admin),
):
    """管理员编辑用户信息：角色、算力、启停、密码重置"""
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
    delta_points = 0
    if req.points is not None:
        new_pts = max(0, int(req.points))
        old_pts = int(user.get("points", 0))
        if new_pts != old_pts:
            updates["points"] = new_pts
            points_changed = True
            delta_points = new_pts - old_pts

    is_deactivating = False
    if req.isActive is not None:
        if user_id == admin["id"] and not req.isActive:
            raise HTTPException(status_code=400, detail="不能封禁当前登录的管理员账号")
        if not req.isActive and user.get("isActive", True):
            is_deactivating = True
        updates["isActive"] = bool(req.isActive)

    if updates:
        update_user_fields(user_id, updates)
        if points_changed:
            admin_name = admin.get("username", "系统管理员")
            db_record_points_ledger(
                user_id=user_id,
                delta=delta_points,
                balance_after=new_pts,
                reason=f"管理员 ({admin_name}) 后台手动调整算力点数"
            )

    pwd_changed = False
    if req.newPassword and len(req.newPassword.strip()) >= 6:
        set_user_password(user_id, req.newPassword.strip())
        pwd_changed = True

    fresh = get_user_by_id(user_id)

    # 实时 SSE 下发，秒级踢人与算力同步
    if is_deactivating:
        await notify_user(
            user_id=user_id,
            event_type="KICK_OFF",
            data={"reason": "您的账户已被管理员停用，已强制下线"},
        )
    elif pwd_changed:
        await notify_user(
            user_id=user_id,
            event_type="KICK_OFF",
            data={"reason": "管理员已修改您的密码凭据，请重新登录"},
        )
    elif points_changed and fresh:
        await notify_user(
            user_id=user_id,
            event_type="POINTS_UPDATED",
            data={"points": fresh.get("points", 0), "reason": "管理员在后台更新了您的算力点数"},
        )

    return {"status": "ok", "user": sanitize_user(fresh)}


@router.post("/api/admin/users/{user_id}/reset-password")
async def admin_reset_user_password(
    user_id: str,
    req: AdminResetPasswordRequest,
    admin: Dict[str, Any] = Depends(get_current_admin),
):
    """管理员重置用户登录密码"""
    if len(req.newPassword.strip()) < 6:
        raise HTTPException(status_code=400, detail="新密码不能少于 6 位")
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    set_user_password(user_id, req.newPassword.strip())
    await notify_user(
        user_id=user_id,
        event_type="KICK_OFF",
        data={"reason": "管理员已重置您的登录密码，请使用新密码重新登录"},
    )
    return {"status": "ok"}


@router.delete("/api/admin/users/{user_id}")
async def admin_delete_user(user_id: str, admin: Dict[str, Any] = Depends(get_current_admin)):
    """管理员注销并物理删除用户"""
    if user_id == admin["id"]:
        raise HTTPException(status_code=400, detail="无法删除当前正在登录的管理员账号")

    target = get_user_by_id(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="用户不存在")

    await notify_user(
        user_id=user_id,
        event_type="KICK_OFF",
        data={"reason": "您的账号已被管理员注销，会话已终止"},
    )
    delete_user_by_id(user_id)
    return {"status": "ok", "message": f"用户 {target.get('username')} 已被安全删除"}


# ==================== 3. 系统配置 ====================

@router.get("/api/admin/system")
def admin_get_system_config(_: Dict[str, Any] = Depends(get_current_admin)):
    """获取系统基础配置脱敏版"""
    return get_system_config_safe()


@router.post("/api/admin/system")
@router.put("/api/admin/system")
def admin_update_system_config(
    req: AdminSystemConfigRequest,
    _: Dict[str, Any] = Depends(get_current_admin),
):
    """管理员更新系统配置"""
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


# ==================== 4. 公告与通知 ====================

@router.get("/api/announcements")
def get_public_announcements():
    """面向前台普通用户的活跃公告列表"""
    return db_get_announcements(active_only=True)


@router.get("/api/admin/announcements")
def get_admin_announcements(_: Dict[str, Any] = Depends(get_current_admin)):
    """管理员全量公告列表（包括停用的）"""
    return db_get_announcements(active_only=False)


@router.post("/api/admin/announcements")
def create_admin_announcement(
    req: AnnouncementCreateRequest,
    _: Dict[str, Any] = Depends(get_current_admin),
):
    """管理员发布新公告"""
    if not req.title.strip():
        raise HTTPException(status_code=400, detail="公告标题不能为空")
    if not req.content.strip():
        raise HTTPException(status_code=400, detail="公告内容不能为空")
    return db_save_announcement(
        title=req.title,
        content=req.content,
        tag=req.tag or "官方公告",
        is_active=True if req.isActive is None else bool(req.isActive),
    )


@router.put("/api/admin/announcements/{anno_id}")
def update_admin_announcement(
    anno_id: str,
    req: AnnouncementUpdateRequest,
    _: Dict[str, Any] = Depends(get_current_admin),
):
    """管理员编辑已有公告"""
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


@router.delete("/api/admin/announcements/{anno_id}")
def delete_admin_announcement(anno_id: str, _: Dict[str, Any] = Depends(get_current_admin)):
    """管理员删除公告"""
    db_delete_announcement(anno_id)
    return {"status": "ok"}


# ==================== 5. 任务管理与强制取消 ====================

@router.get("/api/admin/tasks")
def admin_list_all_tasks(
    status: Optional[str] = None,
    user_id: Optional[str] = None,
    username: Optional[str] = None,
    limit: int = 500,
    _: Dict[str, Any] = Depends(get_current_admin),
):
    """管理员全量任务审计视图（支持按用户、状态进行过滤）"""
    return db_load_tasks(user_id=user_id, status=status, is_admin=True, limit=limit, search_user=username)


@router.post("/api/admin/tasks/{task_id}/cancel")
async def admin_force_cancel_task(task_id: str, _: Dict[str, Any] = Depends(get_current_admin)):
    """管理员强制取消全站任意进行中任务，并自动执行退费与通知"""
    task_id_str = str(task_id).strip()
    t = db_get_task(task_id_str)
    if not t:
        raise HTTPException(status_code=404, detail="任务不存在")

    return await execute_task_cancellation(t, is_admin=True)


@router.delete("/api/admin/tasks/{task_id}")
def admin_delete_task(task_id: str, _: Dict[str, Any] = Depends(get_current_admin)):
    """管理员清理/删除单条任务记录"""
    db_delete_task(str(task_id).strip())
    return {"status": "ok", "message": f"任务 {task_id} 记录已清理"}


@router.post("/api/admin/tasks/clean-batch")
def admin_clean_tasks_batch(payload: Dict[str, Any], _: Dict[str, Any] = Depends(get_current_admin)):
    """管理员批量清理特定状态的任务记录（如已取消或失败任务）"""
    status_target = payload.get("status")
    if not status_target:
        raise HTTPException(status_code=400, detail="缺少清理目标状态")
    deleted_count = db_clean_tasks_by_status(status_target)
    return {"status": "ok", "deletedCount": deleted_count, "message": f"已成功清理 {deleted_count} 条状态为 {status_target} 的任务记录"}


# ==================== 6. 全站广播与维护模式 ====================

@router.post("/api/admin/system/broadcast")
def admin_update_broadcast(payload: Dict[str, Any], _: Dict[str, Any] = Depends(get_current_admin)):
    """更新全站实时广播通知"""
    cfg = load_config()
    sys_cfg = cfg.setdefault("system", {})
    broadcast = {
        "enabled": bool(payload.get("enabled", False)),
        "message": str(payload.get("message", "")).strip(),
        "level": str(payload.get("level", "info")),
        "updatedAt": int(time.time()),
    }
    sys_cfg["broadcast"] = broadcast
    save_config(cfg)
    return {"status": "ok", "broadcast": broadcast}


@router.post("/api/admin/system/maintenance")
def admin_update_maintenance(payload: Dict[str, Any], _: Dict[str, Any] = Depends(get_current_admin)):
    """切换全站维护模式开关及通知文案"""
    cfg = load_config()
    sys_cfg = cfg.setdefault("system", {})
    maint = {
        "enabled": bool(payload.get("enabled", False)),
        "message": str(payload.get("message", "系统正在维护中，暂停提交新任务，请稍后访问。")).strip(),
        "updatedAt": int(time.time()),
    }
    sys_cfg["maintenance"] = maint
    save_config(cfg)
    return {"status": "ok", "maintenance": maint}


# ==================== 7. 全站画廊审查与违规下架 ====================

@router.get("/api/admin/gallery")
def admin_get_gallery(
    username: Optional[str] = None,
    file_type: Optional[str] = None,
    storage: Optional[str] = None,
    status: Optional[str] = None,
    _: Dict[str, Any] = Depends(get_current_admin),
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

            ft = out.get("fileType")
            if not ft or ft == "image":
                ft = infer_media_type(fname, "image")
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
                "url": url,
                "remoteUrl": out.get("remoteUrl", url),
                "imgbedUrl": imgbed_url,
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
                "workflowName": t.get("workflowName", ""),
            })
    items.sort(key=lambda x: x["createdAt"], reverse=True)
    return items


@router.delete("/api/admin/gallery/{task_id}/{filename}")
def admin_delete_gallery_record(
    task_id: str,
    filename: str,
    _: Dict[str, Any] = Depends(get_current_admin),
):
    """管理员删除图片记录（从任务输出台账中彻底移除，前后台均不再展示，但不对图床做任何物理删除）"""
    t = db_get_task(str(task_id))
    if not t:
        raise HTTPException(status_code=404, detail="任务不存在")
    safe_name = os.path.basename(filename)
    outs = t.get("outputs", [])
    initial_len = len(outs)

    new_outs = []
    for o in outs:
        fname = o.get("filename") or os.path.basename(o.get("url", "").split("?")[0])
        remote_fname = os.path.basename(o.get("remoteUrl", "").split("?")[0])
        if safe_name in (fname, remote_fname) or (o.get("url") and safe_name in o.get("url")):
            continue
        new_outs.append(o)

    if len(new_outs) != initial_len:
        update_task_record(str(task_id), {
            "outputs": new_outs,
            "updatedAt": int(time.time()),
        })
        return {
            "status": "ok",
            "message": "图片记录已成功删除，前后台均不再展示（自建图床原文件已安全保留，未作任何改动）"
        }
    else:
        return {
            "status": "ok",
            "message": "未找到对应的图片记录，无需删除"
        }


@router.post("/api/admin/gallery/{task_id}/{filename}/takedown")
def admin_takedown_gallery_item(
    task_id: str,
    filename: str,
    _: Dict[str, Any] = Depends(get_current_admin),
):
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
            "updatedAt": int(time.time()),
        })
    return {"status": "ok", "message": "该成果已成功违规下架（对前台用户屏蔽，已归入后台【已违规下架】分类）"}


@router.post("/api/admin/gallery/{task_id}/{filename}/restore")
def admin_restore_gallery_item(
    task_id: str,
    filename: str,
    _: Dict[str, Any] = Depends(get_current_admin),
):
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
            "updatedAt": int(time.time()),
        })
    return {"status": "ok", "message": "该成果已重新上架，恢复正常前台展示"}


# ==================== 8. 图床运行与一键同步 ====================

@router.get("/api/admin/imgbed")
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


@router.post("/api/admin/imgbed/test")
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
            return http_session.post(upload_url, headers=headers, files=files, timeout=15)

        resp = await asyncio.to_thread(_test)
        if resp.status_code == 200:
            return {"status": "ok", "message": "图床接口连通性极佳！已成功通过 Authorization 认证握手并完成隔离文件夹探测。"}
        else:
            return {"status": "error", "message": f"图床响应异常 (HTTP {resp.status_code}): {resp.text[:200]}"}
    except Exception as e:
        return {"status": "error", "message": f"连接异常: {str(e)}"}


@router.get("/api/admin/imgbed/sync_progress")
def admin_get_sync_progress(_: Dict[str, Any] = Depends(get_current_admin)):
    """获取未备份文件同步归档的实时进度"""
    return get_sync_progress()

@router.post("/api/admin/imgbed/sync_pending")
async def admin_sync_pending_to_imgbed(_: Dict[str, Any] = Depends(get_current_admin)):
    """一键备份全站所有未备份的文件到图床（带实时进度追踪）"""
    cur_progress = get_sync_progress()
    if cur_progress.get("running"):
        return {"status": "busy", "message": "图床备份任务正在后台平稳转存中，请勿重复触发", "progress": cur_progress}

    cfg = load_config()
    imgbed_cfg = get_imgbed_config(cfg)
    if not imgbed_cfg.get("enabled"):
        raise HTTPException(status_code=400, detail="自建图床功能未启用，请先在图床配置中开启")
    if not imgbed_cfg.get("rawAuthHeader"):
        raise HTTPException(status_code=400, detail="未配置图床 Authorization 密钥")

    tasks = db_load_tasks(is_admin=True, limit=1000)
    pending_tasks = []
    total_pending_files = 0
    for t in tasks:
        outs = t.get("outputs", [])
        pending_outs = [o for o in outs if not o.get("imgbedUrl") and not o.get("sourceExpired") and (o.get("remoteUrl") or o.get("url"))]
        if pending_outs:
            pending_tasks.append((str(t.get("taskId")), len(pending_outs)))
            total_pending_files += len(pending_outs)

    if total_pending_files == 0:
        return {"status": "ok", "message": "当前没有待备份的文件（所有有效成果已全部备份归档）", "total": 0}

    return start_pending_sync(pending_tasks, total_pending_files)

@router.post("/api/admin/imgbed/sync_item")
async def admin_sync_single_item(payload: Dict[str, Any], _: Dict[str, Any] = Depends(get_current_admin)):
    """管理员单独将某个未备份作品手动转存至图床"""
    task_id = payload.get("taskId")
    filename = payload.get("filename")
    if not task_id:
        raise HTTPException(status_code=400, detail="缺少 taskId")
    
    t = db_get_task(str(task_id))
    if not t:
        raise HTTPException(status_code=404, detail="任务不存在")
    
    cfg = load_config()
    imgbed_cfg = get_imgbed_config(cfg)
    if not imgbed_cfg.get("enabled"):
        raise HTTPException(status_code=400, detail="自建图床功能未启用")
    if not imgbed_cfg.get("rawAuthHeader"):
        raise HTTPException(status_code=400, detail="尚未配置图床 Authorization 密钥")

    username = t.get("username") or "guest"
    outputs = t.get("outputs", [])
    target_idx = None
    target_out = None
    for idx, o in enumerate(outputs):
        if filename and o.get("filename") == filename:
            target_idx = idx
            target_out = o
            break
        elif not filename and not o.get("imgbedUrl"):
            target_idx = idx
            target_out = o
            break
    
    if target_out is None:
        raise HTTPException(status_code=404, detail="未找到对应的输出作品")

    cur_url = target_out.get("remoteUrl") or target_out.get("url") or ""
    if not cur_url:
        raise HTTPException(status_code=400, detail="该作品缺少源端下载链接")

    fname = target_out.get("filename") or filename or "output.png"
    perm_url = await sync_single_file_to_imgbed(cur_url, fname, username, imgbed_cfg)
    if perm_url == "EXPIRED":
        target_out["sourceExpired"] = True
        target_out["imgbedError"] = "原厂源端文件已失效/丢失 (404)"
        db_update_task(str(task_id), {"outputs": outputs, "updatedAt": int(time.time())})
        return {"status": "expired", "message": "源端文件已在云端过期失效，无法备份"}
    elif perm_url:
        root_folder = imgbed_cfg.get("rootFolder", "RunComfyui").strip() or "RunComfyui"
        user_folder = _sanitize_folder_name(username) if imgbed_cfg.get("isolateByUser", True) else ""
        folder_name = f"{root_folder}/{user_folder}" if user_folder else root_folder
        target_out["imgbedUrl"] = perm_url
        target_out["storage"] = "imgbed"
        target_out["sourceExpired"] = False
        target_out["imgbedFolder"] = folder_name
        target_out["imgbedSyncedAt"] = int(time.time())
        db_update_task(str(task_id), {"outputs": outputs, "updatedAt": int(time.time())})
        return {"status": "ok", "message": "该作品已成功备份至图床", "imgbedUrl": perm_url}
    else:
        raise HTTPException(status_code=500, detail="转存失败，图床接口响应异常")

@router.post("/api/admin/imgbed/sync_all")
async def admin_sync_all_to_imgbed(_: Dict[str, Any] = Depends(get_current_admin)):
    """管理员一键将历史所有未备份的成果平滑转存至图床（按所属用户文件夹隔离）"""
    return start_all_history_sync()


# ==================== 9. Key 池管理与巡检 ====================

@router.get("/api/admin/key-pool/status")
async def admin_get_key_pool_status(_: Dict[str, Any] = Depends(get_current_admin)):
    """管理员实时查看 RunningHub Key 并发轮询池运行状态"""
    stats = KEY_POOL_MANAGER.get_queue_stats()
    items = KEY_POOL_MANAGER.get_pool_status()
    return {
        "status": "ok",
        "stats": stats,
        "keys": items,
    }


@router.post("/api/admin/key-pool/{key_id}/reset")
async def admin_reset_key_in_pool(key_id: str, _: Dict[str, Any] = Depends(get_current_admin)):
    """管理员紧急一键释放被占用的 Key"""
    await KEY_POOL_MANAGER.reset_key(key_id)
    return {"status": "ok", "message": f"Key {key_id} 运行状态已强制重置为空闲"}


@router.post("/api/admin/key-pool/inspect")
async def admin_inspect_all_keys(_: Dict[str, Any] = Depends(get_current_admin)):
    """管理员手动触发一键全池巡检"""
    results = await KEY_POOL_MANAGER.inspect_all_keys()
    healthy_cnt = sum(1 for r in results if r["isValid"])
    banned_cnt = len(results) - healthy_cnt
    return {
        "status": "ok",
        "healthyCount": healthy_cnt,
        "bannedCount": banned_cnt,
        "results": results,
    }


@router.post("/api/admin/key-pool/{key_id}/resume")
async def admin_resume_key_in_pool(key_id: str, _: Dict[str, Any] = Depends(get_current_admin)):
    """管理员一键解除熔断隔离，恢复 Key 为健康可用状态"""
    await KEY_POOL_MANAGER.mark_key_healthy(key_id)
    return {"status": "ok", "message": f"Key {key_id} 已解除熔断，恢复加入调度池"}


# ==================== 10. SMTP 告警设置 ====================

@router.get("/api/admin/system/smtp")
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
        "fromEmail": smtp_cfg.get("fromEmail", ""),
        "hasPassword": bool(smtp_cfg.get("passwordEncrypted")),
        "adminEmail": smtp_cfg.get("adminEmail", ""),
    }


@router.post("/api/admin/system/smtp")
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
    smtp_cfg["fromEmail"] = (req.fromEmail or "").strip()
    smtp_cfg["adminEmail"] = req.adminEmail.strip()

    if req.password is not None and req.password.strip():
        smtp_cfg["passwordEncrypted"] = encrypt_key(req.password.strip())

    cfg["system"]["smtp"] = smtp_cfg
    save_config(cfg)
    return {"status": "ok", "message": "SMTP 告警邮箱设置已成功保存"}


@router.post("/api/admin/system/smtp/test")
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
    ok, msg = await asyncio.to_thread(send_admin_alert_email, "【测试邮件】RunComfyUI 运维告警通道连接测试", html)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "ok", "message": "测试邮件已成功发送至管理员接收邮箱，请检查收件箱或垃圾箱"}
