"""
Gallery Router for RunComfyui
Handles user gallery listings, filtering, and user soft deletion (userHidden).
"""
import os
import time
from typing import Optional, Dict, Any, List

from fastapi import APIRouter, Depends, HTTPException
from core.auth import get_current_user_optional
from core.database import db_load_tasks, db_get_task, update_task_record

router = APIRouter(tags=["Gallery"])


@router.get("/api/gallery")
def get_gallery(current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)):
    """获取专属成果画廊（包含完整元信息，严格过滤用户已删除和管理员已下架的作品）"""
    if current_user:
        user_id_str = str(current_user["id"])
        tasks = db_load_tasks(user_id=user_id_str, limit=500)
    else:
        all_tasks = db_load_tasks(limit=100)
        tasks = [t for t in all_tasks if not t.get("userId")]

    items = []
    seen = set()
    for t in tasks:
        created_at = t.get("createdAt", int(time.time()))
        for out in t.get("outputs", []):
            if out.get("userHidden") or out.get("isTakedown"):
                continue
            url = out.get("url") or out.get("remoteUrl")
            if not url or url.startswith("data:"):
                continue
            fname = out.get("filename") or os.path.basename(url.split("?")[0])
            fp = f"{t.get('taskId')}_{fname}"
            if fp in seen:
                continue
            seen.add(fp)
            ext = os.path.splitext(fname)[1].lower()
            file_type = out.get("fileType")
            if not file_type or file_type == "image":
                if ext in {".mp3", ".wav", ".flac", ".ogg", ".m4a", ".aac", ".wma", ".opus"}:
                    file_type = "audio"
                elif ext in {".mp4", ".webm", ".mov"}:
                    file_type = "video"
                else:
                    file_type = "image"
            items.append({
                "filename": fname,
                "url": url,
                "remoteUrl": out.get("remoteUrl", url),
                "size": out.get("size", 0),
                "createdAt": created_at,
                "fileType": file_type,
                "taskId": t.get("taskId"),
                "username": t.get("username", ""),
                "positivePrompt": t.get("positivePrompt", ""),
                "workflowName": t.get("workflowName", "") or t.get("workflowId", ""),
                "workflowId": t.get("workflowId", ""),
                "duration": t.get("duration", 0),
                "cost": t.get("cost", 0),
                "consumeCoins": t.get("consumeCoins", "0")
            })
    items.sort(key=lambda x: x["createdAt"], reverse=True)
    return items


@router.delete("/api/gallery/{task_id}/{filename}")
@router.delete("/api/gallery/{filename}")
def delete_gallery_file(
    filename: str, 
    task_id: Optional[str] = None, 
    current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    """用户软删除成果：支持传入 taskId 精确定位，彻底对用户自身隐藏，管理员后台依然完整保留可见"""
    safe_name = os.path.basename(filename)
    user_id = str(current_user["id"]) if current_user else ""
    is_admin = bool(current_user and current_user.get("role") == "admin")
    
    # 优先基于精确 taskId 处理
    if task_id:
        t = db_get_task(str(task_id).strip())
        if t:
            task_owner = str(t.get("userId") or "")
            if task_owner and user_id and not is_admin and task_owner != user_id:
                raise HTTPException(status_code=403, detail="无权操作其他用户的成果文件")
            outs = t.get("outputs", [])
            modified = False
            new_outs = []
            for o in outs:
                fname = o.get("filename") or os.path.basename(o.get("url", "").split("?")[0])
                remote_fname = os.path.basename(o.get("remoteUrl", "").split("?")[0])
                if safe_name in (fname, remote_fname) or (o.get("url") and safe_name in o.get("url")) or (o.get("remoteUrl") and safe_name in o.get("remoteUrl")):
                    o_copy = dict(o)
                    o_copy["userHidden"] = True
                    o_copy["userHiddenAt"] = int(time.time())
                    new_outs.append(o_copy)
                    modified = True
                else:
                    new_outs.append(o)
            if modified:
                update_task_record(str(t.get("taskId")), {
                    "outputs": new_outs,
                    "updatedAt": int(time.time())
                })
                return {"status": "ok", "message": "该成果已成功从您的画廊中移除（前台已隐藏）"}
    
    # 兜底：遍历用户任务进行文件指纹匹配
    user_tasks = db_load_tasks(limit=500) if is_admin else (db_load_tasks(user_id=user_id, limit=500) if user_id else db_load_tasks(limit=100))
    for t in user_tasks:
        outs = t.get("outputs", [])
        modified = False
        new_outs = []
        for o in outs:
            fname = o.get("filename") or os.path.basename(o.get("url", "").split("?")[0])
            remote_fname = os.path.basename(o.get("remoteUrl", "").split("?")[0])
            if safe_name in (fname, remote_fname) or (o.get("url") and safe_name in o.get("url")) or (o.get("remoteUrl") and safe_name in o.get("remoteUrl")):
                task_owner = str(t.get("userId") or "")
                if user_id and not is_admin and task_owner and task_owner != user_id:
                    continue
                o_copy = dict(o)
                o_copy["userHidden"] = True
                o_copy["userHiddenAt"] = int(time.time())
                new_outs.append(o_copy)
                modified = True
            else:
                new_outs.append(o)
        if modified:
            update_task_record(str(t.get("taskId")), {
                "outputs": new_outs,
                "updatedAt": int(time.time())
            })
            
    return {"status": "ok", "message": "该成果已成功从您的画廊中移除（前台已隐藏）"}
