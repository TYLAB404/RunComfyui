"""
Gallery Router for RunComfyui
Handles user gallery listings, filtering, and user soft deletion (userHidden).
"""
import os
import time
from typing import Optional, Dict, Any, List

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse, FileResponse, RedirectResponse
import urllib.parse
import aiohttp
from core.config import BASE_DIR, OUTPUTS_DIR, load_config
from core.auth import get_current_user_optional
from core.database import db_load_tasks, db_get_task, update_task_record
from services.imgbed_service import infer_media_type

router = APIRouter(tags=["Gallery"])


@router.get("/api/gallery")
def get_gallery(
    page: Optional[int] = None,
    page_size: Optional[int] = None,
    current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    """获取专属画廊成果，限制仅展示最新 30 条任务的成果（严格保持官方原始直链，支持服务端分页）"""
    if current_user:
        user_id_str = str(current_user["id"])
        tasks = db_load_tasks(user_id=user_id_str, limit=500)
    else:
        all_tasks = db_load_tasks(limit=200)
        tasks = [t for t in all_tasks if not t.get("userId")]

    items = []
    seen = set()
    MAX_TASKS = 30
    tasks_with_outputs_count = 0

    for t in tasks:
        created_at = t.get("createdAt", int(time.time()))
        task_id = t.get("taskId")
        valid_outs = []
        for out in t.get("outputs", []):
            if out.get("userHidden") or out.get("isTakedown"):
                continue
            # 用户端画廊严格保持官方原始直链
            url = out.get("remoteUrl") or out.get("url")
            if not url or url.startswith("data:"):
                continue
            fname = out.get("filename") or os.path.basename(url.split("?")[0])
            fp = f"{task_id}_{fname}"
            if fp in seen:
                continue
            seen.add(fp)
            valid_outs.append((out, fname, url))

        # 仅当任务确实包含有效成果时，计入 30 条任务配额
        if not valid_outs:
            continue

        tasks_with_outputs_count += 1
        if tasks_with_outputs_count > MAX_TASKS:
            break

        batch_total = len(valid_outs)
        for idx, (out, fname, url) in enumerate(valid_outs):
            file_type = out.get("fileType")
            if not file_type or file_type == "image":
                file_type = infer_media_type(fname, "image")
            items.append({
                "filename": fname,
                "url": url,
                "remoteUrl": out.get("remoteUrl", url),
                "size": out.get("size", 0),
                "createdAt": created_at,
                "fileType": file_type,
                "taskId": task_id,
                "batchIndex": idx + 1,
                "batchTotal": batch_total,
                "batchLabel": f"{idx + 1}/{batch_total}" if batch_total > 1 else "",
                "username": t.get("username", ""),
                "positivePrompt": t.get("positivePrompt", ""),
                "workflowName": t.get("workflowName", "") or t.get("workflowId", ""),
                "workflowId": t.get("workflowId", ""),
                "duration": t.get("duration", 0),
                "cost": int(t.get("cost", 0) or 0),
                "consumeCoins": t.get("consumeCoins", "0")
            })

    items.sort(key=lambda x: x["createdAt"], reverse=True)

    # 若指定了分页参数，按分页结构返回
    if page is not None and page_size is not None and page_size > 0:
        import math
        p = max(1, int(page))
        ps = max(1, min(100, int(page_size)))
        total_items = len(items)
        total_pages = max(1, math.ceil(total_items / ps))
        start = (p - 1) * ps
        end = start + ps
        return {
            "items": items[start:end],
            "total": total_items,
            "page": p,
            "pageSize": ps,
            "totalPages": total_pages,
            "taskCount": tasks_with_outputs_count
        }

    return items


@router.delete("/api/gallery/{task_id}/{filename}")
@router.delete("/api/gallery/{filename}")
def delete_gallery_file(
    filename: str, 
    task_id: Optional[str] = None, 
    current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    """用户软删除成果：支持传入 taskId 精确定位，彻底对用户自身隐藏，管理员后台依然完整保留可见"""
    if not current_user:
        raise HTTPException(status_code=401, detail="未授权操作：请先登录后再管理画廊成果")
    
    safe_name = os.path.basename(filename)
    user_id = str(current_user["id"])
    is_admin = bool(current_user.get("role") == "admin")
    
    # 优先基于精确 taskId 处理
    if task_id:
        t = db_get_task(str(task_id).strip())
        if t:
            task_owner = str(t.get("userId") or "")
            if not is_admin and task_owner and task_owner != user_id:
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
    found_any = False
    for t in user_tasks:
        outs = t.get("outputs", [])
        modified = False
        new_outs = []
        for o in outs:
            fname = o.get("filename") or os.path.basename(o.get("url", "").split("?")[0])
            remote_fname = os.path.basename(o.get("remoteUrl", "").split("?")[0])
            if safe_name in (fname, remote_fname) or (o.get("url") and safe_name in o.get("url")) or (o.get("remoteUrl") and safe_name in o.get("remoteUrl")):
                task_owner = str(t.get("userId") or "")
                if not is_admin and task_owner and task_owner != user_id:
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
            found_any = True
            
    if not found_any:
        raise HTTPException(status_code=404, detail="未找到匹配的成果或无权操作")

    return {"status": "ok", "message": "该成果已成功从您的画廊中移除（前台已隐藏）"}


@router.get("/api/gallery/download")
async def download_gallery_media(
    url: str, 
    filename: Optional[str] = None,
    current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    """
    通用媒体文件直链下载网关 (严格加固)：
    1. 杜绝路径穿越 (Path Traversal)：本地文件严格限制在 outputs 目录内并做 realpath 隔离；
    2. 杜绝开放重定向 (Open Redirect)：远端直链严格限制在 RunningHub/官方图床白名单域名；
    3. 302 极速跳转，零消耗 VPS 流量与带宽。
    """
    if not url:
        raise HTTPException(status_code=400, detail="缺少下载地址")
    
    clean_url = urllib.parse.unquote(url).strip()
    safe_filename = filename or os.path.basename(clean_url.split("?")[0]) or "output.png"
    safe_filename = os.path.basename(safe_filename)

    # 1. 本地生成成果 (严格防路径穿越)
    if clean_url.startswith("/outputs/") or clean_url.startswith("outputs/"):
        rel_path = clean_url.lstrip("/")
        outputs_root = os.path.realpath(OUTPUTS_DIR)
        full_path = os.path.realpath(os.path.join(BASE_DIR, rel_path))
        
        # 严格校验：禁止使用 .. 逃逸出 outputs_root 目录
        if not (full_path == outputs_root or full_path.startswith(outputs_root + os.sep)):
            raise HTTPException(status_code=403, detail="非法访问路径：安全策略已拒绝跳级跨目录读取")
        if not os.path.isfile(full_path):
            raise HTTPException(status_code=404, detail="本地成果文件不存在或已被归档")

        encoded_fn = urllib.parse.quote(safe_filename)
        return FileResponse(
            path=full_path,
            filename=safe_filename,
            headers={"Content-Disposition": f"attachment; filename*=UTF-8''{encoded_fn}"}
        )

    # 2. 远端 CDN / 官方直链 (严格防开放重定向钓鱼)
    if clean_url.startswith("http://") or clean_url.startswith("https://"):
        parsed = urllib.parse.urlparse(clean_url)
        host = (parsed.netloc or "").split(":")[0].lower()
        allowed_domain_suffixes = (
            "runninghub.cn",
            "runninghub.ai",
            "xiaoyaoyou.com"
        )
        
        is_trusted = any(host == d or host.endswith("." + d) for d in allowed_domain_suffixes)
        if not is_trusted:
            try:
                cfg = load_config()
                ib_url = cfg.get("system", {}).get("imgbed", {}).get("publicBaseUrl", "")
                if ib_url:
                    ib_host = urllib.parse.urlparse(ib_url).netloc.split(":")[0].lower()
                    if host == ib_host or (ib_host and host.endswith("." + ib_host)):
                        is_trusted = True
            except Exception:
                pass

        if not is_trusted:
            raise HTTPException(status_code=400, detail="安全拦截：仅允许跳转至官方及受信任的媒体存储 CDN")

        return RedirectResponse(url=clean_url, status_code=302)

    raise HTTPException(status_code=400, detail="不支持的下载地址协议")
