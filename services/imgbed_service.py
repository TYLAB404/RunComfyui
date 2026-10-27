import os
import io
import time
import asyncio
import urllib.parse
from typing import Dict, Any, Optional, List
from core.config import load_config, get_imgbed_config
from core.database import db_get_task, db_load_tasks, db_update_task
from core.http_client import HTTP_SESSION

IMGBED_SEMAPHORE = asyncio.Semaphore(4)
SYNC_ALL_RUNNING = False
SYNC_STATUS: Dict[str, Any] = {
    "running": False,
    "total": 0,
    "processed": 0,
    "synced": 0,
    "failed": 0,
    "message": ""
}

def infer_media_type(filename: str, default_type: str = "image") -> str:
    """根据文件名后缀统一推断媒体类型 (image / video / audio)"""
    fname_lower = str(filename or "").lower()
    if any(fname_lower.endswith(ext) for ext in (".mp3", ".wav", ".ogg", ".flac", ".m4a", ".aac")):
        return "audio"
    if any(fname_lower.endswith(ext) for ext in (".mp4", ".webm", ".mov", ".gif")):
        return "video"
    if any(fname_lower.endswith(ext) for ext in (".png", ".jpg", ".jpeg", ".webp", ".bmp")):
        return "image"
    return default_type or "image"

def _sanitize_folder_name(name: str) -> str:
    cleaned = "".join(c for c in str(name) if c.isalnum() or c in ("-", "_")).strip()
    return cleaned or "default"

def get_normalized_imgbed_url(raw_url: str) -> str:
    if not raw_url:
        return ""
    u = raw_url.strip()
    if not u.startswith("http://") and not u.startswith("https://"):
        u = "https://" + u.lstrip("/")
    return u.rstrip("/")

async def sync_single_file_to_imgbed(
    file_url: str, 
    default_filename: str, 
    username: str, 
    imgbed_cfg: Dict[str, Any]
) -> Optional[str]:
    if not imgbed_cfg.get("enabled"):
        return None
    raw_auth = imgbed_cfg.get("rawAuthHeader")
    if not raw_auth:
        return None

    upload_base = imgbed_cfg.get("uploadUrl", "https://imgbed.2364498.xyz/upload").strip()
    root_folder = imgbed_cfg.get("rootFolder", "RunComfyui").strip() or "RunComfyui"
    
    if imgbed_cfg.get("isolateByUser", True):
        user_folder = _sanitize_folder_name(username)
        target_folder = f"{root_folder}/{user_folder}"
    else:
        target_folder = root_folder

    sep = "&" if "?" in upload_base else "?"
    upload_url = f"{upload_base}{sep}uploadFolder={urllib.parse.quote(target_folder)}"

    file_bytes = None
    content_type = None

    if file_url.startswith("/") or ("\\" in file_url and not file_url.startswith("http")):
        clean_path = file_url.lstrip("/").replace("/", os.sep)
        if os.path.exists(clean_path):
            try:
                with open(clean_path, "rb") as fp:
                    file_bytes = fp.read()
            except Exception as e:
                print(f"[ImgBed Warning] Local read failed for {file_url}: {e}")
                return "EXPIRED"
        else:
            return "EXPIRED"
    elif file_url.startswith("http://") or file_url.startswith("https://"):
        try:
            resp = await asyncio.to_thread(HTTP_SESSION.get, file_url, timeout=30)
            if resp.status_code == 200:
                file_bytes = resp.content
                content_type = resp.headers.get("Content-Type") or "application/octet-stream"
            elif resp.status_code in (404, 403, 410):
                print(f"[ImgBed Notice] Remote source missing/expired ({resp.status_code}) at {file_url}")
                return "EXPIRED"
            else:
                return None
        except Exception as e:
            print(f"[ImgBed Warning] Stream fetch failed from {file_url}: {e}")
            return None
    else:
        return "EXPIRED"

    if not file_bytes:
        return None

    fname = default_filename or os.path.basename(file_url.split("?")[0]) or "output.png"
    if not content_type or content_type == "application/octet-stream":
        ext = os.path.splitext(fname)[1].lower()
        if ext in [".png", ".jpg", ".jpeg", ".webp"]:
            content_type = f"image/{ext.lstrip('.')}" if ext != ".jpg" else "image/jpeg"
        elif ext in [".mp4", ".webm"]:
            content_type = f"video/{ext.lstrip('.')}"
        elif ext in [".mp3", ".wav", ".ogg", ".flac", ".m4a"]:
            content_type = f"audio/{ext.lstrip('.')}"

    headers = {"Authorization": raw_auth}

    async with IMGBED_SEMAPHORE:
        for attempt in range(2):
            try:
                def _do_upload():
                    files = {"file": (fname, io.BytesIO(file_bytes), content_type)}
                    return HTTP_SESSION.post(upload_url, headers=headers, files=files, timeout=30)
                
                up_resp = await asyncio.to_thread(_do_upload)
                if up_resp.status_code == 200:
                    data = up_resp.json()
                    src = None
                    if isinstance(data, list) and len(data) > 0:
                        src = data[0].get("src")
                    elif isinstance(data, dict):
                        src = data.get("src") or data.get("url")
                    
                    if src:
                        if src.startswith("http://") or src.startswith("https://"):
                            return src
                        parsed_base = urllib.parse.urlparse(upload_base)
                        domain = f"{parsed_base.scheme}://{parsed_base.netloc}"
                        clean_src = "/" + src.lstrip("/")
                        return f"{domain}{clean_src}"
            except Exception as e:
                print(f"[ImgBed Warning] Upload attempt {attempt+1} error: {e}")
            await asyncio.sleep(1.0)
            
    return None

async def sync_task_outputs_to_imgbed(task_id: str):
    """
    后台任务：在任务生成成功后，平滑将各个成果流式备份到用户隔离图床文件夹。
    用户的任务展示与下载直链必须严格保持为 RunningHub 原始链接 (url/remoteUrl)，
    图床链接仅作为管理员数据归档备份存储在 imgbedUrl 中！
    """
    try:
        t = db_get_task(str(task_id))
        if not t:
            return
        outputs = t.get("outputs", [])
        if not outputs:
            return
        
        cfg = load_config()
        imgbed_cfg = get_imgbed_config(cfg)
        if not imgbed_cfg.get("enabled"):
            return
            
        username = t.get("username") or "guest"
        root_folder = imgbed_cfg.get("rootFolder", "RunComfyui").strip() or "RunComfyui"
        if imgbed_cfg.get("isolateByUser", True):
            folder_name = f"{root_folder}/{_sanitize_folder_name(username)}"
        else:
            folder_name = root_folder
        updated = False
        new_outputs = []
        
        for out in outputs:
            if out.get("imgbedUrl"):
                new_outputs.append(out)
                continue

            if out.get("sourceExpired"):
                new_outputs.append(out)
                continue
            
            cur_url = out.get("remoteUrl") or out.get("url") or ""
            if not cur_url:
                new_outputs.append(out)
                continue
                
            fname = out.get("filename") or os.path.basename(cur_url.split("?")[0])
            perm_url = await sync_single_file_to_imgbed(cur_url, fname, username, imgbed_cfg)
            if perm_url == "EXPIRED":
                out_copy = dict(out)
                out_copy["sourceExpired"] = True
                out_copy["imgbedError"] = "原厂源端文件已失效/丢失 (404)"
                new_outputs.append(out_copy)
                updated = True
            elif perm_url:
                out_copy = dict(out)
                out_copy["remoteUrl"] = cur_url
                out_copy["imgbedUrl"] = perm_url
                out_copy["storage"] = "imgbed"
                out_copy["sourceExpired"] = False
                out_copy["imgbedFolder"] = folder_name
                out_copy["imgbedSyncedAt"] = int(time.time())
                new_outputs.append(out_copy)
                updated = True
            else:
                new_outputs.append(out)

        if updated:
            db_update_task(str(task_id), {"outputs": new_outputs, "updatedAt": int(time.time())})
    except Exception as e:
        print(f"[ImgBed Task Sync Error] {e}")

def get_sync_progress() -> Dict[str, Any]:
    """获取当前后台图床批量备份进度快照"""
    return SYNC_STATUS

async def _run_batch_pending(pending_tasks: list):
    global SYNC_ALL_RUNNING, SYNC_STATUS
    SYNC_ALL_RUNNING = True
    try:
        for tid, count in pending_tasks:
            before_t = db_get_task(tid)
            before_synced = sum(1 for o in (before_t.get("outputs") or []) if o.get("imgbedUrl"))
            await sync_task_outputs_to_imgbed(tid)
            after_t = db_get_task(tid)
            after_synced = sum(1 for o in (after_t.get("outputs") or []) if o.get("imgbedUrl"))
            newly_synced = after_synced - before_synced
            SYNC_STATUS["processed"] += count
            SYNC_STATUS["synced"] += newly_synced
            SYNC_STATUS["failed"] += (count - newly_synced)
            SYNC_STATUS["message"] = f"已备份 {SYNC_STATUS['synced']}/{SYNC_STATUS['total']} 个成果..."
            await asyncio.sleep(0.3)
        SYNC_STATUS["message"] = f"备份完成！共成功转存 {SYNC_STATUS['synced']} 个成果"
    except Exception as e:
        SYNC_STATUS["message"] = f"转存中断: {str(e)}"
    finally:
        SYNC_ALL_RUNNING = False
        SYNC_STATUS["running"] = False

def start_pending_sync(pending_tasks: list, total_pending_files: int) -> Dict[str, Any]:
    """启动待备份文件批量转存任务"""
    global SYNC_ALL_RUNNING, SYNC_STATUS
    if SYNC_ALL_RUNNING:
        return {"status": "busy", "message": "图床备份任务正在后台平稳转存中，请勿重复触发", "progress": SYNC_STATUS}
    SYNC_STATUS = {
        "running": True,
        "total": total_pending_files,
        "processed": 0,
        "synced": 0,
        "failed": 0,
        "message": f"正在平稳转存共 {total_pending_files} 个未备份成果..."
    }
    asyncio.create_task(_run_batch_pending(pending_tasks))
    return {
        "status": "ok",
        "message": f"已启动 {total_pending_files} 个未备份文件的图床归档任务",
        "total": total_pending_files
    }

async def run_sync_all_history():
    global SYNC_ALL_RUNNING
    SYNC_ALL_RUNNING = True
    try:
        tasks = db_load_tasks(is_admin=True, limit=500)
        for t in tasks:
            tid = str(t.get("taskId"))
            outs = t.get("outputs", [])
            needs_sync = any(not o.get("imgbedUrl") and not o.get("sourceExpired") for o in outs)
            if needs_sync:
                await sync_task_outputs_to_imgbed(tid)
                await asyncio.sleep(0.3)
    except Exception as e:
        print(f"[ImgBed Batch Sync Error] {e}")
    finally:
        SYNC_ALL_RUNNING = False

def start_all_history_sync() -> Dict[str, Any]:
    """启动全量历史成果平稳转存任务"""
    if SYNC_ALL_RUNNING:
        return {"status": "busy", "message": "全量历史成果正在后台平稳转存中，请勿重复触发"}
    asyncio.create_task(run_sync_all_history())
    return {"status": "ok", "message": "全量历史成果图床归档任务已成功推入后台调度队列，请稍后刷新审计概览"}
