import os
import io
import time
import asyncio
import urllib.parse
import aiohttp
import requests
from typing import Dict, Any, Optional, List
from core.config import load_config, get_imgbed_config
from core.database import db_get_task, db_load_tasks, db_update_task

IMGBED_SEMAPHORE = asyncio.Semaphore(4)
SYNC_ALL_RUNNING = False

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
    upload_base = get_normalized_imgbed_url(imgbed_cfg.get("uploadUrl", ""))
    raw_auth = imgbed_cfg.get("rawAuthHeader", "")
    if not upload_base or not raw_auth:
        return None

    user_folder = _sanitize_folder_name(username)
    target_folder = f"RunComfyui/{user_folder}"
    upload_url = f"{upload_base}/upload?folder={urllib.parse.quote(target_folder)}"

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
            async with aiohttp.ClientSession() as session:
                async with session.get(file_url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status == 200:
                        file_bytes = await resp.read()
                        content_type = resp.headers.get("Content-Type") or "application/octet-stream"
                    elif resp.status in (404, 403, 410):
                        print(f"[ImgBed Notice] Remote source missing/expired ({resp.status}) at {file_url}")
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
                    return requests.post(upload_url, headers=headers, files=files, timeout=30)
                
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
                out_copy["imgbedFolder"] = f"RunComfyui/{_sanitize_folder_name(username)}"
                out_copy["imgbedSyncedAt"] = int(time.time())
                new_outputs.append(out_copy)
                updated = True
            else:
                new_outputs.append(out)

        if updated:
            db_update_task(str(task_id), {"outputs": new_outputs, "updatedAt": int(time.time())})
    except Exception as e:
        print(f"[ImgBed Task Sync Error] {e}")

async def run_sync_all_history():
    global SYNC_ALL_RUNNING
    try:
        cfg = load_config()
        imgbed_cfg = get_imgbed_config(cfg)
        if not imgbed_cfg.get("enabled"):
            return
        
        tasks = db_load_tasks(is_admin=True, limit=1000)
        success_tasks = [t for t in tasks if t.get("status") == "SUCCESS"]
        print(f"[ImgBed Batch Sync] Found {len(success_tasks)} success tasks to evaluate...")
        
        for t in success_tasks:
            tid = t.get("taskId")
            if tid:
                await sync_task_outputs_to_imgbed(tid)
                await asyncio.sleep(0.5)
        print("[ImgBed Batch Sync] Batch sync completed successfully!")
    except Exception as e:
        print(f"[ImgBed Batch Sync Error] {e}")
    finally:
        SYNC_ALL_RUNNING = False
