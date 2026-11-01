"""
Automated Disaster-Recovery Backup Service for RunComfyui
Provides:
1. Transaction-safe SQLite online snapshot (prevents corruption under WAL mode)
2. Packaging of critical assets: data/app.db, data/.secret.key, data/config.json, data/workflows/, .env
3. Automatic rotation & retention (default keeps last 7 days of rolling snapshots)
4. Offsite email push (disaster vault: sends zip attachment to admin inbox via SMTP/Resend)
5. Restore utility & admin APIs for 1-click backup downloads
"""
import os
import time
import zipfile
import sqlite3
import json
import asyncio
from datetime import datetime
from typing import Tuple, Dict, Any, List, Optional

from core.config import BASE_DIR, DATA_DIR, load_config
from core.database import DB_PATH
from services.email_service import send_admin_alert_email

BACKUP_DIR = os.path.join(BASE_DIR, "backups")
os.makedirs(BACKUP_DIR, exist_ok=True)

_LAST_BACKUP_TIME: float = 0.0


def create_backup(include_workflows: bool = True, send_email: bool = False) -> Tuple[bool, str, Dict[str, Any]]:
    """
    创建一次完整的应用灾备快照压缩包。
    使用 SQLite 在线备份 API，保证在业务并发写入时数据库文件 100% 事务一致、绝不损坏。
    """
    os.makedirs(BACKUP_DIR, exist_ok=True)
    now = datetime.now()
    timestamp_str = now.strftime("%Y%m%d_%H%M%S")
    zip_filename = f"runcomfyui_backup_{timestamp_str}.zip"
    zip_filepath = os.path.join(BACKUP_DIR, zip_filename)
    temp_db_path = os.path.join(BACKUP_DIR, f"_tmp_snapshot_{timestamp_str}.db")

    meta: Dict[str, Any] = {
        "filename": zip_filename,
        "createdAt": now.isoformat(),
        "timestamp": time.time(),
        "filesIncluded": [],
        "totalSizeBytes": 0,
        "dbSizeBytes": 0,
        "version": "2.0.0"
    }

    try:
        # 1. 安全生成 SQLite 在线热快照
        if os.path.exists(DB_PATH):
            src_conn = sqlite3.connect(DB_PATH, timeout=30.0)
            dst_conn = sqlite3.connect(temp_db_path)
            with dst_conn:
                src_conn.backup(dst_conn)
            dst_conn.close()
            src_conn.close()
            meta["dbSizeBytes"] = os.path.getsize(temp_db_path)
        else:
            return False, f"核心数据库不存在: {DB_PATH}", {}

        # 2. 打包生成 ZIP 压缩档案
        with zipfile.ZipFile(zip_filepath, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
            # 写入核心热快照
            zf.write(temp_db_path, arcname="data/app.db")
            meta["filesIncluded"].append("data/app.db")

            # 写入对称加密密钥（关键：解密 Key 必需）
            secret_key_path = os.path.join(DATA_DIR, ".secret.key")
            if os.path.exists(secret_key_path):
                zf.write(secret_key_path, arcname="data/.secret.key")
                meta["filesIncluded"].append("data/.secret.key")

            # 写入系统配置文件
            config_json_path = os.path.join(DATA_DIR, "config.json")
            if os.path.exists(config_json_path):
                zf.write(config_json_path, arcname="data/config.json")
                meta["filesIncluded"].append("data/config.json")

            # 写入环境配置 .env (若存在)
            env_path = os.path.join(BASE_DIR, ".env")
            if os.path.exists(env_path):
                zf.write(env_path, arcname=".env")
                meta["filesIncluded"].append(".env")

            # 写入自定义工作流目录
            if include_workflows:
                wf_dir = os.path.join(DATA_DIR, "workflows")
                if os.path.exists(wf_dir):
                    for root, _, files in os.walk(wf_dir):
                        for f in files:
                            full_path = os.path.join(root, f)
                            rel_path = os.path.relpath(full_path, BASE_DIR)
                            zf.write(full_path, arcname=rel_path.replace("\\", "/"))
                            meta["filesIncluded"].append(rel_path.replace("\\", "/"))

            # 写入自描述清单元数据
            meta_json_str = json.dumps(meta, ensure_ascii=False, indent=2)
            zf.writestr("manifest.json", meta_json_str)

        # 3. 清理临时 SQLite 文件
        if os.path.exists(temp_db_path):
            os.remove(temp_db_path)

        meta["totalSizeBytes"] = os.path.getsize(zip_filepath)

        # 4. 自动滚动轮转：清理 7 天以前的历史备份
        cleanup_old_backups(keep_days=7)

        global _LAST_BACKUP_TIME
        _LAST_BACKUP_TIME = time.time()

        # 5. 异地容灾：若开启邮件推送，静默发送给管理员邮箱保险箱
        if send_email:
            send_backup_to_admin(zip_filepath, meta)

        return True, zip_filepath, meta

    except Exception as e:
        # 清理异常遗留文件
        if os.path.exists(temp_db_path):
            try: os.remove(temp_db_path)
            except Exception: pass
        if os.path.exists(zip_filepath):
            try: os.remove(zip_filepath)
            except Exception: pass
        return False, f"创建备份异常失败: {str(e)}", {}


def cleanup_old_backups(keep_days: int = 7) -> int:
    """清理超过保留天数的本地历史压缩包，防止吃满磁盘"""
    if not os.path.exists(BACKUP_DIR):
        return 0
    now = time.time()
    cutoff = now - (keep_days * 86400)
    cleaned = 0
    for filename in os.listdir(BACKUP_DIR):
        if filename.startswith("runcomfyui_backup_") and filename.endswith(".zip"):
            file_path = os.path.join(BACKUP_DIR, filename)
            try:
                if os.path.getmtime(file_path) < cutoff:
                    os.remove(file_path)
                    cleaned += 1
            except Exception:
                pass
    return cleaned


def list_backups() -> List[Dict[str, Any]]:
    """获取本地所有已生成的备份快照列表（按时间倒序）"""
    if not os.path.exists(BACKUP_DIR):
        return []
    results = []
    for filename in os.listdir(BACKUP_DIR):
        if filename.startswith("runcomfyui_backup_") and filename.endswith(".zip"):
            full_path = os.path.join(BACKUP_DIR, filename)
            try:
                stat = os.stat(full_path)
                results.append({
                    "filename": filename,
                    "sizeBytes": stat.st_size,
                    "sizeFormatted": f"{stat.st_size / (1024 * 1024):.2f} MB" if stat.st_size >= 1048576 else f"{stat.st_size / 1024:.1f} KB",
                    "createdAt": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                    "mtime": stat.st_mtime
                })
            except Exception:
                pass
    return sorted(results, key=lambda x: x["mtime"], reverse=True)


def get_backup_path(filename: str) -> Optional[str]:
    """安全解析备份文件名路径，防止路径遍历攻击 (Path Traversal)"""
    safe_name = os.path.basename(filename)
    if not (safe_name.startswith("runcomfyui_backup_") and safe_name.endswith(".zip")):
        return None
    full_path = os.path.join(BACKUP_DIR, safe_name)
    if os.path.exists(full_path):
        return full_path
    return None


def send_backup_to_admin(zip_filepath: str, meta: Dict[str, Any]) -> Tuple[bool, str]:
    """将备份包作为附件推送到管理员邮箱保险箱"""
    size_str = f"{meta['totalSizeBytes'] / 1024:.1f} KB" if meta['totalSizeBytes'] < 1048576 else f"{meta['totalSizeBytes'] / (1024 * 1024):.2f} MB"
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    subject = f"【RunComfyUI 数据保险箱】全站数据自动灾备快照 ({now_str})"
    html_body = f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b0f19; color: #e2e8f0; padding: 24px; border-radius: 16px; max-width: 600px; margin: 0 auto; border: 1px solid #334155;">
      <h2 style="color: #38bdf8; margin-top: 0;">🛡️ RunComfyUI 异地灾备快照推送</h2>
      <p style="font-size: 14px; color: #cbd5e1; line-height: 1.6;">
        尊敬的管理员：系统已成功执行定时全站核心数据冷备份，并已自动打包附在本邮件附件中。
      </p>
      <div style="background-color: #1e293b; padding: 14px 18px; border-radius: 8px; font-size: 13px; margin: 16px 0; border-left: 4px solid #10b981;">
        <p style="margin: 4px 0;"><b>备份文件名：</b> <code style="color: #93c5fd;">{meta['filename']}</code></p>
        <p style="margin: 4px 0;"><b>压缩包大小：</b> {size_str}</p>
        <p style="margin: 4px 0;"><b>包含核心资产：</b> SQLite数据库 (app.db)、秘钥 (.secret.key)、配置 (config.json)、工作流</p>
        <p style="margin: 4px 0;"><b>备份生成时间：</b> {now_str}</p>
      </div>
      <p style="font-size: 12px; color: #94a3b8; line-height: 1.5;">
        💡 <b>灾备使用提示：</b>即便服务器主板损坏、机房失火或海外 VPS 停服跑路，您只需下载此邮件附件，将其解压覆盖到任何新服务器的 <code>data/</code> 目录，即可 100% 无损满血复原全部用户、积分与设置！
      </p>
    </div>
    """
    return send_admin_alert_email(subject, html_body, attachment_path=zip_filepath)


async def auto_backup_scheduler_loop():
    """
    后台轻量自愈定时器：
    每天凌晨 03:00~03:30 自动执行一次冷备并推送到管理员邮箱。
    """
    while True:
        try:
            await asyncio.sleep(60)  # 每分钟巡检一次当前时间
            now = datetime.now()
            # 每天凌晨 3:15 执行备份，且距离上次备份至少超过 18 小时
            global _LAST_BACKUP_TIME
            if now.hour == 3 and now.minute == 15:
                if time.time() - _LAST_BACKUP_TIME > 18 * 3600:
                    cfg = load_config()
                    auto_email = bool(cfg.get("system", {}).get("smtp", {}).get("enabled"))
                    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [Backup] Starting scheduled nightly automated backup...")
                    ok, res, meta = create_backup(include_workflows=True, send_email=auto_email)
                    if ok:
                        print(f"[Backup] Nightly backup succeeded: {res} ({meta.get('totalSizeBytes', 0)} bytes)")
                    else:
                        print(f"[Backup] Nightly backup failed: {res}")
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[Backup Error] Error in auto backup loop: {e}")
            await asyncio.sleep(60)
