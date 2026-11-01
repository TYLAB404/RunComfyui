#!/usr/bin/env python3
"""
RunComfyUI Disaster-Recovery Backup CLI
Usage:
    python scripts/backup.py --backup           # 创建本地快照
    python scripts/backup.py --backup --email   # 创建快照并同步推送至管理员邮箱保险箱
    python scripts/backup.py --list             # 查看所有历史快照
    python scripts/backup.py --restore <file>   # 从快照压缩包一键还原核心数据
"""
import sys
import os
import argparse
import zipfile
import shutil

# 自动加入父目录路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.backup_service import create_backup, list_backups, get_backup_path, BACKUP_DIR
from core.config import BASE_DIR, DATA_DIR


def main():
    parser = argparse.ArgumentParser(description="RunComfyUI Disaster-Recovery Backup CLI")
    parser.add_argument("--backup", action="store_true", help="执行全站核心数据快照备份")
    parser.add_argument("--email", action="store_true", help="备份完成后同步推送到管理员设置的告警/备份邮箱")
    parser.add_argument("--list", action="store_true", help="列出本地所有快照")
    parser.add_argument("--restore", type=str, help="指定备份文件名或路径进行全站恢复")

    args = parser.parse_args()

    if args.backup:
        print("[*] 正在生成 SQLite 热事务快照并打包核心数据...")
        ok, res, meta = create_backup(include_workflows=True, send_email=args.email)
        if ok:
            print("[OK] 备份成功！")
            print(f"    - 文件路径: {res}")
            print(f"    - 压缩包大小: {meta.get('totalSizeBytes', 0) / 1024:.1f} KB")
            print(f"    - 包含资产: {', '.join(meta.get('filesIncluded', []))}")
            if args.email:
                print("    - 异地推送: 已尝试作为邮件附件静默发送给管理员邮箱")
        else:
            print(f"[FAIL] 备份失败: {res}")
            sys.exit(1)

    elif args.list:
        backups = list_backups()
        if not backups:
            print(f"[*] 暂无备份文件 (备份存储目录: {BACKUP_DIR})")
        else:
            print(f"[*] 发现 {len(backups)} 个备份快照：")
            print(f"{'文件名':<40} {'大小':<12} {'创建时间'}")
            print("-" * 75)
            for b in backups:
                print(f"{b['filename']:<40} {b['sizeFormatted']:<12} {b['createdAt']}")

    elif args.restore:
        zip_path = args.restore
        if not os.path.exists(zip_path):
            candidate = get_backup_path(zip_path)
            if candidate:
                zip_path = candidate
            else:
                print(f"[FAIL] 找不到备份文件: {zip_path}")
                sys.exit(1)

        print(f"[*] 准备从 {zip_path} 恢复数据...")
        confirm = input("[!] 警告：恢复操作将覆盖当前 data/app.db 和配置文件！是否继续？(y/N): ")
        if confirm.lower() != 'y':
            print("已取消还原操作。")
            sys.exit(0)

        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                zf.extractall(BASE_DIR)
            print("[OK] 恢复成功！数据文件已成功解压还原至目标目录。建议重启服务以加载最新数据。")
        except Exception as e:
            print(f"[FAIL] 恢复失败: {e}")
            sys.exit(1)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
