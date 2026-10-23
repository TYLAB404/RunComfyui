#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RunningHub 系统运维终端管理工具
用于无需前台界面即可直接管理管理员账号、重置密码、修改点数
使用方法:
  python manage.py list-users
  python manage.py promote <用户名>
  python manage.py demote <用户名>
  python manage.py set-points <用户名> <点数>
  python manage.py set-password <用户名> <新密码>
"""
import sys
import os
import sqlite3

try:
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "data", "app.db")

def get_conn():
    if not os.path.exists(DB_PATH):
        print(f"[错误] 数据库文件不存在: {DB_PATH}")
        sys.exit(1)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def list_users():
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT id, username, email, role, points, is_active FROM users ORDER BY created_at ASC;")
        rows = c.fetchall()
        print("\n=== 系统全量用户列表 ===")
        print(f"{'用户名':<18} {'角色':<10} {'点数':<8} {'状态':<6} {'邮箱'}")
        print("-" * 65)
        for r in rows:
            role_badge = "[管理员]" if r["role"] == "admin" else "[普通用户]"
            status_badge = "正常" if r["is_active"] else "封禁"
            print(f"{r['username']:<18} {role_badge:<10} {r['points']:<8} {status_badge:<6} {r['email'] or '-'}")
        print(f"共计 {len(rows)} 名用户\n")

def promote_user(username: str):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT id, role FROM users WHERE LOWER(username) = ?;", (username.strip().lower(),))
        row = c.fetchone()
        if not row:
            print(f"[错误] 未找到用户: {username}")
            return
        c.execute("UPDATE users SET role = 'admin', points = MAX(points, 9999) WHERE id = ?;", (row["id"],))
        conn.commit()
        print(f"✓ 成功将用户 【{username}】 提拔为超级管理员 (Admin)，并赋予 9999 算力点数！")

def demote_user(username: str):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT id, role FROM users WHERE LOWER(username) = ?;", (username.strip().lower(),))
        row = c.fetchone()
        if not row:
            print(f"[错误] 未找到用户: {username}")
            return
        c.execute("UPDATE users SET role = 'user' WHERE id = ?;", (row["id"],))
        conn.commit()
        print(f"✓ 成功将用户 【{username}】 权限变更为普通用户。")

def set_points(username: str, points: int):
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE LOWER(username) = ?;", (username.strip().lower(),))
        row = c.fetchone()
        if not row:
            print(f"[错误] 未找到用户: {username}")
            return
        c.execute("UPDATE users SET points = ? WHERE id = ?", (int(points), row["id"]))
        conn.commit()
        print(f"✓ 成功为用户 【{username}】 设置点数为: {points}")

def set_password(username: str, new_password: str):
    from auth import hash_password
    with get_conn() as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE LOWER(username) = ?;", (username.strip().lower(),))
        row = c.fetchone()
        if not row:
            print(f"[错误] 未找到用户: {username}")
            return
        pwd_hash, salt = hash_password(new_password)
        c.execute("UPDATE users SET password_hash = ?, salt = ? WHERE id = ?;", (pwd_hash, salt, row["id"]))
        conn.commit()
        print(f"✓ 成功重置用户 【{username}】 的登录密码！")

def print_help():
    print("""
RunningHub 终端管理指令:
  python manage.py list-users                       # 查看所有注册用户与权限
  python manage.py promote <用户名>                 # 将指定用户设为管理员
  python manage.py demote <用户名>                  # 将管理员降为普通用户
  python manage.py set-points <用户名> <点数>       # 修改用户代币点数
  python manage.py set-password <用户名> <新密码>   # 强制修改用户密码
""")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_help()
        sys.exit(0)
    
    cmd = sys.argv[1].lower()
    if cmd == "list-users":
        list_users()
    elif cmd == "promote" and len(sys.argv) >= 3:
        promote_user(sys.argv[2])
    elif cmd == "demote" and len(sys.argv) >= 3:
        demote_user(sys.argv[2])
    elif cmd == "set-points" and len(sys.argv) >= 4:
        set_points(sys.argv[2], int(sys.argv[3]))
    elif cmd == "set-password" and len(sys.argv) >= 4:
        set_password(sys.argv[2], sys.argv[3])
    else:
        print_help()
