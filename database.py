import os
import sqlite3
import json
import time
from typing import Optional, List, Dict, Any, Tuple

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "app.db")
OLD_TASKS_PATH = os.path.join(DATA_DIR, "tasks.json")

os.makedirs(DATA_DIR, exist_ok=True)

# ----------------- 内存级防爆破与限流缓存 -----------------
_LOGIN_ATTEMPTS: Dict[str, List[float]] = {}

def is_rate_limited(key: str, max_attempts: int = 5, window_seconds: int = 900) -> bool:
    """滑动窗口限流：15 分钟内连续失败超过 5 次则锁定"""
    now = time.time()
    attempts = [t for t in _LOGIN_ATTEMPTS.get(key, []) if now - t < window_seconds]
    _LOGIN_ATTEMPTS[key] = attempts
    return len(attempts) >= max_attempts

def record_failed_attempt(key: str):
    now = time.time()
    attempts = _LOGIN_ATTEMPTS.setdefault(key, [])
    _LOGIN_ATTEMPTS[key] = [t for t in attempts if now - t < 900] + [now]

def clear_failed_attempts(key: str):
    _LOGIN_ATTEMPTS.pop(key, None)

# ----------------- SQLite 高并发连接池 (WAL模式) -----------------

def get_db_connection() -> sqlite3.Connection:
    """
    获取 SQLite 数据库连接：
    开启 WAL 预写日志模式，支持极高并发读写，彻底杜绝多用户同时注册/更新时的冲突问题
    """
    conn = sqlite3.connect(DB_PATH, timeout=25.0)
    conn.row_factory = sqlite3.Row
    # 开启 WAL 模式（高并发核心）与异步落盘同步
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_database():
    """初始化数据库表架构与自动迁移旧版数据"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # 1. 用户表 (Users)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            points INTEGER NOT NULL DEFAULT 100,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL,
            last_login INTEGER NOT NULL,
            task_count INTEGER NOT NULL DEFAULT 0
        );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);")

        # 2. 任务表 (Tasks) - 支持持久化与多租户审计
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS tasks (
            task_id TEXT PRIMARY KEY,
            user_id TEXT,
            username TEXT,
            workflow_id TEXT,
            workflow_name TEXT,
            task_type TEXT DEFAULT 'Standard',
            positive_prompt TEXT,
            negative_prompt TEXT,
            status TEXT NOT NULL,
            duration INTEGER DEFAULT 0,
            consume_coins TEXT DEFAULT '0',
            outputs_json TEXT DEFAULT '[]',
            node_info_json TEXT DEFAULT '[]',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tasks_user_id ON tasks (user_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks (status);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tasks_created_at ON tasks (created_at DESC);")

        # 3. 公告表 (Announcements) - 平台官方公告与活动通知
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS announcements (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            tag TEXT DEFAULT '官方公告',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_announcements_created_at ON announcements (created_at DESC);")

        # 预设一条初始欢迎公告
        cursor.execute("SELECT COUNT(*) FROM announcements;")
        if cursor.fetchone()[0] == 0:
            cursor.execute("""
            INSERT INTO announcements (id, title, content, tag, is_active, created_at, updated_at)
            VALUES (?, ?, ?, ?, 1, ?, ?);
            """, (
                "anno_welcome",
                "🎉 欢迎加入全新一代 ComfyUI 云端创作平台！",
                "欢迎体验新升级的 AI 创作中枢！系统全面接入高并发工作流渲染流水线，支持毫秒级流式预览、历史成果画廊与跨设备同步。祝您创作愉快！",
                "新手引导",
                int(time.time()),
                int(time.time())
            ))

        # 4. 积分对账流水台账表 (Points Ledger - 彻底解决 P0-5 计费虚设问题)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS points_ledger (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            task_id TEXT,
            amount INTEGER NOT NULL,
            balance_after INTEGER NOT NULL,
            reason TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_points_user_id ON points_ledger (user_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_points_created_at ON points_ledger (created_at DESC);")

        # 5. 自动无损增量同步字段 (避免 SQLite 重建表)
        def _add_col_if_missing(tbl, col, def_sql):
            cursor.execute(f"PRAGMA table_info({tbl});")
            cols = [r[1] for r in cursor.fetchall()]
            if col not in cols:
                cursor.execute(f"ALTER TABLE {tbl} ADD COLUMN {col} {def_sql};")

        _add_col_if_missing("users", "token_version", "INTEGER NOT NULL DEFAULT 1")
        _add_col_if_missing("tasks", "queue_remaining", "INTEGER DEFAULT 0")
        _add_col_if_missing("tasks", "status_text", "TEXT DEFAULT ''")
        _add_col_if_missing("tasks", "progress_percent", "REAL DEFAULT 0")
        _add_col_if_missing("tasks", "current_step", "INTEGER DEFAULT 0")
        _add_col_if_missing("tasks", "current_node_id", "TEXT DEFAULT ''")
        _add_col_if_missing("tasks", "error_message", "TEXT DEFAULT ''")
        _add_col_if_missing("tasks", "cost", "INTEGER DEFAULT 0")

        conn.commit()

        # 3. 自动迁移 tasks.json 历史任务至 SQLite
        cursor.execute("SELECT COUNT(*) FROM tasks;")
        count = cursor.fetchone()[0]
        if count == 0 and os.path.exists(OLD_TASKS_PATH):
            try:
                with open(OLD_TASKS_PATH, "r", encoding="utf-8") as f:
                    old_tasks = json.load(f)
                if isinstance(old_tasks, list) and len(old_tasks) > 0:
                    for t in old_tasks:
                        tid = str(t.get("taskId", ""))
                        if not tid:
                            continue
                        cursor.execute("""
                        INSERT OR IGNORE INTO tasks (
                            task_id, user_id, username, workflow_id, workflow_name, task_type,
                            positive_prompt, negative_prompt, status, duration, consume_coins,
                            outputs_json, node_info_json, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                        """, (
                            tid,
                            t.get("userId") if t.get("userId") else None,
                            t.get("username", "匿名访客"),
                            str(t.get("workflowId", "")),
                            t.get("workflowName", ""),
                            t.get("taskType", "Standard"),
                            t.get("positivePrompt", ""),
                            t.get("negativePrompt", ""),
                            t.get("status", "SUCCESS"),
                            int(t.get("duration", 0) or 0),
                            str(t.get("consumeCoins", "0")),
                            json.dumps(t.get("outputs", []), ensure_ascii=False),
                            json.dumps(t.get("nodeInfoList", []), ensure_ascii=False),
                            int(t.get("createdAt", time.time())),
                            int(t.get("updatedAt", time.time()))
                        ))
                    conn.commit()
            except Exception as e:
                print(f"[Database Warning] Auto-migration of tasks.json skipped: {e}")

# ----------------- 任务表 (Tasks) 封装操作 -----------------

def db_row_to_task(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    try:
        outputs = json.loads(d.get("outputs_json") or "[]")
    except Exception:
        outputs = []
    try:
        node_info = json.loads(d.get("node_info_json") or "[]")
    except Exception:
        node_info = []

    return {
        "taskId": d.get("task_id"),
        "userId": d.get("user_id") or "",
        "username": d.get("username") or "匿名访客",
        "workflowId": d.get("workflow_id"),
        "workflowName": d.get("workflow_name"),
        "taskType": d.get("task_type", "Standard"),
        "positivePrompt": d.get("positive_prompt") or "",
        "negativePrompt": d.get("negative_prompt") or "",
        "status": d.get("status"),
        "duration": d.get("duration", 0),
        "consumeCoins": d.get("consume_coins", "0"),
        "queueRemaining": d.get("queue_remaining", 0),
        "statusText": d.get("status_text", ""),
        "progressPercent": d.get("progress_percent", 0),
        "currentStep": d.get("current_step", 0),
        "currentNodeId": d.get("current_node_id", ""),
        "error": d.get("error_message", ""),
        "cost": d.get("cost", 0),
        "outputs": outputs,
        "nodeInfoList": node_info,
        "createdAt": d.get("created_at"),
        "updatedAt": d.get("updated_at")
    }

def db_load_tasks(
    user_id: Optional[str] = None, 
    status: Optional[str] = None,
    is_admin: bool = False, 
    limit: int = 200,
    search_user: Optional[str] = None
) -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        clauses = []
        params = []
        
        if is_admin:
            if user_id:
                clauses.append("user_id = ?")
                params.append(str(user_id))
            elif search_user:
                clauses.append("(user_id = ? OR username LIKE ?)")
                params.extend([str(search_user), f"%{search_user}%"])
        else:
            if user_id:
                clauses.append("user_id = ?")
                params.append(str(user_id))
            else:
                clauses.append("(user_id = '' OR user_id IS NULL)")
        
        if status and status.upper() != "ALL":
            st_upper = status.upper()
            if st_upper in ("RUNNING", "QUEUED", "PENDING", "IN_PROGRESS"):
                clauses.append("status IN ('QUEUED', 'RUNNING', 'PENDING')")
            else:
                clauses.append("status = ?")
                params.append(st_upper)
                
        where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM tasks {where_sql} ORDER BY created_at DESC LIMIT ?;"
        params.append(limit)
        
        cursor.execute(sql, tuple(params))
        rows = cursor.fetchall()
        return [db_row_to_task(r) for r in rows]

def db_get_task(task_id: str) -> Optional[Dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM tasks WHERE task_id = ?;", (str(task_id),))
        row = cursor.fetchone()
        return db_row_to_task(row) if row else None

def db_save_task(task: Dict[str, Any]):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO tasks (
            task_id, user_id, username, workflow_id, workflow_name, task_type,
            positive_prompt, negative_prompt, status, duration, consume_coins,
            outputs_json, node_info_json, cost, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(task_id) DO UPDATE SET
            status = excluded.status,
            duration = excluded.duration,
            consume_coins = excluded.consume_coins,
            outputs_json = excluded.outputs_json,
            cost = excluded.cost,
            updated_at = excluded.updated_at;
        """, (
            str(task["taskId"]),
            str(task["userId"]) if task.get("userId") else None,
            str(task.get("username", "匿名访客")),
            str(task.get("workflowId", "")),
            str(task.get("workflowName", "")),
            str(task.get("taskType", "Standard")),
            str(task.get("positivePrompt", "")),
            str(task.get("negativePrompt", "")),
            str(task.get("status", "QUEUED")),
            int(task.get("duration", 0) or 0),
            str(task.get("consumeCoins", "0")),
            json.dumps(task.get("outputs", []), ensure_ascii=False),
            json.dumps(task.get("nodeInfoList", []), ensure_ascii=False),
            int(task.get("cost", 0) or 0),
            int(task.get("createdAt", time.time())),
            int(task.get("updatedAt", time.time()))
        ))
        conn.commit()

def db_update_task(task_id: str, updates: Dict[str, Any]):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        col_updates = []
        vals = []
        
        mapping = {
            "status": "status",
            "duration": "duration",
            "consumeCoins": "consume_coins",
            "updatedAt": "updated_at",
            "taskType": "task_type",
            "cost": "cost",
            "queueRemaining": "queue_remaining",
            "statusText": "status_text",
            "progressPercent": "progress_percent",
            "currentStep": "current_step",
            "currentNodeId": "current_node_id",
            "error": "error_message",
            "errorMessage": "error_message"
        }
        for k, v in updates.items():
            if k in mapping:
                col_updates.append(f"{mapping[k]} = ?")
                vals.append(v)
            elif k == "outputs":
                col_updates.append("outputs_json = ?")
                vals.append(json.dumps(v, ensure_ascii=False))
        
        if not col_updates:
            return
            
        vals.append(str(task_id))
        sql = f"UPDATE tasks SET {', '.join(col_updates)} WHERE task_id = ?;"
        cursor.execute(sql, tuple(vals))
        conn.commit()

def db_delete_tasks_batch(task_ids: List[str]) -> int:
    """从数据库批量删除任务记录"""
    if not task_ids:
        return 0
    with get_db_connection() as conn:
        cursor = conn.cursor()
        placeholders = ",".join("?" for _ in task_ids)
        cursor.execute(f"DELETE FROM tasks WHERE task_id IN ({placeholders});", tuple(str(tid) for tid in task_ids))
        deleted_count = cursor.rowcount
        conn.commit()
        return deleted_count

def db_delete_task(task_id: str):
    """从数据库删除单条任务"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM tasks WHERE task_id = ?;", (str(task_id),))
        conn.commit()

# ----------------- 积分计费原子操作与流水账本 (P0-5 资产防超卖与防并发并发) -----------------

def db_deduct_user_points(user_id: str, amount: int, task_id: str = "", reason: str = "工作流生图扣费") -> Tuple[bool, int, str]:
    """
    原子扣减用户积分：
    采用 SQL 原生条件更新 UPDATE ... WHERE points >= amount，彻底杜绝并发下余额扣成负数！
    返回 (成功标志, 扣后余额, 错误信息)
    """
    if amount <= 0:
        with get_db_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT points FROM users WHERE id = ?;", (str(user_id),))
            r = c.fetchone()
            return True, (r[0] if r else 0), ""

    with get_db_connection() as conn:
        cursor = conn.cursor()
        # 1. 原子条件扣减
        cursor.execute(
            "UPDATE users SET points = points - ? WHERE id = ? AND points >= ? AND is_active = 1;",
            (amount, str(user_id), amount)
        )
        if cursor.rowcount == 0:
            # 扣减失败，查询当前状态
            cursor.execute("SELECT points, is_active FROM users WHERE id = ?;", (str(user_id),))
            row = cursor.fetchone()
            if not row:
                return False, 0, "用户不存在"
            if not row[1]:
                return False, row[0], "用户账户已被封禁，禁止消费"
            return False, row[0], f"算力点数不足（当前余额: {row[0]}, 本次需要: {amount}）"

        # 2. 查询扣减后最新余额
        cursor.execute("SELECT points FROM users WHERE id = ?;", (str(user_id),))
        new_balance = cursor.fetchone()[0]

        # 3. 记录流水台账
        ledger_id = f"led_{int(time.time())}_{os.urandom(3).hex()}"
        cursor.execute("""
        INSERT INTO points_ledger (id, user_id, task_id, amount, balance_after, reason, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?);
        """, (ledger_id, str(user_id), str(task_id), -amount, new_balance, reason, int(time.time())))

        conn.commit()
        return True, new_balance, "扣费成功"

def db_refund_user_points(user_id: str, amount: int, task_id: str = "", reason: str = "生图失败/取消退款") -> Tuple[bool, int]:
    """原子退还用户积分，并写入退款对账流水"""
    if amount <= 0:
        return True, 0
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET points = points + ? WHERE id = ?;", (amount, str(user_id)))
        cursor.execute("SELECT points FROM users WHERE id = ?;", (str(user_id),))
        row = cursor.fetchone()
        new_balance = row[0] if row else 0

        ledger_id = f"led_{int(time.time())}_{os.urandom(3).hex()}"
        cursor.execute("""
        INSERT INTO points_ledger (id, user_id, task_id, amount, balance_after, reason, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?);
        """, (ledger_id, str(user_id), str(task_id), amount, new_balance, reason, int(time.time())))
        conn.commit()
        return True, new_balance

def db_bump_token_version(user_id: str) -> int:
    """递增用户的 token 版本号，使之前签发的所有旧 JWT 立即失效（用于改密、封禁与秒踢）"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET token_version = token_version + 1 WHERE id = ?;", (str(user_id),))
        cursor.execute("SELECT token_version FROM users WHERE id = ?;", (str(user_id),))
        row = cursor.fetchone()
        conn.commit()
        return row[0] if row else 1

def db_get_token_version(user_id: str) -> int:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT token_version FROM users WHERE id = ?;", (str(user_id),))
        row = cursor.fetchone()
        return row[0] if row else 1

# ----------------- 公告表 (Announcements) 封装操作 -----------------

def db_get_announcements(active_only: bool = True) -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if active_only:
            cursor.execute("SELECT * FROM announcements WHERE is_active = 1 ORDER BY created_at DESC;")
        else:
            cursor.execute("SELECT * FROM announcements ORDER BY created_at DESC;")
        rows = cursor.fetchall()
        return [
            {
                "id": r["id"],
                "title": r["title"],
                "content": r["content"],
                "tag": r["tag"],
                "isActive": bool(r["is_active"]),
                "createdAt": r["created_at"],
                "updatedAt": r["updated_at"]
            }
            for r in rows
        ]

def db_save_announcement(title: str, content: str, tag: str = "官方公告", is_active: bool = True) -> Dict[str, Any]:
    anno_id = f"anno_{int(time.time())}_{os.urandom(3).hex()}"
    now = int(time.time())
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO announcements (id, title, content, tag, is_active, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?);
        """, (anno_id, title.strip(), content.strip(), tag.strip(), 1 if is_active else 0, now, now))
        conn.commit()
    return {
        "id": anno_id,
        "title": title.strip(),
        "content": content.strip(),
        "tag": tag.strip(),
        "isActive": is_active,
        "createdAt": now,
        "updatedAt": now
    }

def db_update_announcement(anno_id: str, updates: Dict[str, Any]):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cols = []
        vals = []
        mapping = {
            "title": "title",
            "content": "content",
            "tag": "tag",
            "isActive": "is_active"
        }
        for k, v in updates.items():
            if k in mapping:
                cols.append(f"{mapping[k]} = ?")
                vals.append(1 if v else 0 if k == "isActive" else v)
        if not cols:
            return
        cols.append("updated_at = ?")
        vals.append(int(time.time()))
        vals.append(str(anno_id))
        sql = f"UPDATE announcements SET {', '.join(cols)} WHERE id = ?;"
        cursor.execute(sql, tuple(vals))
        conn.commit()

def db_delete_announcement(anno_id: str):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM announcements WHERE id = ?;", (str(anno_id),))
        conn.commit()

# 执行数据库自动初始化
init_database()
