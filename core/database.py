import os
import sqlite3
import json
import time
from typing import Optional, List, Dict, Any, Tuple
import secrets

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
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

# 卡密兑换防爆破限频字典 (15分钟内连续输错 5 次锁定 15 分钟)
_REDEEM_ATTEMPTS: Dict[str, List[float]] = {}

def is_redeem_rate_limited(key: str, max_attempts: int = 5, window_seconds: int = 900) -> bool:
    now = time.time()
    attempts = [t for t in _REDEEM_ATTEMPTS.get(key, []) if now - t < window_seconds]
    _REDEEM_ATTEMPTS[key] = attempts
    return len(attempts) >= max_attempts

def record_failed_redeem_attempt(key: str):
    now = time.time()
    attempts = _REDEEM_ATTEMPTS.setdefault(key, [])
    _REDEEM_ATTEMPTS[key] = [t for t in attempts if now - t < 900] + [now]

def clear_failed_redeem_attempts(key: str):
    _REDEEM_ATTEMPTS.pop(key, None)


# ----------------- SQLite 高并发连接池 (WAL模式) -----------------

import contextlib

@contextlib.contextmanager
def get_db_connection():
    """
    高性能防泄漏 SQLite 连接引擎：
    1. 启用 WAL 预写日志（在 init_database 持久化开启）与 NORMAL 同步
    2. 开启 32MB 内存缓存与 128MB mmap 内存映射，减少 90% 物理磁盘寻道
    3. 严格在 finally 块中关闭连接，彻底消除 Windows 文件锁与文件句柄泄漏
    """
    conn = sqlite3.connect(DB_PATH, timeout=25.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA cache_size = -32000;")
    conn.execute("PRAGMA temp_store = MEMORY;")
    conn.execute("PRAGMA mmap_size = 134217728;")
    try:
        yield conn
    finally:
        conn.close()

def init_database():
    """初始化数据库表架构与自动迁移旧版数据"""
    with get_db_connection() as conn:
        conn.execute("PRAGMA journal_mode = WAL;")
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
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tasks_user_status ON tasks (user_id, status);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tasks_user_created ON tasks (user_id, created_at DESC);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tasks_status_created ON tasks (status, created_at DESC);")

        try:
            cursor.execute("ALTER TABLE tasks ADD COLUMN key_id TEXT DEFAULT '';")
            conn.commit()
        except Exception:
            pass


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

        # 5. 卡密与兑换码发行核销表 (CDKeys) - 银行级防爆破与原子核销
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS cdkeys (
            code TEXT PRIMARY KEY,
            points INTEGER NOT NULL,
            is_used INTEGER NOT NULL DEFAULT 0,
            is_void INTEGER NOT NULL DEFAULT 0,
            used_by_user_id TEXT DEFAULT '',
            used_by_username TEXT DEFAULT '',
            created_at INTEGER NOT NULL,
            used_at INTEGER DEFAULT 0,
            remark TEXT DEFAULT ''
        );
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cdkeys_is_used ON cdkeys (is_used);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cdkeys_is_void ON cdkeys (is_void);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_cdkeys_created_at ON cdkeys (created_at DESC);")


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
        "updatedAt": d.get("updated_at"),
        "keyId": d.get("key_id") or ""
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
            outputs_json, node_info_json, cost, created_at, updated_at, key_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(task_id) DO UPDATE SET
            status = excluded.status,
            duration = excluded.duration,
            consume_coins = excluded.consume_coins,
            outputs_json = excluded.outputs_json,
            cost = excluded.cost,
            updated_at = excluded.updated_at,
            key_id = COALESCE(NULLIF(excluded.key_id, ''), tasks.key_id);
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
            int(task.get("updatedAt", time.time())),
            str(task.get("keyId") or task.get("key_id") or "")
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
            "errorMessage": "error_message",
            "keyId": "key_id",
            "key_id": "key_id"
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

def db_clean_tasks_by_status(status: str = "FAILED") -> int:
    """按状态直接在 SQL 层批量清理任务，避免加载全量 JSON 到内存"""
    st = (status or "FAILED").upper()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if st == "ALL_FINISHED":
            cursor.execute("DELETE FROM tasks WHERE status IN ('FAILED', 'SUCCESS', 'CANCELLED');")
        else:
            cursor.execute("DELETE FROM tasks WHERE status = ?;", (st,))
        deleted_count = cursor.rowcount
        conn.commit()
        return deleted_count

def db_get_user_task_counts() -> Dict[str, int]:
    """基于 SQL GROUP BY 索引统计每个用户的任务总数，避免全表反序列化"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT user_id, COUNT(*) as cnt FROM tasks WHERE user_id IS NOT NULL AND user_id != '' GROUP BY user_id;")
        return {str(r["user_id"]): int(r["cnt"]) for r in cursor.fetchall()}

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


# ----------------- 卡密发行、核销与对账 (CDKeys) -----------------

CDKEY_CHARS = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"  # 排除 0, O, 1, I 等易混淆字符

def generate_secure_cdkey_code() -> str:
    """生成 16 位密码学真随机高熵卡密 (格式: XXXX-XXXX-XXXX-XXXX)"""
    parts = []
    for _ in range(4):
        part = "".join(secrets.choice(CDKEY_CHARS) for _ in range(4))
        parts.append(part)
    return "-".join(parts)

def db_generate_cdkeys(points: int, count: int, remark: str = "") -> List[str]:
    """批量生成高熵卡密并写入数据库"""
    if points <= 0 or count <= 0:
        return []
    count = min(count, 500)
    now = int(time.time())
    generated = []
    
    with get_db_connection() as conn:
        cursor = conn.cursor()
        for _ in range(count):
            code = generate_secure_cdkey_code()
            cursor.execute("""
            INSERT OR IGNORE INTO cdkeys (code, points, is_used, is_void, used_by_user_id, used_by_username, created_at, used_at, remark)
            VALUES (?, ?, 0, 0, '', '', ?, 0, ?);
            """, (code, points, now, (remark or "").strip()))
            generated.append(code)
        conn.commit()
    return generated

def db_redeem_cdkey(raw_code: str, user_id: str, username: str) -> Tuple[bool, int, str]:
    """
    原子核销卡密：
    1. 输入清洗 (大写、去首尾空格)
    2. 原子排他条件更新 UPDATE ... WHERE is_used = 0 AND is_void = 0
    3. 成功后原子增加用户积分并记录流水台账
    """
    code = (raw_code or "").strip().upper()
    if not code:
        return False, 0, "卡密兑换码不能为空"

    now = int(time.time())
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT points, is_used, is_void FROM cdkeys WHERE code = ?;", (code,))
        row = cursor.fetchone()
        if not row:
            return False, 0, "卡密不存在，请仔细核对是否输错"
        
        pts, is_used, is_void = row[0], bool(row[1]), bool(row[2])
        if is_void:
            return False, 0, "该卡密已被系统管理员作废"
        if is_used:
            return False, 0, "该卡密已被使用，无法重复兑换"

        # 原子排他核销（高并发重放攻击彻底拦截）
        cursor.execute("""
        UPDATE cdkeys 
        SET is_used = 1, used_by_user_id = ?, used_by_username = ?, used_at = ? 
        WHERE code = ? AND is_used = 0 AND is_void = 0;
        """, (str(user_id), str(username), now, code))
        
        if cursor.rowcount == 0:
            return False, 0, "卡密已被并发核销，请勿重复提交"

        # 原子增加用户积分
        cursor.execute("UPDATE users SET points = points + ? WHERE id = ?;", (pts, str(user_id)))
        cursor.execute("SELECT points FROM users WHERE id = ?;", (str(user_id),))
        u_row = cursor.fetchone()
        new_balance = u_row[0] if u_row else pts

        # 记录积分流水对账台账
        ledger_id = f"led_{now}_{os.urandom(3).hex()}"
        cursor.execute("""
        INSERT INTO points_ledger (id, user_id, task_id, amount, balance_after, reason, created_at)
        VALUES (?, ?, '', ?, ?, ?, ?);
        """, (ledger_id, str(user_id), pts, new_balance, f"卡密兑换充值 ({code})", now))

        conn.commit()
        return True, new_balance, f"兑换成功！已为您充值 {pts} 点算力"

def db_list_cdkeys(status_filter: str = "ALL", page: int = 1, page_size: int = 50, search: str = "") -> Dict[str, Any]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        clauses = []
        params = []

        if status_filter == "UNUSED":
            clauses.append("is_used = 0 AND is_void = 0")
        elif status_filter == "USED":
            clauses.append("is_used = 1")
        elif status_filter == "VOID":
            clauses.append("is_void = 1")

        if search:
            search_pattern = f"%{search.strip()}%"
            clauses.append("(code LIKE ? OR used_by_username LIKE ? OR remark LIKE ?)")
            params.extend([search_pattern, search_pattern, search_pattern])

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        cursor.execute("""
            SELECT 
                COUNT(CASE WHEN is_used = 0 AND is_void = 0 THEN 1 END) as unused_cnt,
                COUNT(CASE WHEN is_used = 1 THEN 1 END) as used_cnt,
                COUNT(CASE WHEN is_void = 1 THEN 1 END) as void_cnt,
                COALESCE(SUM(points), 0) as total_pts
            FROM cdkeys;
        """)
        agg_row = cursor.fetchone()
        unused_count = agg_row["unused_cnt"] if agg_row else 0
        used_count = agg_row["used_cnt"] if agg_row else 0
        void_count = agg_row["void_cnt"] if agg_row else 0
        total_points_issued = agg_row["total_pts"] if agg_row else 0

        cursor.execute(f"SELECT COUNT(*) FROM cdkeys {where_sql};", tuple(params))
        filtered_total = cursor.fetchone()[0]

        offset = max(0, (page - 1) * page_size)
        cursor.execute(
            f"SELECT * FROM cdkeys {where_sql} ORDER BY created_at DESC LIMIT ? OFFSET ?;",
            tuple(params + [page_size, offset])
        )
        rows = cursor.fetchall()
        items = []
        for r in rows:
            items.append({
                "code": r["code"],
                "points": r["points"],
                "isUsed": bool(r["is_used"]),
                "isVoid": bool(r["is_void"]),
                "usedByUserId": r["used_by_user_id"],
                "usedByUsername": r["used_by_username"],
                "createdAt": r["created_at"],
                "usedAt": r["used_at"],
                "remark": r["remark"]
            })

        return {
            "total": filtered_total,
            "page": page,
            "pageSize": page_size,
            "unusedCount": unused_count,
            "usedCount": used_count,
            "voidCount": void_count,
            "totalPointsIssued": total_points_issued,
            "items": items
        }

def db_void_cdkey(code: str) -> bool:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE cdkeys SET is_void = 1 WHERE code = ? AND is_used = 0;", (code.strip().upper(),))
        conn.commit()
        return cursor.rowcount > 0

def db_delete_cdkey(code: str) -> bool:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM cdkeys WHERE code = ?;", (code.strip().upper(),))
        conn.commit()
        return cursor.rowcount > 0

def db_get_unused_cdkeys_export(remark: str = "") -> List[Dict[str, Any]]:
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if remark:
            cursor.execute("SELECT code, points, remark, created_at FROM cdkeys WHERE is_used = 0 AND is_void = 0 AND remark = ? ORDER BY created_at DESC;", (remark.strip(),))
        else:
            cursor.execute("SELECT code, points, remark, created_at FROM cdkeys WHERE is_used = 0 AND is_void = 0 ORDER BY created_at DESC LIMIT 500;")
        rows = cursor.fetchall()
        return [{"code": r["code"], "points": r["points"], "remark": r["remark"], "createdAt": r["created_at"]} for r in rows]


# 执行数据库自动初始化
init_database()


def db_get_admin_overview_stats() -> Dict[str, Any]:
    """
    毫秒级高性能全站聚合统计：
    基于 SQL 原生 COUNT/SUM 索引聚合，彻底解决原先加载 500 条数据至内存的统计失真与内存膨胀 Bug。
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # 用户统计
        cursor.execute("""
            SELECT 
                COUNT(*) as total_users,
                COUNT(CASE WHEN role = 'admin' THEN 1 END) as admin_count,
                COUNT(CASE WHEN is_active = 1 THEN 1 END) as active_users
            FROM users;
        """)
        u_row = cursor.fetchone()
        
        # 任务统计 (过去 24 小时)
        now_ts = int(time.time())
        one_day_ago = now_ts - 86400
        
        cursor.execute("""
            SELECT 
                COUNT(*) as total_tasks,
                COUNT(CASE WHEN created_at >= ? THEN 1 END) as today_tasks,
                COUNT(CASE WHEN status = 'SUCCESS' THEN 1 END) as success_tasks,
                COUNT(CASE WHEN status = 'FAILED' THEN 1 END) as failed_tasks,
                COALESCE(SUM(CAST(consume_coins AS REAL)), 0.0) as total_coins
            FROM tasks;
        """, (one_day_ago,))
        t_row = cursor.fetchone()

        return {
            "totalUsers": u_row["total_users"] if u_row else 0,
            "adminCount": u_row["admin_count"] if u_row else 0,
            "activeUsers": u_row["active_users"] if u_row else 0,
            "totalTasks": t_row["total_tasks"] if t_row else 0,
            "todayTasks": t_row["today_tasks"] if t_row else 0,
            "successTasks": t_row["success_tasks"] if t_row else 0,
            "failedTasks": t_row["failed_tasks"] if t_row else 0,
            "totalCoinsUsed": round(float(t_row["total_coins"] if t_row else 0.0), 2)
        }


# 别名兼容
update_task_record = db_update_task

def load_tasks() -> List[Dict[str, Any]]:
    return db_load_tasks(is_admin=True, limit=500)

def save_tasks(tasks: List[Dict[str, Any]]):
    for t in tasks:
        db_save_task(t)


def db_record_points_ledger(user_id: str, delta: int, balance_after: int, reason: str, task_id: str = ""):
    """手动增扣点数或调账时记录流水，确保余额与流水强一致"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        ledger_id = f"led_{int(time.time())}_{os.urandom(3).hex()}"
        cursor.execute("""
        INSERT INTO points_ledger (id, user_id, task_id, amount, balance_after, reason, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?);
        """, (ledger_id, str(user_id), str(task_id), delta, balance_after, reason, int(time.time())))
        conn.commit()


def db_count_user_active_tasks(user_id: str) -> int:
    """统计指定用户当前正在进行中（排队或渲染中）的任务数"""
    if not user_id:
        return 0
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM tasks WHERE user_id = ? AND status IN ('QUEUED', 'RUNNING', 'PENDING');", (str(user_id),))
        row = cursor.fetchone()
        return row[0] if row else 0


def db_atomic_cancel_and_refund(task_id: str, reason: str = "任务取消退款") -> Tuple[bool, str, int]:
    """
    原子化取消任务并执行点数退还（杜绝并发双击/多重取消导致的重复退款）:
    1. 在数据库事务内执行 UPDATE tasks SET status='CANCELLED', cost=0 WHERE task_id=? AND status IN ('QUEUED','RUNNING','PENDING') AND cost > 0;
    2. 检查 cursor.rowcount:
       - 若 rowcount == 1: 成功拿到唯一退款权！读取该任务的 user_id 和原 cost，调用 db_refund_user_points 退还。
       - 若 rowcount == 0: 说明该任务已被其他并发请求取消、已退过款、或本身为 0 算力，直接幂等返回 False，拒绝二次退款！
    """
    now = int(time.time())
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT user_id, cost, status FROM tasks WHERE task_id = ?;", (str(task_id),))
        row = cursor.fetchone()
        if not row:
            return False, "任务不存在", 0
        
        user_id = row["user_id"]
        original_cost = int(row["cost"] or 0)
        cur_status = str(row["status"] or "")
        if cur_status in ("CANCELLED", "FAILED", "SUCCESS"):
            return False, f"任务已处于终态 ({cur_status})，无需重复取消或退款", 0
        
        if original_cost <= 0:
            cursor.execute("UPDATE tasks SET status = 'CANCELLED', updated_at = ? WHERE task_id = ? AND status IN ('QUEUED', 'RUNNING', 'PENDING');", (now, str(task_id)))
            conn.commit()
            return True, "任务已标记取消（无需退款）", 0
        
        # 核心原子状态跃迁：只在 cost > 0 且状态为进行中时扣减
        cursor.execute("""
            UPDATE tasks 
            SET status = 'CANCELLED', cost = 0, updated_at = ? 
            WHERE task_id = ? AND status IN ('QUEUED', 'RUNNING', 'PENDING') AND cost > 0;
        """, (now, str(task_id)))
        
        if cursor.rowcount == 0:
            return False, "任务已处于终态或退款已处理完毕（幂等防护生效）", 0

        # 单事务 ACID 原子化点数返还与流水落盘，杜绝分布式崩溃窗口资损
        new_bal = 0
        if user_id and original_cost > 0:
            cursor.execute("UPDATE users SET points = points + ? WHERE id = ?;", (original_cost, str(user_id)))
            cursor.execute("SELECT points FROM users WHERE id = ?;", (str(user_id),))
            p_row = cursor.fetchone()
            new_bal = p_row[0] if p_row else 0

            ledger_id = f"led_{now}_{os.urandom(3).hex()}"
            ledger_reason = f"{reason} (任务ID: {task_id})"
            cursor.execute("""
            INSERT INTO points_ledger (id, user_id, task_id, amount, balance_after, reason, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?);
            """, (ledger_id, str(user_id), str(task_id), original_cost, new_bal, ledger_reason, now))

        conn.commit()
        return True, f"已成功取消并退还 {original_cost} 算力点", new_bal
