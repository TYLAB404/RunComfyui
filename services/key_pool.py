import time
import asyncio
from typing import Dict, List, Any, Optional, Set, Tuple
from core.config import load_config
from core.security import decrypt_key, mask_key, verify_key_with_runninghub
from core.database import db_get_task
from services.email_service import async_notify_key_incident, _ALERTED_KEY_INCIDENTS

class KeyPoolManager:
    """
    RunningHub 多 API Key 轮询调度器与单并发互斥池 (支持健康熔断与无感故障转移)
    """
    def __init__(self):
        self._states: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()
        self._waiters: List[asyncio.Event] = []

    def _get_all_keys(self) -> List[Dict[str, Any]]:
        cfg = load_config()
        return cfg.get("apiKeys", [])

    async def acquire_free_key(self, task_id: str, exclude_key_ids: Optional[Set[str]] = None) -> Optional[Tuple[str, str, str]]:
        """
        原子挑选一个【空闲且健康】的 API Key。
        若传入 exclude_key_ids，则直接跳过指定的故障 Key（用于静默无感自动故障转移）。
        """
        async with self._lock:
            all_keys = self._get_all_keys()
            if not all_keys:
                return None
            
            excludes = exclude_key_ids or set()
            for k in all_keys:
                kid = k.get("id")
                if kid in excludes:
                    continue
                st = self._states.setdefault(kid, {
                    "is_busy": False, 
                    "task_id": None, 
                    "busy_since": None,
                    "is_healthy": True,
                    "health_error": "",
                    "last_checked": 0
                })
                if not st["is_busy"] and st.get("is_healthy", True):
                    raw = decrypt_key(k.get("keyEncrypted", ""))
                    if raw:
                        st["is_busy"] = True
                        st["task_id"] = str(task_id)
                        st["busy_since"] = time.time()
                        return kid, raw, k.get("name", "未命名密钥")
            return None

    async def wait_for_free_key(self, task_id: str, timeout: float = 300.0, exclude_key_ids: Optional[Set[str]] = None) -> Optional[Tuple[str, str, str]]:
        start = time.time()
        while time.time() - start < timeout:
            key_info = await self.acquire_free_key(task_id, exclude_key_ids=exclude_key_ids)
            if key_info:
                return key_info
            
            ev = asyncio.Event()
            async with self._lock:
                self._waiters.append(ev)
            
            try:
                await asyncio.wait_for(ev.wait(), timeout=min(3.0, max(0.5, timeout - (time.time() - start))))
            except (asyncio.TimeoutError, TimeoutError):
                pass
            finally:
                async with self._lock:
                    if ev in self._waiters:
                        self._waiters.remove(ev)
        return None

    async def release_key(self, key_id: str, task_id: Optional[str] = None):
        async with self._lock:
            if key_id in self._states:
                st = self._states[key_id]
                if task_id is None or st.get("task_id") == str(task_id):
                    st["is_busy"] = False
                    st["task_id"] = None
                    st["busy_since"] = None
            for w in self._waiters:
                w.set()
            self._waiters.clear()

    async def release_key_by_task_id(self, task_id: str):
        async with self._lock:
            for kid, st in self._states.items():
                if st.get("task_id") == str(task_id):
                    st["is_busy"] = False
                    st["task_id"] = None
                    st["busy_since"] = None
            for w in self._waiters:
                w.set()
            self._waiters.clear()

    async def mark_key_unhealthy(self, key_id: str, error_reason: str):
        """将某个 Key 标记为故障/被封禁熔断，并触发后台告警邮件"""
        key_name = key_id
        masked = "****"
        async with self._lock:
            st = self._states.setdefault(key_id, {
                "is_busy": False, "task_id": None, "busy_since": None,
                "is_healthy": True, "health_error": "", "last_checked": 0
            })
            st["is_healthy"] = False
            st["health_error"] = str(error_reason)
            st["is_busy"] = False
            st["task_id"] = None
            st["busy_since"] = None
            
            for k in self._get_all_keys():
                if k.get("id") == key_id:
                    key_name = k.get("name", key_id)
                    masked = mask_key(decrypt_key(k.get("keyEncrypted", "")))
                    break
            
            for w in self._waiters:
                w.set()
            self._waiters.clear()

        asyncio.create_task(async_notify_key_incident(key_id, key_name, masked, error_reason))

    async def mark_key_healthy(self, key_id: str):
        """管理员一键恢复某个 Key 为健康可用状态"""
        async with self._lock:
            if key_id in self._states:
                st = self._states[key_id]
                st["is_healthy"] = True
                st["health_error"] = ""
            _ALERTED_KEY_INCIDENTS.pop(key_id, None)
            for w in self._waiters:
                w.set()
            self._waiters.clear()

    async def inspect_all_keys(self) -> List[Dict[str, Any]]:
        """全池主动巡检所有 Key，更新健康状态"""
        all_keys = self._get_all_keys()
        results = []
        for k in all_keys:
            kid = k.get("id")
            name = k.get("name", "未命名密钥")
            raw = decrypt_key(k.get("keyEncrypted", ""))
            masked = mask_key(raw)
            valid, msg = await asyncio.to_thread(verify_key_with_runninghub, raw)
            
            async with self._lock:
                st = self._states.setdefault(kid, {
                    "is_busy": False, "task_id": None, "busy_since": None,
                    "is_healthy": True, "health_error": "", "last_checked": 0
                })
                st["last_checked"] = time.time()
                if valid:
                    st["is_healthy"] = True
                    st["health_error"] = ""
                else:
                    st["is_healthy"] = False
                    st["health_error"] = msg
                    st["is_busy"] = False
                    st["task_id"] = None
            
            if not valid:
                asyncio.create_task(async_notify_key_incident(kid, name, masked, msg))

            results.append({
                "id": kid,
                "name": name,
                "maskedKey": masked,
                "isValid": valid,
                "message": msg
            })
        return results

    def get_pool_status(self) -> List[Dict[str, Any]]:
        all_keys = self._get_all_keys()
        now = time.time()
        res = []
        for k in all_keys:
            kid = k.get("id")
            raw = decrypt_key(k.get("keyEncrypted", ""))
            st = self._states.get(kid, {
                "is_busy": False, "task_id": None, "busy_since": None,
                "is_healthy": True, "health_error": "", "last_checked": 0
            })
            is_busy = bool(st.get("is_busy"))
            is_healthy = bool(st.get("is_healthy", True))
            busy_duration = int(now - st["busy_since"]) if (is_busy and st.get("busy_since")) else 0
            res.append({
                "id": kid,
                "name": k.get("name", "未命名密钥"),
                "maskedKey": mask_key(raw),
                "isBusy": is_busy,
                "isHealthy": is_healthy,
                "healthError": st.get("health_error", ""),
                "currentTaskId": st.get("task_id") if is_busy else None,
                "busyDuration": busy_duration,
                "note": k.get("note", "")
            })
        return res

    async def reset_key(self, key_id: str):
        await self.release_key(key_id)
        await self.mark_key_healthy(key_id)

    async def mark_key_busy(self, key_id: str, task_id: str):
        """恢复某个 Key 为忙碌占用状态（用于服务重启对账时恢复云端正在运行的任务）"""
        async with self._lock:
            st = self._states.setdefault(key_id, {
                "is_busy": False, "task_id": None, "busy_since": None,
                "is_healthy": True, "health_error": "", "last_checked": 0
            })
            st["is_busy"] = True
            st["task_id"] = str(task_id)
            st["busy_since"] = time.time()

    def get_busy_count(self) -> Tuple[int, int]:
        all_keys = self._get_all_keys()
        busy_keys = sum(1 for k in all_keys if self._states.get(k.get("id"), {}).get("is_busy"))
        return busy_keys, len(all_keys)

    def get_queue_stats(self) -> Dict[str, Any]:
        all_keys = self._get_all_keys()
        total_keys = len(all_keys)
        healthy_keys = sum(1 for k in all_keys if self._states.get(k.get("id"), {}).get("is_healthy", True))
        busy_keys = sum(1 for k in all_keys if self._states.get(k.get("id"), {}).get("is_busy"))
        waiting_tasks = len(self._waiters)
        return {
            "totalKeys": total_keys,
            "healthyKeys": healthy_keys,
            "bannedKeys": total_keys - healthy_keys,
            "busyKeys": busy_keys,
            "freeKeys": max(0, healthy_keys - busy_keys),
            "waitingTasks": waiting_tasks
        }

KEY_POOL_MANAGER = KeyPoolManager()

async def key_pool_watchdog_loop():
    """状态对账守护协程：每 20 秒自检一次，仅同步已完成/取消的任务释放"""
    while True:
        await asyncio.sleep(20)
        try:
            async with KEY_POOL_MANAGER._lock:
                for kid, st in KEY_POOL_MANAGER._states.items():
                    if st.get("is_busy"):
                        tid = st.get("task_id")
                        if tid:
                            task = db_get_task(tid)
                            if task and task.get("status") in ("SUCCESS", "FAILED", "CANCELLED"):
                                print(f"[Watchdog] Task {tid} finished ({task.get('status')}), auto-releasing key {kid}")
                                st["is_busy"] = False
                                st["task_id"] = None
                                st["busy_since"] = None
        except Exception as e:
            print(f"[Watchdog Error] {e}")

async def key_pool_health_inspector_loop():
    """无人值守自动健康巡检守护协程：每 30 分钟对所有 Key 巡检一次，发现异常自动隔离并邮件告警"""
    while True:
        await asyncio.sleep(1800)
        try:
            print("[Health Inspector] Starting periodic full pool health inspection...")
            await KEY_POOL_MANAGER.inspect_all_keys()
        except Exception as e:
            print(f"[Health Inspector Error] {e}")
