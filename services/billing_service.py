"""
Billing Service for RunComfyui
Handles pricing configuration, instance tier resolution,
minimum balance pre-checks, and duration-based settlement.
"""
import logging
from typing import Dict, Any, Optional, Tuple

from core.config import load_config
from core.database import db_deduct_user_points, get_db_connection
from core.auth import notify_user

logger = logging.getLogger("BillingService")

DEFAULT_PRICING = {
    "standardRate": 0.2,       # Standard 基础档：0.2 币/秒 (24GB 基础算力)
    "plusRate": 0.4,           # Plus 极速档：0.4 币/秒 (48GB 独享显存)
    "minBalanceRequired": 5.0  # 启动最低余额门槛 (5.0 币)
}


def get_billing_pricing() -> Dict[str, float]:
    """获取当前系统生效的计费规则"""
    cfg = load_config()
    sys_cfg = cfg.get("system", {})
    pricing = sys_cfg.get("pricing", {})
    return {
        "standardRate": float(pricing.get("standardRate", DEFAULT_PRICING["standardRate"])),
        "plusRate": float(pricing.get("plusRate", DEFAULT_PRICING["plusRate"])),
        "minBalanceRequired": float(pricing.get("minBalanceRequired", DEFAULT_PRICING["minBalanceRequired"])),
    }


def resolve_instance_tier(
    req_instance_type: Optional[str] = None,
    task_type: Optional[str] = None
) -> Tuple[str, str, float]:
    """
    统一解析运行算力档位与对应费率：
    返回 (instance_type, tier_name, rate_per_second)
    - Plus (高档位): instanceType="plus", 48GB 显存，0.4 币/秒
    - Standard (低档位): instanceType="default", 24GB 显存，0.2 币/秒
    """
    pricing = get_billing_pricing()
    
    is_standard = False
    if req_instance_type:
        is_standard = str(req_instance_type).strip().lower() in ("default", "standard")
    elif task_type:
        is_standard = str(task_type).strip().upper() in ("STANDARD", "LITE")

    if is_standard:
        return "default", "Standard", pricing["standardRate"]
    else:
        return "plus", "Plus", pricing["plusRate"]


def check_user_can_start_task(user: Optional[Dict[str, Any]]) -> Tuple[bool, float, str]:
    """
    任务启动前余额门槛校验：
    - 管理员免校验，直接放行
    - 普通用户需确保账户余额 >= 最低启动门槛 (minBalanceRequired)
    返回 (是否允许, 当前余额, 错误/提示原因)
    """
    if not user:
        return True, 0.0, ""

    if user.get("role") == "admin":
        return True, float(user.get("points", 999999)), "管理员免计费特权"

    pricing = get_billing_pricing()
    min_required = pricing["minBalanceRequired"]

    user_id = str(user.get("id"))
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT points, is_active FROM users WHERE id = ?;", (user_id,))
        row = cursor.fetchone()
        if not row:
            return False, 0.0, "用户账户不存在"
        if not row[1]:
            return False, 0.0, "您的账户已被停用，无法提交新任务"

        cur_points = round(float(row[0] or 0), 2)
        if cur_points < min_required:
            return (
                False,
                cur_points,
                f"账户算力余额不足：启动任务需至少保留 {min_required} 点算力（当前账户仅剩 {cur_points} 点），请先前往兑换卡密充值"
            )

        return True, cur_points, ""


async def settle_task_billing(
    user_id: str,
    task_id: str,
    duration_seconds: int,
    instance_type: str = "plus",
    workflow_name: str = "工作流渲染"
) -> Dict[str, Any]:
    """
    任务执行成功时的纯运行秒数计费原子结算：
    排队耗时不计入计费，仅按实际工作流运行秒数结算。
    - 管理员免费
    - 普通用户按 时长(秒) * 费率(币/秒) 计算并原子扣除
    """
    if not user_id:
        return {"cost": 0.0, "rate": 0.0, "duration": duration_seconds, "deducted": False}

    with get_db_connection() as conn:
        c = conn.cursor()
        c.execute("SELECT role, points FROM users WHERE id = ?;", (str(user_id),))
        u_row = c.fetchone()
        if not u_row:
            return {"cost": 0.0, "rate": 0.0, "duration": duration_seconds, "deducted": False}

        role = u_row[0]
        if role == "admin":
            return {"cost": 0.0, "rate": 0.0, "duration": duration_seconds, "deducted": False, "reason": "管理员免扣费"}

    pricing = get_billing_pricing()
    rate = pricing["standardRate"] if instance_type.lower() == "default" else pricing["plusRate"]

    billed_duration = max(1, int(duration_seconds))
    actual_cost = round(billed_duration * rate, 2)

    tier_label = "Standard 基础档" if instance_type.lower() == "default" else "Plus 极速档"
    reason = f"任务渲染计费 [{tier_label}] ({billed_duration}秒 × {rate}币/秒)"

    ok, new_bal, msg = db_deduct_user_points(
        user_id=user_id,
        amount=actual_cost,
        task_id=task_id,
        reason=reason
    )

    if ok:
        try:
            await notify_user(
                user_id=user_id,
                event_type="POINTS_UPDATED",
                data={
                    "points": new_bal,
                    "cost": actual_cost,
                    "duration": billed_duration,
                    "rate": rate,
                    "taskId": task_id,
                    "reason": reason
                }
            )
        except Exception as e:
            logger.warning(f"Failed to send SSE notification to user {user_id}: {e}")

    return {
        "cost": actual_cost,
        "rate": rate,
        "duration": billed_duration,
        "deducted": ok,
        "remainingBalance": new_bal,
        "message": msg
    }
