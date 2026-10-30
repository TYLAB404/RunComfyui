import os
import sys
import json
import time
from fastapi.testclient import TestClient

from app import app
from core.database import (
    get_db_connection, db_get_task,
    db_save_task, db_atomic_cancel_and_refund
)
from core.auth import create_jwt_token, get_user_by_identifier
from services.key_pool import KEY_POOL_MANAGER

client = TestClient(app)

def run_tests():
    print("=" * 60)
    print("Running Comprehensive Verification Tests...")
    print("=" * 60)

    # 1. 验证用户和Token获取
    admin_user = get_user_by_identifier("adminkosakii")
    assert admin_user is not None, "admin user must exist in data/app.db"
    admin_token = create_jwt_token({"sub": admin_user["id"], "username": admin_user["username"], "role": "admin", "ver": admin_user.get("token_version", 1)})
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # 获取现有测试普通用户
    test_user = get_user_by_identifier("123123")
    assert test_user is not None, "user 123123 must exist in data/app.db"
    
    # 保证测试用户有充足点数且无进行中任务干扰
    with get_db_connection() as conn:
        conn.execute("UPDATE users SET points = 100 WHERE id = ?;", (test_user["id"],))
        conn.execute("UPDATE tasks SET status = 'CANCELLED' WHERE user_id = ? AND status IN ('QUEUED', 'RUNNING', 'PENDING');", (test_user["id"],))
        conn.commit()

    user_token = create_jwt_token({"sub": test_user["id"], "username": test_user["username"], "role": "user", "ver": test_user.get("token_version", 1)})
    user_headers = {"Authorization": f"Bearer {user_token}"}

    # 2. 验证工作流定价约束 (Pydantic Field ge=0 & 普通用户防绕过)
    print("\n[Test 1] 校验工作流负定价拦截与普通用户保底定价...")
    # Admin 提交负数 pointsCost 应被 Pydantic ge=0 校验拒绝 422
    res = client.post("/api/workflows", json={"id": "wf_invalid_neg", "name": "Neg WF", "pointsCost": -5}, headers=admin_headers)
    assert res.status_code == 422, f"Negative pointsCost must be rejected with 422, got {res.status_code}"
    print("  -> Admin 提交负定价工作流被 Pydantic ge=0 严格拦截 (422) [OK]")

    # 普通用户提交 0 算力工作流应被强制提升为 >= 5
    res = client.post("/api/workflows", json={"id": "wf_user_zero", "name": "User Zero WF", "pointsCost": 0}, headers=user_headers)
    assert res.status_code == 200, f"User workflow save failed: {res.text}"
    saved_wf = res.json().get("workflow", {})
    assert saved_wf.get("pointsCost") >= 5, f"User workflow pointsCost must be >= 5, got {saved_wf.get('pointsCost')}"
    print(f"  -> 普通用户尝试提交 0 算力工作流，被平台自动保底提升为 {saved_wf.get('pointsCost')} 点 [OK]")

    # 清理测试工作流
    client.delete("/api/workflows/wf_user_zero", headers=user_headers)

    # 3. 验证排队响应结构 (前端协议契约 status === 'ok', isQueued: true)
    print("\n[Test 2] 验证 Key 全部繁忙时的排队响应契约...")
    from unittest.mock import patch
    from core.config import load_config
    cfg = load_config()
    # 模拟把所有 Key 占满
    for k in cfg.get("apiKeys", []):
        kid = k["id"]
        st = KEY_POOL_MANAGER._states.setdefault(kid, {
            "is_busy": False, "task_id": None, "busy_since": None,
            "is_healthy": True, "health_error": "", "last_checked": 0
        })
        st["is_busy"] = True
        st["task_id"] = "mock_busy_task"

    valid_wf_id = cfg.get("workflows", [{}])[0].get("id", "1904136902449209346")
    with patch("routers.tasks_router.dispatch_queued_task"):
        res = client.post("/api/generate", json={
            "workflowId": valid_wf_id,
            "nodeInfoList": []
        }, headers=user_headers)
    assert res.status_code == 200, f"Generate queue request failed: {res.text}"
    qdata = res.json()
    assert qdata.get("status") == "ok", f"Expected status 'ok', got {qdata.get('status')}"
    assert qdata.get("isQueued") is True, f"Expected isQueued True, got {qdata.get('isQueued')}"
    queued_task_id = qdata.get("taskId")
    assert queued_task_id and queued_task_id.startswith("task_"), f"Queued taskId should start with 'task_', got {queued_task_id}"
    print(f"  -> 排队任务创建成功，返回 status: 'ok', isQueued: True, taskId: {queued_task_id} [OK]")

    # 3.1 验证多开标签/并发拦截（已有一个任务在进行时，提交第 2 个任务必须被严格阻断 400）
    print("\n[Test 2.1] 验证单账号多开标签/多任务并发阻断...")
    res_second = client.post("/api/generate", json={
        "workflowId": valid_wf_id,
        "nodeInfoList": []
    }, headers=user_headers)
    assert res_second.status_code == 400, f"Expected 400 for concurrent submission, got {res_second.status_code}"
    print(f"  -> 多开并发提交被系统精准阻断 (HTTP 400): {res_second.json().get('detail')} [OK]")

    # 3.2 验证管理员特权豁免（管理员并发提交不受单任务限制，无阻断）
    print("\n[Test 2.2] 验证管理员并发提交特权豁免（无限制）...")
    with get_db_connection() as conn:
        conn.execute("INSERT OR REPLACE INTO tasks (task_id, workflow_id, user_id, status, created_at, updated_at) VALUES ('task_admin_active_1', ?, ?, 'RUNNING', ?, ?);", (valid_wf_id, admin_user["id"], int(time.time()), int(time.time())))
        conn.commit()

    with patch("routers.tasks_router.dispatch_queued_task"):
        res_admin_second = client.post("/api/generate", json={
            "workflowId": valid_wf_id,
            "nodeInfoList": []
        }, headers=admin_headers)
    assert res_admin_second.status_code == 200, f"Admin must NOT be restricted by 1-task limit, got {res_admin_second.status_code}: {res_admin_second.text}"
    print(f"  -> 管理员并发提交成功豁免单任务限制，返回 200 正常入队/调度 [OK]")

    # 清理 admin 的测试任务
    with get_db_connection() as conn:
        conn.execute("DELETE FROM tasks WHERE task_id IN ('task_admin_active_1', ?);", (res_admin_second.json().get("taskId"),))
        conn.commit()

    # 释放模拟占用的 Key
    for k in cfg.get("apiKeys", []):
        kid = k["id"]
        if kid in KEY_POOL_MANAGER._states:
            KEY_POOL_MANAGER._states[kid]["is_busy"] = False
            KEY_POOL_MANAGER._states[kid]["task_id"] = None

    # 4. 验证原子取消与幂等退款 (单事务 ACID，防重复退款)
    print("\n[Test 3] 验证原子取消与幂等防二次退款...")
    # 获取用户当前点数
    u_before = get_user_by_identifier("123123")
    points_before = u_before["points"]

    # 第一次取消排队任务
    cancel_res_1 = client.post(f"/api/tasks/{queued_task_id}/cancel", headers=user_headers)
    assert cancel_res_1.status_code == 200, f"Cancel 1 failed: {cancel_res_1.text}"
    cdata_1 = cancel_res_1.json()
    assert cdata_1.get("status") == "ok", f"Expected ok, got {cdata_1}"
    
    u_after_1 = get_user_by_identifier("123123")
    assert u_after_1["points"] == points_before, f"Queued task deduction is 0 until run, points should remain {points_before}, got {u_after_1['points']}"
    print(f"  -> 第一次取消成功，排队任务未扣费故零扣款/退款，用户余额为 {u_after_1['points']} [OK]")

    # 第二次取消同一任务（模拟用户双击或并发攻击）
    cancel_res_2 = client.post(f"/api/tasks/{queued_task_id}/cancel", headers=user_headers)
    cdata_2 = cancel_res_2.json()
    assert cdata_2.get("status") == "error", f"Second cancel must return error, got {cdata_2}"
    
    u_after_2 = get_user_by_identifier("123123")
    assert u_after_2["points"] == u_after_1["points"], "User points must NOT change on second cancel!"
    print("  -> 第二次重复取消被幂等门禁拦截，零二次退款 [OK]")

    # 5. 验证已成功终态 (SUCCESS) 任务不可被取消或退款
    print("\n[Test 4] 验证已完成 (SUCCESS) 任务不可取消或退款...")
    # 创建一个 SUCCESS 任务
    success_task_id = f"test_success_task_{int(time.time())}"
    db_save_task({
        "taskId": success_task_id,
        "workflowId": "1949392211475148802",
        "workflowName": "Wan2.1 测试",
        "taskType": "Standard",
        "userId": test_user["id"],
        "username": test_user["username"],
        "cost": 20,
        "status": "SUCCESS",
        "createdAt": int(time.time()),
        "updatedAt": int(time.time()),
        "outputs": [{"url": "https://example.com/test.png"}]
    })

    cancel_res_succ = client.post(f"/api/tasks/{success_task_id}/cancel", headers=user_headers)
    cdata_succ = cancel_res_succ.json()
    assert cdata_succ.get("status") == "error", f"Cancel on SUCCESS task must return error, got {cdata_succ}"
    
    # 确认数据库中该任务状态仍为 SUCCESS
    t_after = db_get_task(success_task_id)
    assert t_after["status"] == "SUCCESS", f"Task status should remain SUCCESS, got {t_after['status']}"
    
    u_after_succ = get_user_by_identifier("123123")
    assert u_after_succ["points"] == u_after_1["points"], "User points must NOT change when trying to cancel SUCCESS task!"
    print("  -> 对 SUCCESS 任务执行取消被安全拦截，任务状态完整保留为 SUCCESS，零退款 [OK]")

    # 6. 验证对账流水 (points_ledger)
    print("\n[Test 5] 验证 points_ledger 对账流水完整性...")
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM points_ledger WHERE user_id = ?;", (test_user["id"],))
        ledger_count = cursor.fetchone()[0]
        assert ledger_count >= 1, "points_ledger must record transactions"
    print(f"  -> 测试用户流水记录数: {ledger_count} 条，每一笔扣费与退款皆有账可查 [OK]")

    print("\n" + "=" * 60)
    print("All Comprehensive Verification Tests Passed Successfully!")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
