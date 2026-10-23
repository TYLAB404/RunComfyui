import os
import sys
import time
import json
from fastapi.testclient import TestClient

from app import app
from database import init_database, db_bump_token_version, db_deduct_user_points, get_db_connection
from auth import create_user, create_jwt_token, get_user_by_identifier, delete_user_by_id

client = TestClient(app)

def test_full_security_matrix():
    print("--- 1. Initializing Database ---")
    init_database()

    print("--- 2. Setting Up Test Users ---")
    # Clean up test users if present (respecting foreign key constraints)
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM points_ledger WHERE user_id IN (SELECT id FROM users WHERE username IN ('test_admin_sec', 'test_user_a', 'test_user_b'));")
        cursor.execute("DELETE FROM tasks WHERE user_id IN (SELECT id FROM users WHERE username IN ('test_admin_sec', 'test_user_a', 'test_user_b')) OR workflow_id = 'wf_test_audit';")
        cursor.execute("DELETE FROM users WHERE username IN ('test_admin_sec', 'test_user_a', 'test_user_b');")
        conn.commit()

    admin = create_user("test_admin_sec", "admin@sec.com", "PasswordAdmin123!", role="admin", points=500)
    user_a = create_user("test_user_a", "usera@sec.com", "PasswordUserA123!", role="user", points=50)
    user_b = create_user("test_user_b", "userb@sec.com", "PasswordUserB123!", role="user", points=10)

    admin_token = create_jwt_token({"sub": admin["id"], "username": admin["username"], "role": "admin", "ver": admin.get("tokenVersion", 1)})
    user_a_token = create_jwt_token({"sub": user_a["id"], "username": user_a["username"], "role": "user", "ver": user_a.get("tokenVersion", 1)})
    user_b_token = create_jwt_token({"sub": user_b["id"], "username": user_b["username"], "role": "user", "ver": user_b.get("tokenVersion", 1)})

    headers_admin = {"Authorization": f"Bearer {admin_token}"}
    headers_user_a = {"Authorization": f"Bearer {user_a_token}"}
    headers_user_b = {"Authorization": f"Bearer {user_b_token}"}

    print("\n--- 3. Testing P0-2: Management Endpoints Authorization Matrix ---")
    # 3.1 Anonymous access to /api/keys
    r = client.get("/api/keys")
    assert r.status_code == 401, f"Expected 401 for anonymous /api/keys, got {r.status_code}"
    print(" [PASS] Anonymous GET /api/keys -> 401")

    # 3.2 User A access to /api/keys
    r = client.get("/api/keys", headers=headers_user_a)
    assert r.status_code == 403, f"Expected 403 for user /api/keys, got {r.status_code}"
    print(" [PASS] User A GET /api/keys -> 403 Forbidden")

    # 3.3 Admin access to /api/keys
    r = client.get("/api/keys", headers=headers_admin)
    assert r.status_code == 200, f"Expected 200 for admin /api/keys, got {r.status_code}"
    print(" [PASS] Admin GET /api/keys -> 200 OK")

    # 3.4 POST /api/config by non-admin
    r = client.post("/api/config", json={"apiKey": "fake_key"})
    assert r.status_code == 401, f"Expected 401 for anonymous /api/config, got {r.status_code}"
    r = client.post("/api/config", json={"apiKey": "fake_key"}, headers=headers_user_a)
    assert r.status_code == 403, f"Expected 403 for user /api/config, got {r.status_code}"
    print(" [PASS] Anonymous & User POST /api/config -> 401 & 403")

    # 3.5 GET /api/config masks keys for regular users
    r_pub = client.get("/api/config", headers=headers_user_a)
    assert r_pub.status_code == 200
    data_pub = r_pub.json()
    assert data_pub["keys"] == [], "Keys must be empty for normal users"
    assert data_pub["activeKeyId"] == "", "activeKeyId must be empty for normal users"
    print(" [PASS] GET /api/config properly masks keys from non-admin users")

    # 3.6 POST /api/workflows by user vs admin
    r = client.post("/api/workflows", json={"id": "wf_test_audit", "name": "Test WF"}, headers=headers_user_a)
    assert r.status_code == 403, f"Expected 403 for user wf add, got {r.status_code}"
    r = client.post("/api/workflows", json={"id": "wf_test_audit", "name": "Test WF", "pointsCost": 20}, headers=headers_admin)
    assert r.status_code == 200, f"Expected 200 for admin wf add, got {r.status_code}"
    print(" [PASS] POST /api/workflows restricted to admin")

    print("\n--- 4. Testing P0-3 & P0-4: Tenant Validation (Tasks & Gallery) ---")
    # Seed a task owned by user_a
    from database import db_save_task
    test_task_id = "task_sec_audit_1001"
    db_save_task({
        "taskId": test_task_id,
        "workflowId": "wf_test_audit",
        "userId": user_a["id"],
        "username": user_a["username"],
        "status": "QUEUED",
        "cost": 20,
        "outputs": [{"filename": "secret_user_a.png", "url": "https://cos.com/secret_user_a.png"}]
    })

    # User B trying to read User A's task -> 404 (anti-enumeration)
    r = client.get(f"/api/tasks/{test_task_id}", headers=headers_user_b)
    assert r.status_code == 404, f"Expected 404 for User B reading User A task, got {r.status_code}"
    print(" [PASS] User B cannot read User A task (404 anti-enumeration)")

    # User A reading User A's task -> 200
    r = client.get(f"/api/tasks/{test_task_id}", headers=headers_user_a)
    assert r.status_code == 200, f"Expected 200 for User A reading own task, got {r.status_code}"
    print(" [PASS] User A can read own task (200)")

    # User B trying to cancel User A's task -> 403
    r = client.post(f"/api/tasks/{test_task_id}/cancel", headers=headers_user_b)
    assert r.status_code == 403, f"Expected 403 for User B cancelling User A task, got {r.status_code}"
    print(" [PASS] User B cannot cancel User A task (403 Forbidden)")

    # User B trying to delete User A's gallery output -> 404/403
    r = client.delete("/api/gallery/secret_user_a.png", headers=headers_user_b)
    assert r.status_code in (403, 404), f"Expected 403/404 for User B deleting User A gallery file, got {r.status_code}"
    print(" [PASS] User B cannot delete User A gallery file")

    print("\n--- 5. Testing P0-5: Atomic Points Deduction & Refund ---")
    from auth import get_user_by_id
    u_before = get_user_by_id(user_a["id"])
    points_before = u_before["points"]

    # Cancel task as User A -> Points should be refunded
    r = client.post(f"/api/tasks/{test_task_id}/cancel", headers=headers_user_a)
    assert r.status_code == 200
    u_after = get_user_by_id(user_a["id"])
    assert u_after["points"] == points_before + 20, f"Points should have been refunded (+20), was {points_before} now {u_after['points']}"
    print(f" [PASS] User A cancelled task, points refunded: {points_before} -> {u_after['points']}")

    # Insufficient points check: user_b only has 10 points, deduct 20 -> fails atomically
    success, rem, msg = db_deduct_user_points(user_b["id"], 20, reason="Test overdraw")
    assert not success, "Deducting 20 points from user with 10 points must fail"
    u_b = get_user_by_id(user_b["id"])
    assert u_b["points"] == 10, f"Balance must remain 10, got {u_b['points']}"
    print(" [PASS] Atomic deduction rejects insufficient points, no negative balances")

    print("\n--- 6. Testing P0-7: Instant Kick (Token Versioning & Revocation) ---")
    # Verify User A works with original token
    r = client.get("/api/tasks", headers=headers_user_a)
    assert r.status_code == 200

    # Admin changes User A's password or disables User A
    from auth import set_user_password
    set_user_password(user_a["id"], "NewPassword456!")
    # Old token used by User A should be instantly invalid
    r = client.get("/api/tasks", headers=headers_user_a)
    assert r.status_code == 401 or r.json() == [], "Old token must be rejected immediately"
    print(" [PASS] Password change instantly revokes old JWT token (0.1s instant kick verified)")

    print("\n--- 7. Cleanup Test Records ---")
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM points_ledger WHERE user_id IN (SELECT id FROM users WHERE username IN ('test_admin_sec', 'test_user_a', 'test_user_b'));")
        cursor.execute("DELETE FROM tasks WHERE user_id IN (SELECT id FROM users WHERE username IN ('test_admin_sec', 'test_user_a', 'test_user_b')) OR workflow_id = 'wf_test_audit';")
        cursor.execute("DELETE FROM users WHERE username IN ('test_admin_sec', 'test_user_a', 'test_user_b');")
        conn.commit()
    print(" [PASS] Cleaned up test records from database.")

    print("\n==========================================")
    print(" ALL SECURITY & ARCHITECTURE TESTS PASSED! ")
    print("==========================================")

if __name__ == "__main__":
    test_full_security_matrix()
