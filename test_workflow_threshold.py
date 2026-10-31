import os
import sys
from fastapi.testclient import TestClient

from app import app
from core.database import (
    init_database, db_deduct_user_points, db_refund_user_points,
    db_save_task, db_get_task, db_update_task
)
from core.auth import create_user, verify_password, create_jwt_token, get_user_by_id, get_user_by_identifier
from core.config import load_config, save_config

client = TestClient(app)

def test_workflow_threshold_flow():
    print("--- 1. Initializing DB and Test Users ---")
    init_database()
    
    admin_email = "threshold_admin@test.com"
    poor_email = "threshold_poor@test.com"
    rich_email = "threshold_rich@test.com"
    
    admin = get_user_by_identifier(admin_email)
    if not admin:
        admin = create_user("ThresholdAdmin", admin_email, "AdminPass123!", role="admin", points=500)
        
    user_poor = get_user_by_identifier(poor_email)
    if not user_poor:
        user_poor = create_user("ThresholdPoor", poor_email, "UserPass123!", role="user", points=30)
    else:
        db_deduct_user_points(user_poor["id"], user_poor["points"], reason="Reset")
        db_refund_user_points(user_poor["id"], 30, reason="Set 30")
        user_poor = get_user_by_id(user_poor["id"])
        
    user_rich = get_user_by_identifier(rich_email)
    if not user_rich:
        user_rich = create_user("ThresholdRich", rich_email, "UserPass123!", role="user", points=200)
    else:
        db_deduct_user_points(user_rich["id"], user_rich["points"], reason="Reset")
        db_refund_user_points(user_rich["id"], 200, reason="Set 200")
        user_rich = get_user_by_id(user_rich["id"])
        
    def make_token(u):
        return create_jwt_token({
            "sub": u["id"],
            "username": u["username"],
            "role": u.get("role", "user"),
            "ver": u.get("tokenVersion", 1)
        })
        
    token_admin = make_token(admin)
    token_poor = make_token(user_poor)
    token_rich = make_token(user_rich)
    
    headers_admin = {"Authorization": f"Bearer {token_admin}"}
    headers_poor = {"Authorization": f"Bearer {token_poor}"}
    headers_rich = {"Authorization": f"Bearer {token_rich}"}
    
    print("--- 2. Admin Creates/Updates Workflow with Usage Threshold ---")
    wf_payload = {
        "id": "wf_test_threshold_01",
        "name": "高门槛视频渲染工作流",
        "category": "视频生成",
        "pointsCost": 5,
        "minPointsEnabled": True,
        "minPoints": 100,
        "description": "需要至少 100 RC币才可运行的大型工作流",
        "isOfficial": True,
        "isActive": True
    }
    r = client.post("/api/workflows", json=wf_payload, headers=headers_admin)
    assert r.status_code == 200, f"Admin workflow create failed: {r.text}"
    print(" [PASS] Admin successfully configured workflow threshold: minPointsEnabled=True, minPoints=100")
    
    # Verify in GET /api/workflows
    r = client.get("/api/workflows", headers=headers_poor)
    assert r.status_code == 200
    wfs = r.json()
    wf_found = next((w for w in wfs if w.get("name") == "高门槛视频渲染工作流"), None)
    assert wf_found is not None
    assert wf_found["minPointsEnabled"] is True
    assert wf_found["minPoints"] == 100
    print(" [PASS] User GET /api/workflows returns threshold parameters correctly (masked virtual ID: " + wf_found["id"] + ")")
    
    print("--- 3. Testing Execution Validation (P0-1 & Threshold Block) ---")
    gen_payload = {
        "workflowId": wf_found["id"],
        "taskType": "standard",
        "nodeOverrides": {}
    }
    
    # Anonymous -> 401
    r = client.post("/api/generate", json=gen_payload)
    assert r.status_code == 401, f"Anonymous should get 401, got {r.status_code}: {r.text}"
    print(" [PASS] Anonymous user /api/generate blocked with 401")
    
    # User Poor (30 points < 100 threshold) -> 402 Payment Required
    r = client.post("/api/generate", json=gen_payload, headers=headers_poor)
    assert r.status_code == 402, f"Poor user should get 402, got {r.status_code}: {r.text}"
    detail = r.json()["detail"]
    assert "准入门槛" in detail and "100" in detail
    print(f" [PASS] Poor user (30 RC) correctly blocked: {detail}")
    
    # Admin (bypass threshold)
    r = client.post("/api/generate", json=gen_payload, headers=headers_admin)
    assert r.status_code != 402, f"Admin should not be blocked by 402 threshold, got {r.status_code}: {r.text}"
    print(f" [PASS] Admin exempted from workflow threshold check (HTTP {r.status_code})")
    
    print("--- 4. Toggle Threshold OFF and Re-test ---")
    wf_payload["minPointsEnabled"] = False
    r = client.post("/api/workflows", json=wf_payload, headers=headers_admin)
    assert r.status_code == 200
    
    # When threshold disabled, poor user (30 points >= 5 standard start threshold) is not blocked by 402
    r = client.post("/api/generate", json=gen_payload, headers=headers_poor)
    assert r.status_code != 402, f"When disabled, poor user should not get 402, got {r.status_code}: {r.text}"
    print(f" [PASS] When threshold is disabled, 402 block is lifted (HTTP {r.status_code})")
    
    print("--- 5. Overdraw Cap at 0 Test ---")
    u = get_user_by_id(user_poor["id"])
    cur = u["points"]
    # Attempt to deduct 500 points when user only has cur
    success, rem, msg = db_deduct_user_points(user_poor["id"], 500, reason="Huge task settlement")
    assert success is True
    u_after = get_user_by_id(user_poor["id"])
    assert u_after["points"] == 0, f"User points should be exactly 0, got {u_after['points']}"
    print(" [PASS] Overdraw capped at 0, no free ride, no negative balance!")
    
    # Clean up test workflow
    cfg = load_config()
    cfg["workflows"] = [w for w in cfg.get("workflows", []) if w["id"] != "wf_test_threshold_01"]
    save_config(cfg)
    
    print("\n==================================================")
    print(" ALL WORKFLOW THRESHOLD & BILLING TESTS PASSED! ")
    print("==================================================")

if __name__ == "__main__":
    test_workflow_threshold_flow()
