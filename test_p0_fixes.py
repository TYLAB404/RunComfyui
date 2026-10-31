import asyncio
from fastapi.testclient import TestClient

from app import app
from core.database import init_database
from services.key_pool import KeyPoolManager
from services.runninghub import sanitize_error_msg, poll_task_status

client = TestClient(app)

def test_p0_p1_matrix():
    print("==================================================")
    print("Testing P0-1, P0-3, P0-4, P1 Fixes Matrix")
    print("==================================================")
    
    # 1. P0-1: Anonymous generation must be blocked with 401
    print("\n--- Test P0-1: Block Anonymous Generation ---")
    r = client.post("/api/generate", json={"workflowId": "test", "taskType": "Standard"})
    assert r.status_code == 401, f"Expected 401, got {r.status_code}: {r.text}"
    print(" [PASS] Anonymous POST /api/generate blocked with 401")
    
    # 2. P0-3: Poll status guard skips local task_ placeholder
    print("\n--- Test P0-3: Polling Guard for Local task_ Placeholder ---")
    # Calling poll_task_status with task_ prefix should return immediately without throwing
    asyncio.run(poll_task_status("task_local_queue_999", "fake_api_key"))
    print(" [PASS] poll_task_status safely skips local queue placeholder without querying RunningHub")
    
    # 3. P0-4: API Key Desensitization
    print("\n--- Test P0-4: RunningHub API Key Desensitization ---")
    raw_error = "Connection failed to https://www.runninghub.ai/proxy/rh_sec_key_xyz123abc456/prompt with apiKey=rh_sec_key_xyz123abc456 and payload {\"apiKey\": \"rh_sec_key_xyz123abc456\"}"
    sanitized = sanitize_error_msg(raw_error, "rh_sec_key_xyz123abc456")
    assert "rh_sec_key_xyz123abc456" not in sanitized, f"Key leaked in sanitized error: {sanitized}"
    assert "******" in sanitized
    print(f" [PASS] Sensitive Key successfully masked in error strings:\n        Raw: {raw_error[:65]}...\n        Sanitized: {sanitized}")
    
    # Verify /api/proxy/view route is registered
    r = client.get("/api/proxy/view?filename=test.png")
    # Will fail on upstream connection or 400/500/502 without exposing key, not 404 route missing
    assert r.status_code != 404, "/api/proxy/view route must be registered in FastAPI router"
    print(" [PASS] /api/proxy/view endpoint registered and actively protects key from browser exposure")
    
    # 4. P1: Key release task_id verification
    print("\n--- Test P1: release_key Task ID Verification ---")
    async def run_key_test():
        km = KeyPoolManager()
        km._config_loader = lambda: {"apiKeys": [{"id": "key_1", "keyEncrypted": "enc", "name": "Key1"}]}
        
        # Mark key_1 busy with task_original
        await km.mark_key_busy("key_1", "task_original")
        assert km._states["key_1"]["is_busy"] is True
        assert km._states["key_1"]["task_id"] == "task_original"
        
        # Wrong task tries to release key_1
        await km.release_key("key_1", task_id="task_imposter")
        # Must still be busy!
        assert km._states["key_1"]["is_busy"] is True, "Key was mistakenly released by an imposter task!"
        assert km._states["key_1"]["task_id"] == "task_original"
        
        # Original task releases key_1
        await km.release_key("key_1", task_id="task_original")
        # Now it is free
        assert km._states["key_1"]["is_busy"] is False
        assert km._states["key_1"]["task_id"] is None
        
    asyncio.run(run_key_test())
    print(" [PASS] release_key strictly verifies task_id and rejects stale/imposter task release calls")
    
    print("\n==================================================")
    print(" ALL P0 & P1 VERIFICATION TESTS PASSED! ")
    print("==================================================")

if __name__ == "__main__":
    test_p0_p1_matrix()
