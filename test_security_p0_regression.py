"""
P0 Security Vulnerability Regression Verification Suite for RunComfyui
Covers:
1. Path traversal denial on /api/gallery/download (Arbitrary File Read)
2. Open redirect denial on /api/gallery/download (Phishing & SSRF)
3. Mandatory authentication on task creation (/api/tasks/run) and billing pre-checks
4. Mandatory authentication on gallery deletion (/api/gallery/{task_id}/{filename})
5. Mandatory authentication on media proxy (/api/proxy/view)
6. Master encryption key exclusion from externalized email backups
"""
import os
import sys
import io
import zipfile

# 强制 UTF-8 输出防 Windows GBK 控制台乱码
if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
from fastapi.testclient import TestClient

# Ensure root path is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app
from services.billing_service import check_user_can_start_task
from services.backup_service import create_backup, validate_backup_zip

client = TestClient(app, follow_redirects=False)


def run_security_regression_tests():
    print("=" * 70)
    print("🛡️  开始 RunComfyUI P0 级严重安全漏洞加固回归自动化测试")
    print("=" * 70)

    # -----------------------------------------------------------------
    # 测试 1: 路径穿越任意文件读取拦截 (Path Traversal 防护)
    # -----------------------------------------------------------------
    print("\n[Test 1] 验证 /api/gallery/download 路径穿越防御...")
    traversal_attacks = [
        "/outputs/../data/app.db",
        "/outputs/../data/.secret.key",
        "/outputs/../data/config.json",
        "/outputs/../backups/runcomfyui_backup_test.zip",
        "/outputs/../../../../etc/passwd",
        "outputs/../../Windows/System32/drivers/etc/hosts"
    ]
    for attack in traversal_attacks:
        resp = client.get(f"/api/gallery/download?url={attack}")
        assert resp.status_code == 403, f"路径穿越未被拦截! URL: {attack}, 返回状态码: {resp.status_code}"
    print("  -> [PASS] 所有跨目录/跳级路径穿越攻击均被严格拦截 (403 Forbidden)")

    # -----------------------------------------------------------------
    # 测试 2: 开放重定向钓鱼攻击拦截 (Open Redirect 防护)
    # -----------------------------------------------------------------
    print("\n[Test 2] 验证 /api/gallery/download 开放重定向与钓鱼拦截...")
    malicious_urls = [
        "https://evil-phishing.com/steal-login",
        "http://attacker.xyz/malware.exe",
        "https://google.com.attacker.com/test",
        "https://runninghub.cn.evil.org/fake.mp4"
    ]
    for mal_url in malicious_urls:
        resp = client.get(f"/api/gallery/download?url={mal_url}")
        assert resp.status_code == 400, f"恶意外部重定向未被拦截! URL: {mal_url}, 返回状态码: {resp.status_code}"
    
    # 验证受信任官方白名单域名正常允许 302 重定向
    official_cdn_url = "https://rh-hk-images.xiaoyaoyou.com/temp/valid_output.mp4"
    resp_trusted = client.get(f"/api/gallery/download?url={official_cdn_url}")
    assert resp_trusted.status_code == 302, f"受信任官方 CDN 直链应当返回 302, 实际返回: {resp_trusted.status_code}"
    assert resp_trusted.headers["location"] == official_cdn_url
    print("  -> [PASS] 非受信外部域名跳转 100% 拦截 (400 Bad Request)，官方白名单正常 302 直连")

    # -----------------------------------------------------------------
    # 测试 3: 匿名用户提交任务与计费门禁拦截 (算力盗刷防护)
    # -----------------------------------------------------------------
    print("\n[Test 3] 验证未登录匿名用户无法启动生成任务 (算力盗刷防护)...")
    can_start, pts, msg = check_user_can_start_task(None)
    assert not can_start, f"未登录用户绝不能被放行启动任务! can_start={can_start}"
    assert "未登录" in msg, f"提示信息不明确: {msg}"

    # 模拟外部匿名向 /api/generate 发起 POST 请求
    resp_run = client.post("/api/generate", json={"workflowId": "test_wf", "prompt": "hello"})
    assert resp_run.status_code == 401, f"未登录提交任务必须被拦截为 401, 实际: {resp_run.status_code}"
    print("  -> [PASS] 匿名算力提交被双重熔断彻底拦截 (401 Unauthorized)")

    # -----------------------------------------------------------------
    # 测试 4: 匿名恶意删除他人成果拦截 (画廊越权防护)
    # -----------------------------------------------------------------
    print("\n[Test 4] 验证未登录匿名用户无法软删除他人画廊成果...")
    resp_del = client.delete("/api/gallery/some_fake_task_id/test_image.png")
    assert resp_del.status_code == 401, f"未登录操作删除必须返回 401, 实际: {resp_del.status_code}"
    print("  -> [PASS] 匿名画廊软删除攻击被成功阻断 (401 Unauthorized)")

    # -----------------------------------------------------------------
    # 测试 5: 媒体代理网关防越权与未授权访问
    # -----------------------------------------------------------------
    print("\n[Test 5] 验证 /api/proxy/view 未授权访问与路径遍历...")
    resp_proxy_anon = client.get("/api/proxy/view?filename=test.png")
    assert resp_proxy_anon.status_code == 401, f"匿名媒体代理必须返回 401, 实际: {resp_proxy_anon.status_code}"

    # 模拟路径遍历
    resp_proxy_traversal = client.get("/api/proxy/view?filename=../../secret.key", headers={"Authorization": "Bearer fake_token"})
    assert resp_proxy_traversal.status_code in (400, 401), f"代理路径遍历未被阻断! 返回: {resp_proxy_traversal.status_code}"
    print("  -> [PASS] 媒体代理网关成功限制仅合法用户访问 (401/400)")

    # -----------------------------------------------------------------
    # 测试 6: 备份中主密钥物理隔离 (防止邮件泄露导致全站解密)
    # -----------------------------------------------------------------
    print("\n[Test 6] 验证外发邮件备份中对称主密钥物理脱敏隔离...")
    ok, b_path, meta = create_backup(prefix="test_p0_sec_", include_workflows=False, send_email=True)
    assert ok, f"生成备份失败: {b_path}"
    
    with zipfile.ZipFile(b_path, 'r') as zf:
        file_list = zf.namelist()
        assert "data/app.db" in file_list, "数据库应当被正常备份"
        assert "data/.secret.key" not in file_list, "主密钥绝不能被打包到外发邮件备份包中！"
    
    # 清理测试备份
    if os.path.exists(b_path):
        os.remove(b_path)
    print("  -> [PASS] 邮件外发灾备快照已实现主密钥物理剥离隔离安全策略！")

    print("\n" + "=" * 70)
    print("🏆 恭喜！全部 6 项 P0 级严重安全漏洞加固回归测试 100% 全部通过！")
    print("=" * 70)


if __name__ == "__main__":
    run_security_regression_tests()
