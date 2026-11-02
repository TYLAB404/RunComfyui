"""
P0 Security Vulnerability Regression Verification Suite for RunComfyui
Covers:
1. Path traversal denial on /api/gallery/download (Arbitrary File Read)
2. Narrowed open redirect denial on /api/gallery/download (OSS/COS wildcard phishing elimination)
3. Mandatory authentication on task creation (/api/generate) and billing pre-checks
4. Mandatory authentication on gallery deletion (/api/gallery/{task_id}/{filename})
5. Strict validation & ownership check on media proxy (/api/proxy/view)
6. Master key and .env physical exclusion from externalized email backups
7. Inspection authentication & topology desensitization on /api/workflows/inspect
"""
import os
import sys
import io
import zipfile
import json
from unittest.mock import patch

# 强制 UTF-8 输出防 Windows GBK 控制台乱码
if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Ensure root path is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi.testclient import TestClient
from app import app
from services.billing_service import check_user_can_start_task
from services.backup_service import create_backup
from core.auth import create_jwt_token, get_user_by_id

client = TestClient(app, follow_redirects=False)


def run_security_regression_tests():
    print("=" * 70)
    print("🛡️  开始 RunComfyUI P0/P1 级严重安全漏洞深度加固回归自动化测试")
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
        "/outputs/..%2f..%2fdata%2fapp.db"
    ]
    for attack in traversal_attacks:
        resp = client.get(f"/api/gallery/download?url={attack}")
        assert resp.status_code == 403, f"路径穿越未被拦截! URL: {attack}, 返回状态码: {resp.status_code}"
    print("  -> [PASS] 所有跨目录/跳级路径穿越攻击均被严格拦截 (403 Forbidden)")

    # -----------------------------------------------------------------
    # 测试 2: 开放重定向钓鱼与泛 OSS/COS 域名拦截 (Open Redirect 防护)
    # -----------------------------------------------------------------
    print("\n[Test 2] 验证 /api/gallery/download 开放重定向与泛云存储后缀拦截...")
    malicious_urls = [
        "https://evil-phishing.com/steal-login",
        "http://attacker.xyz/malware.exe",
        "https://google.com.attacker.com/test",
        "https://runninghub.cn.evil.org/fake.mp4",
        # 重点：验证攻击者自建的阿里云 OSS / 腾讯云 COS 桶跳板已被彻底封杀
        "https://attacker-bucket.oss-cn-hangzhou.aliyuncs.com/malware.exe",
        "https://evil-bucket.cos.ap-guangzhou.myqcloud.com/phishing.html"
    ]
    for mal_url in malicious_urls:
        resp = client.get(f"/api/gallery/download?url={mal_url}")
        assert resp.status_code == 400, f"恶意外部/泛云存储重定向未被拦截! URL: {mal_url}, 返回状态码: {resp.status_code}"
    
    # 验证受信任官方白名单域名正常允许 302 重定向
    official_cdn_url = "https://rh-hk-images.xiaoyaoyou.com/temp/valid_output.mp4"
    resp_trusted = client.get(f"/api/gallery/download?url={official_cdn_url}")
    assert resp_trusted.status_code == 302, f"受信任官方 CDN 直链应当返回 302, 实际返回: {resp_trusted.status_code}"
    assert resp_trusted.headers["location"] == official_cdn_url
    print("  -> [PASS] 非受信外部域名及泛 OSS/COS 域名 100% 拦截 (400 Bad Request)，官方白名单正常 302")

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
    # 测试 5: 媒体代理网关防越权与三元组路径精准校验
    # -----------------------------------------------------------------
    print("\n[Test 5] 验证 /api/proxy/view 未授权访问、路径遍历与非法参数校验...")
    # 未登录
    resp_proxy_anon = client.get("/api/proxy/view?filename=test.png")
    assert resp_proxy_anon.status_code == 401, f"匿名媒体代理必须返回 401, 实际: {resp_proxy_anon.status_code}"

    # 获取一个常规测试用户并签发合法 Token
    test_u = get_user_by_id("usr_a36e8f6b67")
    u_id = test_u["id"] if test_u else "usr_a36e8f6b67"
    u_ver = test_u.get("token_version", 1) if test_u else 1
    normal_token = create_jwt_token({"sub": u_id, "username": "123123", "role": "user", "ver": u_ver})
    auth_headers = {"Authorization": f"Bearer {normal_token}"}

    # 模拟非法路径遍历参数
    resp_proxy_traversal = client.get("/api/proxy/view?filename=../../secret.key", headers=auth_headers)
    assert resp_proxy_traversal.status_code in (400, 403), f"代理路径遍历未被阻断! 返回: {resp_proxy_traversal.status_code}"

    # 模拟非法 type 参数
    resp_proxy_bad_type = client.get("/api/proxy/view?filename=test.png&type=system_root", headers=auth_headers)
    assert resp_proxy_bad_type.status_code == 400, f"非法的 type 参数未被阻断! 返回: {resp_proxy_bad_type.status_code}"

    # 模拟合法用户试图访问未经本人任务生成的未知产物
    resp_proxy_unowned = client.get("/api/proxy/view?filename=unowned_task_file.png", headers=auth_headers)
    assert resp_proxy_unowned.status_code == 403, f"越权拉取他人产物必须返回 403, 实际: {resp_proxy_unowned.status_code}"
    print("  -> [PASS] 媒体代理网关成功实现未登录 401、路径遍历 400、非法类型 400 以及未授权资产 403 严格隔离！")

    # -----------------------------------------------------------------
    # 测试 6: 外发邮件备份中主密钥与 .env 物理隔离 (双保险)
    # -----------------------------------------------------------------
    print("\n[Test 6] 验证外发邮件备份中主密钥与 .env 物理双脱敏隔离...")
    with patch("services.backup_service.send_admin_alert_email", return_value=(True, "Mock mail sent")):
        ok, b_path, meta = create_backup(prefix="test_p0_sec_", include_workflows=False, send_email=True)
    assert ok, f"生成备份失败: {b_path}"
    
    with zipfile.ZipFile(b_path, 'r') as zf:
        file_list = zf.namelist()
        assert "data/app.db" in file_list, "数据库应当被正常备份"
        assert "data/.secret.key" not in file_list, "主密钥绝不能被打包到外发邮件备份包中！"
        assert ".env" not in file_list, "环境配置文件 (.env) 绝不能被打包到外发邮件备份包中！"
    
    # 清理测试备份
    if os.path.exists(b_path):
        os.remove(b_path)
    print("  -> [PASS] 邮件外发灾备快照已实现 .secret.key 与 .env 环境变量物理双隔离！")

    # -----------------------------------------------------------------
    # 测试 7: 工作流底层拓扑探测防护 (/api/workflows/inspect)
    # -----------------------------------------------------------------
    print("\n[Test 7] 验证 /api/workflows/inspect 鉴权门禁与非管理员拓扑脱敏...")
    # 匿名调用拒绝
    resp_inspect_anon = client.post("/api/workflows/inspect", json={"workflowId": "test_wf"})
    assert resp_inspect_anon.status_code == 401, f"未登录调用 inspect 必须返回 401, 实际: {resp_inspect_anon.status_code}"

    # 普通用户调用：必须剔除 rawPrompt 与底层私密拓扑
    resp_inspect_user = client.post("/api/workflows/inspect", json={"workflowId": "non_existent_or_test"}, headers=auth_headers)
    # 无论是返回 fallback 还是 400 (云端未找到)，验证如果是 200 响应，绝不含 rawPrompt
    if resp_inspect_user.status_code == 200:
        data = resp_inspect_user.json()
        assert "rawPrompt" not in data, "非管理员响应中绝对禁止泄露底层 rawPrompt 拓扑！"
    print("  -> [PASS] 工作流节点逆向探针成功加固：匿名 401 拦截，非管理员严格脱敏 rawPrompt！")

    print("\n" + "=" * 70)
    print("🏆 恭喜！全部 7 项 P0/P1 级严重安全漏洞加固与回归测试 100% 全部通过！")
    print("=" * 70)


if __name__ == "__main__":
    run_security_regression_tests()
