import time
import asyncio
from typing import Tuple, Dict
from core.config import load_config
from core.security import decrypt_key

_ALERTED_KEY_INCIDENTS: Dict[str, float] = {}

def send_admin_alert_email(subject: str, html_body: str) -> Tuple[bool, str]:
    """
    发送系统运维告警邮件至管理员指定邮箱
    支持 SSL (465) 与 TLS (587/25) 协议，密码加密存储
    """
    cfg = load_config()
    smtp_cfg = cfg.get("system", {}).get("smtp", {})
    if not smtp_cfg.get("enabled"):
        return False, "SMTP 邮件告警未开启"
    
    host = (smtp_cfg.get("host") or "").strip()
    port = int(smtp_cfg.get("port") or 465)
    user = (smtp_cfg.get("user") or "").strip()
    enc_pwd = smtp_cfg.get("passwordEncrypted") or ""
    pwd = decrypt_key(enc_pwd) if enc_pwd else ""
    admin_email = (smtp_cfg.get("adminEmail") or "").strip()
    
    if not host or not user or not pwd or not admin_email:
        return False, "SMTP 邮件配置不完整（缺少主机、账号、密码或接收邮箱）"
    
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    from email.header import Header

    msg = MIMEMultipart()
    msg['From'] = Header(f"RunComfyUI 运维管家 <{user}>", 'utf-8')
    msg['To'] = Header(admin_email, 'utf-8')
    msg['Subject'] = Header(subject, 'utf-8')
    msg.attach(MIMEText(html_body, 'html', 'utf-8'))

    try:
        if port == 465:
            server = smtplib.SMTP_SSL(host, port, timeout=12)
        else:
            server = smtplib.SMTP(host, port, timeout=12)
            server.starttls()
        server.login(user, pwd)
        server.sendmail(user, [admin_email], msg.as_string())
        server.quit()
        return True, "告警邮件已成功发送"
    except Exception as e:
        print(f"[SMTP Error] Failed to send alert email: {e}")
        return False, f"邮件发送失败: {str(e)}"

async def async_notify_key_incident(key_id: str, key_name: str, masked_key: str, error_msg: str):
    """异步检测并发送 Key 异常告警邮件（带 4 小时冷却，杜绝频繁轰炸站长邮箱）"""
    now = time.time()
    last_sent = _ALERTED_KEY_INCIDENTS.get(key_id, 0)
    if now - last_sent < 14400:  # 4 小时内不重复发送同一 Key 告警
        return
    _ALERTED_KEY_INCIDENTS[key_id] = now
    
    html = f"""
    <div style="font-family: sans-serif; background-color: #0b0f19; color: #e2e8f0; padding: 24px; border-radius: 16px; max-width: 600px; margin: 0 auto; border: 1px solid #334155;">
      <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 16px;">
        <span style="font-size: 24px;">🚨</span>
        <h2 style="margin: 0; color: #f43f5e; font-size: 20px;">RunningHub 算力账号异常熔断告警</h2>
      </div>
      <p style="font-size: 14px; line-height: 1.6; color: #cbd5e1;">
        尊敬的管理员，系统在任务调度/自动巡检中检测到底层 API Key 出现致命异常，<b>已自动将其移出派单队列（熔断隔离）</b>。
      </p>
      <div style="background-color: #1e293b; padding: 16px; border-radius: 12px; margin: 16px 0; font-size: 13px;">
        <p style="margin: 6px 0;"><b>异常账号名称：</b> <span style="color: #38bdf8;">{key_name}</span></p>
        <p style="margin: 6px 0;"><b>Key 标识与掩码：</b> <code style="color: #a78bfa;">{key_id} ({masked_key})</code></p>
        <p style="margin: 6px 0;"><b>官方具体报错：</b> <span style="color: #f43f5e; font-family: monospace;">{error_msg}</span></p>
        <p style="margin: 6px 0;"><b>检测告警时间：</b> {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())}</p>
      </div>
      <div style="background-color: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); padding: 12px; border-radius: 10px; font-size: 12px; color: #34d399;">
        🛡️ <b>用户体验保护说明：</b><br>
        系统已自动 PASS 绕过该账号，并将后续用户任务<b>100% 无感故障转移至其他健康 Key</b>，用户端未产生任何封禁报错感知。
      </div>
      <p style="font-size: 12px; color: #94a3b8; margin-top: 20px;">
        建议操作：请登录 RunningHub 官网检查该账号状态（如是否被风控封禁、是否欠费），并在后台控制台更换或恢复该 Key。
      </p>
    </div>
    """
    await asyncio.to_thread(
        send_admin_alert_email,
        f"【紧急运维告警】RunningHub 账号 [{key_name}] 已被自动熔断隔离",
        html
    )
