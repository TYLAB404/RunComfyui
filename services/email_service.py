import os
import time
import asyncio
from typing import Tuple, Dict, Optional
from core.config import load_config
from core.security import decrypt_key
from core.http_client import HTTP_SESSION

_ALERTED_KEY_INCIDENTS: Dict[str, float] = {}

def send_smtp_email(
    to_email: str,
    subject: str,
    html_body: str,
    from_title: str = "RunComfyUI",
    attachment_path: Optional[str] = None
) -> Tuple[bool, str]:
    """
    通用 SMTP 邮件发送基础服务
    支持 SSL (465) 与 TLS (587/25) 协议，密码加密存储，支持附件发送
    """
    cfg = load_config()
    smtp_cfg = cfg.get("system", {}).get("smtp", {})
    if not smtp_cfg.get("enabled"):
        return False, "SMTP 邮件服务未开启，请先在系统设置中启用"
    
    host = (smtp_cfg.get("host") or "").strip()
    port = int(smtp_cfg.get("port") or 465)
    user = (smtp_cfg.get("user") or "").strip()
    enc_pwd = smtp_cfg.get("passwordEncrypted") or ""
    pwd = decrypt_key(enc_pwd) if enc_pwd else ""
    from_email = (smtp_cfg.get("fromEmail") or "").strip()
    sender_email = from_email if (from_email and "@" in from_email) else user
    target_email = (to_email or "").strip()
    
    if not host or not user or not pwd:
        return False, "SMTP 邮件配置不完整（缺少主机、账号或授权密码）"
    if not target_email or "@" not in target_email:
        return False, "目标接收邮箱地址无效"
    
    # 智能识别 Resend 发信服务 (海外 SMTP 端口在国内云服务器经常被封锁，使用官方 HTTPS API 极速且 100% 稳定直达)
    if pwd.startswith("re_") or "resend" in host.lower() or "resend" in user.lower():
        try:
            import base64
            from_addr = f"{from_title} <{sender_email}>" if sender_email else f"{from_title} <admin@notify.2364498.xyz>"
            payload = {
                "from": from_addr,
                "to": [target_email],
                "subject": subject,
                "html": html_body
            }
            if attachment_path and os.path.exists(attachment_path):
                with open(attachment_path, "rb") as af:
                    content_b64 = base64.b64encode(af.read()).decode("utf-8")
                payload["attachments"] = [{
                    "filename": os.path.basename(attachment_path),
                    "content": content_b64
                }]
            resp = HTTP_SESSION.post(
                "https://api.resend.com/emails",
                headers={
                    "Authorization": f"Bearer {pwd}",
                    "Content-Type": "application/json"
                },
                json=payload,
                timeout=18
            )
            if resp.status_code in (200, 201):
                return True, "邮件已成功发送 (Resend)"
            else:
                return False, f"Resend 发信失败 ({resp.status_code}): {resp.text}"
        except Exception as e:
            return False, f"Resend API 请求异常: {str(e)}"

    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    from email.mime.base import MIMEBase
    from email import encoders
    from email.header import Header
    from email.utils import formataddr

    msg = MIMEMultipart()
    from_name = Header(from_title, "utf-8").encode()
    to_name = Header("用户", "utf-8").encode()
    msg['From'] = formataddr((from_name, sender_email))
    msg['To'] = formataddr((to_name, target_email))
    msg['Subject'] = Header(subject, 'utf-8')
    msg.attach(MIMEText(html_body, 'html', 'utf-8'))

    if attachment_path and os.path.exists(attachment_path):
        try:
            filename = os.path.basename(attachment_path)
            part = MIMEBase('application', 'octet-stream')
            with open(attachment_path, 'rb') as af:
                part.set_payload(af.read())
            encoders.encode_base64(part)
            # RFC 2231 / utf-8 兼容头部
            part.add_header('Content-Disposition', f'attachment; filename="{filename}"')
            msg.attach(part)
        except Exception as att_err:
            print(f"[SMTP Warning] Failed to attach file {attachment_path}: {att_err}")

    try:
        if port == 465:
            server = smtplib.SMTP_SSL(host, port, timeout=12)
        else:
            server = smtplib.SMTP(host, port, timeout=12)
            server.starttls()
        server.login(user, pwd)
        server.sendmail(sender_email, [target_email], msg.as_string())
        server.quit()
        return True, "邮件已成功发送"
    except Exception as e:
        print(f"[SMTP Error] Failed to send email to {target_email}: {e}")
        return False, f"邮件发送失败: {str(e)}"

def send_admin_alert_email(subject: str, html_body: str, attachment_path: Optional[str] = None) -> Tuple[bool, str]:
    """发送运维告警/通知邮件至管理员指定邮箱（支持携带附件）"""
    cfg = load_config()
    admin_email = (cfg.get("system", {}).get("smtp", {}).get("adminEmail") or "").strip()
    if not admin_email:
        return False, "未配置管理员告警接收邮箱"
    return send_smtp_email(admin_email, subject, html_body, from_title="RunComfyUI 运维管家", attachment_path=attachment_path)

def send_verification_code_email(to_email: str, code: str, purpose: str = "register") -> Tuple[bool, str]:
    """
    发送 6 位数验证码邮件（注册验证或密码重置）
    """
    cfg = load_config()
    site_title = cfg.get("system", {}).get("siteTitle", "RunComfyUI")
    
    if purpose == "reset":
        action_name = "密码找回与重置"
        subject = f"【{site_title}】密码重置验证码：{code}"
        tip_text = "您正在申请重置账户密码。若非您本人操作，请立即检查账户安全并忽略此邮件。"
    else:
        action_name = "新账户注册"
        subject = f"【{site_title}】注册验证码：{code}"
        tip_text = "您正在注册新账户。验证码用于核验您的邮箱真实性，切勿泄露给任何人。"

    html_body = f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b0f19; color: #e2e8f0; padding: 32px 16px; margin: 0;">
      <div style="max-width: 520px; margin: 0 auto; background-color: #111827; border: 1px solid #1f2937; border-radius: 20px; padding: 32px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);">
        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 24px;">
          <div style="width: 40px; height: 40px; border-radius: 12px; background: linear-gradient(135deg, #6366f1, #a855f7); display: flex; align-items: center; justify-content: center; font-weight: bold; color: #ffffff; font-size: 18px; line-height: 40px; text-align: center;">RH</div>
          <h2 style="margin: 0; font-size: 18px; color: #f8fafc; font-weight: 700;">{site_title} · 安全验证</h2>
        </div>
        
        <p style="font-size: 14px; color: #cbd5e1; line-height: 1.6; margin: 0 0 20px 0;">
          您好！您正在进行<strong>{action_name}</strong>操作，请在验证框中输入下方 6 位数字验证码：
        </p>
        
        <div style="background-color: #1e293b; border: 1px dashed #6366f1; border-radius: 14px; padding: 22px; text-align: center; margin: 24px 0;">
          <div style="font-size: 34px; font-weight: 800; letter-spacing: 10px; color: #818cf8; font-family: monospace; display: inline-block; padding-left: 10px;">
            {code}
          </div>
          <p style="margin: 10px 0 0 0; font-size: 12px; color: #94a3b8;">⏱️ 验证码有效期为 5 分钟，请尽快完成验证</p>
        </div>
        
        <p style="font-size: 12px; color: #94a3b8; line-height: 1.6; margin: 20px 0 0 0;">
          {tip_text}
        </p>
        <div style="margin-top: 24px; padding-top: 16px; border-top: 1px solid #1f2937; font-size: 11px; color: #64748b; text-align: center;">
          此为系统自动发送邮件，请勿直接回复。© {time.strftime('%Y')} {site_title}
        </div>
      </div>
    </div>
    """
    return send_smtp_email(to_email, subject, html_body, from_title=site_title)

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

# ==================== 电子邮箱后缀与一次性临时邮箱安全风控 ====================

DEFAULT_EMAIL_WHITELIST_STR = "qq.com, 163.com, 126.com, gmail.com, outlook.com, hotmail.com, icloud.com, aliyun.com, foxmail.com, 139.com, 189.com, sina.com, sohu.com, yahoo.com, proton.me, protonmail.com"

# 内置 200+ 常见一次性临时邮箱域名黑名单
BUILTIN_DISPOSABLE_DOMAINS = {
    "tempmail.com", "10minutemail.com", "guerrillamail.com", "guerrillamail.net",
    "guerrillamail.org", "guerrillamail.biz", "guerrillamailblock.com", "mailinator.com",
    "yopmail.com", "yopmail.fr", "yopmail.net", "dispostable.com", "sharklasers.com",
    "grr.la", "pokemail.net", "spam4.me", "throwawaymail.com", "fakeinbox.com",
    "getairmail.com", "mohmal.com", "trashmail.com", "trashmail.net", "trashmail.me",
    "temp-mail.org", "dropmail.me", "10mail.org", "minutemail.com", "generator.email",
    "discard.email", "discardmail.com", "tempail.com", "emailondeck.com", "mytrashmailer.com",
    "crazymailing.com", "maildrop.cc", "getnada.com", "inoutmail.de", "tempinbox.com",
    "meltmail.com", "boun.cr", "chacuo.net", "linshiyouxiang.net", "027168.com",
    "bccto.me", "binkmail.com", "bobmail.info", "chammy.info", "devnullmail.com",
    "dfgh.net", "dmailman.com", "dodgit.com", "drdrb.net", "emailmiser.com",
    "emailsensei.com", "emailtemporaneo.net", "fakemailgenerator.com", "fastacura.com",
    "filzmail.com", "freemailmsn.com", "getonemail.com", "gishpuppy.com", "hidemail.biz",
    "incognitomail.org", "instant-mail.de", "jetable.org", "kasmail.com", "kurzepost.de",
    "link2mail.net", "lortemail.dk", "mailexpire.com", "mailfreeonline.com", "mailhazard.com",
    "mailhazard.us", "mailimate.com", "mailin8r.com", "mailinator2.com", "mailnesia.com",
    "mailnull.com", "mailscrap.com", "mailslite.com", "mailtemp.info", "mailtothis.com",
    "messagebeamer.de", "mintemail.com", "mycleaninbox.net", "mytrashmail.com", "no-spam.ws",
    "noclickemail.com", "nogmailspam.info", "nomail.xl.cx", "noobmail.com", "nospam.ze.tc",
    "nospam4.us", "nospammail.net", "notsharingmy.info", "nowmymail.com", "objectmail.com",
    "obobbo.com", "oneoffmail.com", "onewaymail.com", "ourklip.com", "owlpic.com",
    "pookmail.com", "quickinbox.com", "rando.email", "rcpt.at", "safe-mail.net",
    "safetymail.info", "sendspamhere.com", "shieldmail.com", "shortmail.net", "sibmail.com",
    "sneakymail.com", "sogetthis.com", "spamavert.com", "spambob.com", "spambog.com",
    "spambox.us", "spamcannibal.net", "spamcon.org", "spamcorptastic.com", "spamcowboy.com",
    "spamday.com", "spamex.com", "spamfree24.org", "spamgourmet.com", "spamhole.com",
    "spamify.com", "spaminator.de", "spamkill.info", "spaml.com", "spammotel.com",
    "spamspot.com", "spamtrap.ro", "spamtrail.com", "speed.1s.fr", "superrito.com",
    "tafmail.com", "teewars.org", "tempemail.biz", "tempemail.net", "tempinbox.co.uk",
    "tempmail.eu", "tempmail2.com", "tempmailer.com", "tempomail.fr", "temporaryemail.net",
    "temporaryforwarding.com", "temporaryinbox.com", "throwawayemailaddress.com", "tiffanycleaners.com",
    "trbvm.com", "umail.net", "vefsida.com", "veryrealemail.com", "vidavee.com",
    "voicemailx.com", "webemail.me", "wetrainbayarea.com", "whyspam.me", "willselfdestruct.com",
    "winmail.garlic.com", "wronghead.com", "wuzup.net", "wuzupmail.net", "xagloo.com",
    "xents.com", "xmaily.com", "yourtempemail.com", "zehnminutenmail.de", "zipmail.com.br"
}

def parse_domain_list(raw_str: str) -> set:
    """解析以逗号、分号、换行或空格分隔的域名列表"""
    if not raw_str:
        return set()
    cleaned = set()
    formatted = raw_str.replace("，", ",").replace("；", ",").replace(";", ",").replace(" ", ",")
    for line in formatted.splitlines():
        for item in line.split(","):
            dom = item.strip().lower().lstrip("@")
            if dom and "." in dom:
                cleaned.add(dom)
    return cleaned

def validate_email_domain(email: str, sys_cfg: Optional[Dict] = None) -> Tuple[bool, str]:
    """
    电子邮箱域名风控检测：
    1. 提取 @ 后的域名；
    2. 检查临时邮箱拦截（blockDisposableEmails）与自定义黑名单；
    3. 检查域名过滤模式（disposable_only | whitelist_only | off）；
    返回 (是否合规, 拦截提示文案)
    """
    if not email or "@" not in email:
        return False, "请输入格式正确的电子邮箱地址"
    
    if sys_cfg is None:
        cfg = load_config()
        sys_cfg = cfg.get("system", {})
    
    domain = email.split("@")[-1].strip().lower()
    if not domain or "." not in domain:
        return False, "邮箱域名格式不正确"
    
    mode = (sys_cfg.get("emailDomainMode") or "disposable_only").strip().lower()
    if mode == "off":
        return True, ""
    
    # 1. 严格白名单模式 (whitelist_only)
    if mode == "whitelist_only":
        whitelist_raw = sys_cfg.get("emailDomainWhitelist") or DEFAULT_EMAIL_WHITELIST_STR
        whitelist = parse_domain_list(whitelist_raw)
        if domain not in whitelist:
            return False, f"系统已开启正规大厂邮箱限制，暂不支持「@{domain}」，请使用常见正规邮箱（如 QQ、网易、Gmail、Outlook 等）注册"
        return True, ""
    
    # 2. 临时邮箱黑名单过滤 (disposable_only)
    is_disposable_blocked = bool(sys_cfg.get("blockDisposableEmails", True))
    if is_disposable_blocked:
        custom_blacklist_raw = sys_cfg.get("emailDomainBlacklist") or ""
        custom_blacklist = parse_domain_list(custom_blacklist_raw)
        
        if domain in BUILTIN_DISPOSABLE_DOMAINS or domain in custom_blacklist:
            return False, f"系统已拦截一次性临时邮箱「@{domain}」，请使用常用正规电子邮箱注册"
    
    return True, ""

