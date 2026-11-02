import os
import hmac
import hashlib
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple
import requests

def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

def _get_signature_key(key: str, date_stamp: str, region_name: str, service_name: str) -> bytes:
    k_date = _sign(('AWS4' + key).encode('utf-8'), date_stamp)
    k_region = _sign(k_date, region_name)
    k_service = _sign(k_region, service_name)
    k_signing = _sign(k_service, 'aws4_request')
    return k_signing

def generate_r2_presigned_put_url(
    account_id: str,
    access_key: str,
    secret_key: str,
    bucket_name: str,
    object_key: str,
    content_type: str = "application/octet-stream",
    expires_in: int = 300
) -> str:
    """
    使用纯 Python 标准库生成 AWS SigV4 规范的 Cloudflare R2 预签名上传链接 (PUT)
    零外部重型依赖 (无需 boto3)，毫秒级执行 (纯 CPU 哈希运算，无网络往返)
    """
    region = "auto"
    service = "s3"
    clean_account_id = str(account_id or "").strip()
    clean_bucket = str(bucket_name or "").strip()
    host = f"{clean_account_id}.r2.cloudflarestorage.com"
    endpoint = f"https://{host}"
    
    now = datetime.now(timezone.utc)
    amz_date = now.strftime('%Y%m%dT%H%M%SZ')
    date_stamp = now.strftime('%Y%m%d')
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    
    # 路径部分分段编码，严格保留目录斜杠 '/'
    quoted_parts = [urllib.parse.quote(p, safe='-_.~') for p in object_key.strip('/').split('/')]
    canonical_uri = f"/{clean_bucket}/" + "/".join(quoted_parts)
    
    query_params = {
        'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
        'X-Amz-Credential': f"{access_key.strip()}/{credential_scope}",
        'X-Amz-Date': amz_date,
        'X-Amz-Expires': str(expires_in),
        'X-Amz-SignedHeaders': 'host'
    }
    
    canonical_querystring = '&'.join([
        f"{urllib.parse.quote(k, safe='-_.~')}={urllib.parse.quote(v, safe='-_.~')}" 
        for k, v in sorted(query_params.items())
    ])
    
    canonical_headers = f"host:{host}\n"
    signed_headers = 'host'
    payload_hash = 'UNSIGNED-PAYLOAD'
    
    canonical_request = '\n'.join([
        'PUT',
        canonical_uri,
        canonical_querystring,
        canonical_headers,
        signed_headers,
        payload_hash
    ])
    
    algorithm = 'AWS4-HMAC-SHA256'
    string_to_sign = '\n'.join([
        algorithm,
        amz_date,
        credential_scope,
        hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
    ])
    
    signing_key = _get_signature_key(secret_key.strip(), date_stamp, region, service)
    signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
    
    return f"{endpoint}{canonical_uri}?{canonical_querystring}&X-Amz-Signature={signature}"

def test_r2_connectivity(
    account_id: str,
    access_key: str,
    secret_key: str,
    bucket_name: str,
    public_url: str
) -> Tuple[bool, str]:
    """
    连通性自检：生成临时签名上传 1 字节健康探测包并从 Public URL 读回校验
    """
    try:
        test_key = f"_health_check/{int(datetime.now().timestamp())}_ping.txt"
        upload_url = generate_r2_presigned_put_url(
            account_id, access_key, secret_key, bucket_name, test_key, expires_in=120
        )
        # 上传 1 字节探测
        put_res = requests.put(
            upload_url, 
            data=b"OK", 
            headers={"Content-Type": "text/plain"}, 
            timeout=10
        )
        if put_res.status_code not in (200, 204):
            return False, f"PUT 直传探测失败 (HTTP {put_res.status_code}): {put_res.text[:150]}"
        
        # 检验 Public URL 访问
        clean_pub = public_url.strip().rstrip('/')
        if clean_pub:
            probe_url = f"{clean_pub}/{test_key}"
            get_res = requests.get(probe_url, timeout=10)
            if get_res.status_code != 200:
                return False, f"直传成功，但 Public URL 读回失败 (HTTP {get_res.status_code})，请检查 R2 公开访问开关"
        
        return True, "Cloudflare R2 预签名与公网直链双向测试成功！"
    except Exception as e:
        return False, f"R2 测试发生异常: {str(e)}"
