import time
from typing import Optional, Dict, Any
from fastapi import APIRouter, Request, HTTPException, Depends
from pydantic import BaseModel

from core.database import (
    db_redeem_cdkey, db_generate_cdkeys, db_list_cdkeys,
    db_void_cdkey, db_delete_cdkey, db_get_unused_cdkeys_export,
    db_get_user_cdkey_history
)
from core.auth import get_current_user, get_current_admin, notify_user

router = APIRouter(tags=["CDKeys"])

_REDEEM_COOLDOWN: Dict[str, float] = {}

class RedeemCDKeyRequest(BaseModel):
    code: str

class GenerateCDKeysRequest(BaseModel):
    points: int
    count: int = 1
    remark: Optional[str] = ""

@router.post("/api/user/redeem-cdkey")
async def user_redeem_cdkey(
    req: RedeemCDKeyRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    clean_code = (req.code or "").strip().upper()
    if not clean_code:
        raise HTTPException(status_code=400, detail="请输入有效的卡密兑换码")

    cooldown_key = f"redeem_cd_{current_user['id']}"
    now_ts = time.time()
    last_attempt = _REDEEM_COOLDOWN.get(cooldown_key, 0)
    if now_ts - last_attempt < 1.5:
        raise HTTPException(status_code=429, detail="操作过于频繁，请稍等 1 秒后再试")
    _REDEEM_COOLDOWN[cooldown_key] = now_ts

    ok, new_balance, msg = db_redeem_cdkey(
        raw_code=clean_code,
        user_id=current_user["id"],
        username=current_user["username"]
    )

    if not ok:
        raise HTTPException(status_code=400, detail=msg)

    await notify_user(
        user_id=current_user["id"],
        event_type="POINTS_UPDATED",
        data={"points": new_balance, "reason": f"卡密兑换到账 ({clean_code})"}
    )

    return {
        "status": "ok",
        "message": msg,
        "newPoints": new_balance,
        "code": clean_code
    }

@router.get("/api/user/cdkey-history")
async def get_my_cdkey_history(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """用户查看自己的卡密核销充值明细流水"""
    history = db_get_user_cdkey_history(current_user["id"])
    return {
        "status": "ok",
        "history": history
    }

@router.post("/api/admin/cdkeys/generate")
async def admin_generate_cdkeys(
    req: GenerateCDKeysRequest,
    _: Dict[str, Any] = Depends(get_current_admin)
):
    if req.points <= 0:
        raise HTTPException(status_code=400, detail="卡密面额点数必须大于 0")
    if req.count <= 0 or req.count > 500:
        raise HTTPException(status_code=400, detail="单次生成数量必须在 1 ~ 500 张之间")

    codes = db_generate_cdkeys(
        points=req.points,
        count=req.count,
        remark=req.remark or ""
    )

    return {
        "status": "ok",
        "count": len(codes),
        "points": req.points,
        "remark": req.remark or "",
        "codes": codes
    }

@router.get("/api/admin/cdkeys")
async def admin_list_cdkeys(
    status: Optional[str] = "ALL",
    page: Optional[int] = 1,
    pageSize: Optional[int] = 50,
    search: Optional[str] = "",
    _: Dict[str, Any] = Depends(get_current_admin)
):
    return db_list_cdkeys(
        status_filter=status or "ALL",
        page=max(1, int(page or 1)),
        page_size=min(200, max(10, int(pageSize or 50))),
        search=search or ""
    )

@router.post("/api/admin/cdkeys/{code}/void")
async def admin_void_cdkey(
    code: str,
    _: Dict[str, Any] = Depends(get_current_admin)
):
    ok = db_void_cdkey(code)
    if not ok:
        raise HTTPException(status_code=400, detail="卡密不存在或已被使用，无法作废")
    return {"status": "ok", "message": f"卡密 {code} 已成功作废"}

@router.delete("/api/admin/cdkeys/{code}")
async def admin_delete_cdkey(
    code: str,
    _: Dict[str, Any] = Depends(get_current_admin)
):
    ok = db_delete_cdkey(code)
    if not ok:
        raise HTTPException(status_code=404, detail="卡密不存在")
    return {"status": "ok", "message": f"卡密 {code} 已删除"}

@router.get("/api/admin/cdkeys/export")
async def admin_export_unused_cdkeys(
    remark: Optional[str] = "",
    _: Dict[str, Any] = Depends(get_current_admin)
):
    items = db_get_unused_cdkeys_export(remark=remark or "")
    text_lines = [item["code"] for item in items]
    return {
        "count": len(items),
        "rawText": "\n".join(text_lines),
        "items": items
    }
