import os
import time
import json
import asyncio
import requests
from typing import Optional, Dict, Any, List
from fastapi import APIRouter, HTTPException, Depends, UploadFile, File
from pydantic import BaseModel, Field

from core.config import (
    load_config, save_config, get_active_api_key,
    filter_workflows_for_user, sort_workflows, resolve_real_workflow_id, RUNNINGHUB_API_URL,
    DATA_DIR
)
from core.auth import get_current_user_optional, get_current_admin
from core.http_client import HTTP_SESSION
from services.workflow_service import (
    parse_nodes_to_dynamic_schema, get_cached_object_info,
    convert_ui_workflow_to_prompt, build_visual_graph
)

router = APIRouter(tags=["Workflows"])

class WorkflowModel(BaseModel):
    id: str
    originalId: Optional[str] = None
    name: str
    description: Optional[str] = ""
    category: Optional[str] = "官方预设"
    pointsCost: Optional[int] = Field(5, ge=0)
    defaultParams: Optional[Dict[str, Any]] = None
    isOfficial: Optional[bool] = None
    isActive: Optional[bool] = True
    isPinned: Optional[bool] = False
    coverImage: Optional[str] = ""
    instanceType: Optional[str] = "plus"
    customPrompt: Optional[Dict[str, Any]] = None
    minPointsEnabled: Optional[bool] = False
    minPoints: Optional[int] = Field(50, ge=0)

@router.get("/api/workflows")
def get_workflows(current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)):
    """获取工作流列表（具备多租户隔离与置顶排序）"""
    cfg = load_config()
    return filter_workflows_for_user(cfg.get("workflows", []), current_user)

@router.post("/api/workflows")
def add_or_update_workflow(wf: WorkflowModel, current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)):
    """添加或修改工作流（支持修改工作流 ID，具备租户隔离与官方工作流防篡改防护）"""
    cfg = load_config()
    workflows = cfg.get("workflows", [])
    is_admin = current_user and current_user.get("role") == "admin"
    
    target_id = str(wf.id).strip()
    lookup_id = str(wf.originalId).strip() if wf.originalId else target_id
    
    existing_idx = None
    existing_wf = None
    for i, w in enumerate(workflows):
        if str(w.get("id")) == lookup_id:
            existing_idx = i
            existing_wf = w
            break

    # 查重：防止新修改的 ID 与其他已有工作流冲突
    for i, w in enumerate(workflows):
        if i != existing_idx and str(w.get("id")) == target_id:
            raise HTTPException(status_code=400, detail=f"工作流 ID '{target_id}' 已被其他工作流占用，请更换不同 ID")
            
    wf_data = wf.dict()
    wf_data.pop("originalId", None)
    wf_data["id"] = target_id
    wf_data["updatedAt"] = int(time.time())
    wf_data["minPointsEnabled"] = bool(wf.minPointsEnabled)
    wf_data["minPoints"] = max(0, int(wf.minPoints or 0))
    
    if not is_admin:
        if not current_user:
            raise HTTPException(status_code=401, detail="请先登录后再保存自定义工作流")
            
        if existing_wf:
            if existing_wf.get("isOfficial"):
                raise HTTPException(status_code=403, detail="【官方预设工作流】受全平台保护，仅限管理员修改")
            if str(existing_wf.get("ownerId", "")) != str(current_user["id"]):
                raise HTTPException(status_code=403, detail="无权修改其他用户的私有工作流")
                
        wf_data["isOfficial"] = False
        wf_data["ownerId"] = str(current_user["id"])
        wf_data["ownerName"] = str(current_user.get("username", "用户"))
        wf_data["isActive"] = True
        wf_data["isPinned"] = False
        # 普通用户自建工作流默认计费不可低于 5 点，防止私自设为 0 点白嫖算力
        wf_data["pointsCost"] = max(5, int(wf_data.get("pointsCost") or 5))
        if not wf_data.get("category") or wf_data.get("category") == "官方预设":
            wf_data["category"] = "我的自建"
    else:
        if wf_data.get("isOfficial") is None:
            wf_data["isOfficial"] = existing_wf.get("isOfficial", True) if existing_wf else True
        if wf_data.get("isOfficial"):
            wf_data["ownerId"] = None
            wf_data["ownerName"] = "系统官方"
        else:
            if existing_wf and existing_wf.get("ownerId"):
                wf_data["ownerId"] = existing_wf["ownerId"]
                wf_data["ownerName"] = existing_wf.get("ownerName", "用户")
            else:
                wf_data["ownerId"] = str(current_user["id"]) if current_user else "admin"
                wf_data["ownerName"] = current_user.get("username", "管理员") if current_user else "管理员"
                
    if existing_idx is not None:
        merged = dict(existing_wf)
        for k, v in wf_data.items():
            if v is not None:
                merged[k] = v
        merged["id"] = target_id
        workflows[existing_idx] = merged
        result_wf = merged
    else:
        workflows.append(wf_data)
        result_wf = wf_data
        
    cfg["workflows"] = workflows
    save_config(cfg)
    return {"status": "ok", "workflow": result_wf}

@router.delete("/api/workflows/{workflow_id}")
def delete_workflow(workflow_id: str, current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)):
    """删除工作流（防越权：普通用户只能删除自己的工作流，禁止删除官方工作流）"""
    cfg = load_config()
    workflows = cfg.get("workflows", [])
    target = next((w for w in workflows if str(w.get("id")) == str(workflow_id)), None)
    if not target:
        raise HTTPException(status_code=404, detail="工作流不存在")
        
    is_admin = current_user and current_user.get("role") == "admin"
    if not is_admin:
        if not current_user:
            raise HTTPException(status_code=401, detail="请先登录后再进行操作")
        if target.get("isOfficial"):
            raise HTTPException(status_code=403, detail="【官方预设工作流】全平台受保护，仅限管理员下架或删除")
        if str(target.get("ownerId", "")) != str(current_user["id"]):
            raise HTTPException(status_code=403, detail="无权删除非本人的私有工作流")
            
    cfg["workflows"] = [w for w in workflows if str(w.get("id")) != str(workflow_id)]
    save_config(cfg)
    return {"status": "ok", "message": f"工作流 {workflow_id} 已成功删除"}

@router.get("/api/admin/workflows")
def admin_list_workflows(_: Dict[str, Any] = Depends(get_current_admin)):
    cfg = load_config()
    raw_wfs = cfg.get("workflows", [])
    for w in raw_wfs:
        if "isActive" not in w:
            w["isActive"] = True
    return sort_workflows(raw_wfs)

@router.delete("/api/admin/workflows/{workflow_id}")
def admin_delete_workflow(workflow_id: str, _: Dict[str, Any] = Depends(get_current_admin)):
    """管理员强制删除工作流"""
    cfg = load_config()
    workflows = cfg.get("workflows", [])
    target = next((w for w in workflows if str(w.get("id")) == str(workflow_id)), None)
    if not target:
        raise HTTPException(status_code=404, detail="工作流不存在")
    cfg["workflows"] = [w for w in workflows if str(w.get("id")) != str(workflow_id)]
    save_config(cfg)
    return {"status": "ok", "message": f"工作流 {workflow_id} 已成功删除"}

@router.post("/api/admin/workflows/{workflow_id}/toggle-active")
def admin_toggle_workflow_active(workflow_id: str, _: Dict[str, Any] = Depends(get_current_admin)):
    cfg = load_config()
    workflows = cfg.get("workflows", [])
    target = next((w for w in workflows if str(w.get("id")) == str(workflow_id)), None)
    if not target:
        raise HTTPException(status_code=404, detail="工作流不存在")
    target["isActive"] = not bool(target.get("isActive", True))
    target["updatedAt"] = int(time.time())
    save_config(cfg)
    return {"status": "ok", "workflow": target, "isActive": target["isActive"]}

@router.post("/api/admin/workflows/{workflow_id}/toggle-pin")
def admin_toggle_workflow_pin(workflow_id: str, _: Dict[str, Any] = Depends(get_current_admin)):
    cfg = load_config()
    workflows = cfg.get("workflows", [])
    target = next((w for w in workflows if str(w.get("id")) == str(workflow_id)), None)
    if not target:
        raise HTTPException(status_code=404, detail="工作流不存在")
    is_pinned = not bool(target.get("isPinned", False))
    target["isPinned"] = is_pinned
    target["pinnedAt"] = int(time.time()) if is_pinned else 0
    target["updatedAt"] = int(time.time())
    save_config(cfg)
    return {"status": "ok", "workflow": target, "isPinned": target["isPinned"]}

@router.post("/api/admin/workflows/{workflow_id}/toggle-official")
def admin_toggle_workflow_official(workflow_id: str, _: Dict[str, Any] = Depends(get_current_admin)):
    cfg = load_config()
    workflows = cfg.get("workflows", [])
    target = next((w for w in workflows if str(w.get("id")) == str(workflow_id)), None)
    if not target:
        raise HTTPException(status_code=404, detail="工作流不存在")
    is_off = not bool(target.get("isOfficial", False))
    target["isOfficial"] = is_off
    if is_off:
        target["ownerId"] = None
        target["ownerName"] = "系统官方"
        if not target.get("category") or target.get("category") == "我的自建":
            target["category"] = "官方预设"
    target["updatedAt"] = int(time.time())
    save_config(cfg)
    return {"status": "ok", "workflow": target, "isOfficial": target["isOfficial"]}

PRESET_SCHEMAS_PATH = os.path.join(DATA_DIR, "preset_workflow_schemas.json")
_PRESET_SCHEMAS_CACHE: Dict[str, Any] = {}

def get_preset_workflow_schema(wf_id: str) -> Optional[Dict[str, Any]]:
    global _PRESET_SCHEMAS_CACHE
    if not _PRESET_SCHEMAS_CACHE and os.path.exists(PRESET_SCHEMAS_PATH):
        try:
            with open(PRESET_SCHEMAS_PATH, "r", encoding="utf-8") as f:
                _PRESET_SCHEMAS_CACHE = json.load(f)
        except Exception as e:
            print(f"[Workflow Schema] Failed to load preset schemas: {e}")
    target_id = str(wf_id).strip()
    return _PRESET_SCHEMAS_CACHE.get(target_id)

def save_preset_workflow_schema(wf_id: str, schema_data: Dict[str, Any]):
    global _PRESET_SCHEMAS_CACHE
    target_id = str(wf_id).strip()
    _PRESET_SCHEMAS_CACHE[target_id] = schema_data
    try:
        with open(PRESET_SCHEMAS_PATH, "w", encoding="utf-8") as f:
            json.dump(_PRESET_SCHEMAS_CACHE, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[Workflow Schema] Failed to persist schema: {e}")

@router.post("/api/workflows/inspect")
def inspect_workflow_endpoint(payload: Dict[str, Any]):
    """通过 RunningHub OpenAPI 实时动态拉取工作流的 ComfyUI 原始结构并做深度动态提取"""
    workflow_id = payload.get("workflowId")
    if not workflow_id:
        raise HTTPException(status_code=400, detail="Missing workflowId")
    
    cfg = load_config()
    real_workflow_id = resolve_real_workflow_id(workflow_id, cfg)
    api_key = payload.get("apiKey") or get_active_api_key(cfg)

    # 1. 如果已配置 API Key，始终优先向 RunningHub 实时动态拉取（保证新上传/新修改的工作流参数即时生效）
    if api_key:
        url = f"{RUNNINGHUB_API_URL}/api/openapi/getJsonApiFormat"
        try:
            res = HTTP_SESSION.post(url, json={"apiKey": api_key, "workflowId": str(real_workflow_id)}, timeout=15)
            raw_data = res.json()
            if raw_data.get("code") == 0:
                prompt_str = raw_data.get("data", {}).get("prompt", "{}")
                try:
                    nodes = json.loads(prompt_str)
                except Exception:
                    nodes = {}

                parsed = parse_nodes_to_dynamic_schema(nodes, cfg)
                visual_graph = build_visual_graph(nodes, set(parsed.get("hiddenAuxiliaryNodeIds") or []))
                result = {
                    "status": "ok",
                    "workflowId": str(workflow_id),
                    "totalNodes": len(nodes),
                    "rawPrompt": nodes,
                    "visualGraph": visual_graph,
                    "hiddenAuxiliaryNodeIds": parsed["hiddenAuxiliaryNodeIds"],
                    "dynamicSchema": parsed["dynamicSchema"]
                }
                # 动态刷新持久化缓存以备容灾
                save_preset_workflow_schema(str(real_workflow_id), result)
                return result
            else:
                err_msg = str(raw_data.get("msg") or "获取工作流信息失败")
                if "WORKFLOW_NOT_SAVED" in err_msg.upper() or "NOT_RUNNING" in err_msg.upper():
                    err_msg = "该工作流在 RunningHub 上尚未保存或未运行过：请在 RunningHub 网页版画布左上角点击【保存 (Alt+S)】或先运行一次，云端即可同步编译并开放 API 格式！"
                # 云端报错时，若是预置工作流则尝试降级，新工作流则准确抛出错误
                fallback = get_preset_workflow_schema(real_workflow_id) or get_preset_workflow_schema(str(workflow_id))
                if fallback:
                    res = dict(fallback)
                    res["workflowId"] = str(workflow_id)
                    return res
                raise HTTPException(status_code=400, detail=err_msg)
        except HTTPException:
            raise
        except Exception as e:
            fallback = get_preset_workflow_schema(real_workflow_id) or get_preset_workflow_schema(str(workflow_id))
            if fallback:
                res = dict(fallback)
                res["workflowId"] = str(workflow_id)
                return res
            raise HTTPException(status_code=500, detail=f"连接 RunningHub 失败: {str(e)}")

    # 2. 若当前未配置有效 API Key，预置工作流尝试容灾，新工作流则友好引导进入后台配置
    fallback = get_preset_workflow_schema(real_workflow_id) or get_preset_workflow_schema(str(workflow_id))
    if fallback:
        res = dict(fallback)
        res["workflowId"] = str(workflow_id)
        return res

    raise HTTPException(status_code=400, detail="未配置有效 API Key。请以管理员身份登录管理后台 (/admin.html)，在【API 密钥池】中添加并启用您的 RunningHub 密钥")

@router.post("/api/workflows/parse_json")
async def parse_workflow_json_endpoint(
    file: UploadFile = File(...),
    current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    """用户直接上传本地 ComfyUI 工作流 JSON 文件"""
    cfg = load_config()
    filename = file.filename or "custom_workflow.json"
    content_bytes = await file.read()
    if len(content_bytes) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="工作流 JSON 文件体积过大，最大限制为 10MB")
    try:
        content_text = content_bytes.decode("utf-8")
        raw_json = json.loads(content_text)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"文件不是合法的 JSON 格式: {str(e)}")

    if isinstance(raw_json, dict) and "prompt" in raw_json and isinstance(raw_json["prompt"], dict):
        nodes = raw_json["prompt"]
    elif isinstance(raw_json, dict) and any("class_type" in v for v in raw_json.values() if isinstance(v, dict)):
        nodes = raw_json
    elif isinstance(raw_json, dict) and "nodes" in raw_json and isinstance(raw_json["nodes"], list):
        api_key = get_active_api_key(cfg)
        obj_info = get_cached_object_info(api_key)
        nodes = convert_ui_workflow_to_prompt(raw_json, obj_info)
        if not nodes:
            raise HTTPException(status_code=400, detail="画布工程文件自动转换失败，未识别到有效节点。")
    else:
        raise HTTPException(status_code=400, detail="未能识别出有效的 ComfyUI 工作流节点拓扑，请确保为 ComfyUI 格式 JSON。")

    parsed = parse_nodes_to_dynamic_schema(nodes, cfg)
    visual_graph = build_visual_graph(nodes, set(parsed.get("hiddenAuxiliaryNodeIds") or []))
    return {
        "status": "ok",
        "workflowName": filename,
        "totalNodes": len(nodes),
        "rawPrompt": nodes,
        "customPrompt": nodes,
        "visualGraph": visual_graph,
        "hiddenAuxiliaryNodeIds": parsed["hiddenAuxiliaryNodeIds"],
        "dynamicSchema": parsed["dynamicSchema"]
    }

@router.post("/api/upload")
async def upload_file_to_runninghub(
    file: UploadFile = File(...),
    current_user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
):
    """上传本地图片或视频到 RunningHub，限流最大 30MB 与安全扩展名"""
    cfg = load_config()
    sys_cfg = cfg.get("system", {})
    if sys_cfg.get("requireLoginToGenerate") and not current_user:
        raise HTTPException(status_code=401, detail="当前系统已开启强制登录，请先登录后再上传素材")

    api_key = get_active_api_key(cfg)
    if not api_key:
        raise HTTPException(status_code=400, detail="未配置有效 API Key，请先进入顶部切换或设置中配置启用")

    filename_raw = file.filename or ""
    allowed_image_exts = {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif"}
    allowed_video_exts = {".mp4", ".webm", ".mov"}
    allowed_audio_exts = {".mp3", ".wav", ".flac", ".ogg", ".m4a", ".aac", ".wma", ".opus"}
    allowed_exts = allowed_image_exts | allowed_video_exts | allowed_audio_exts

    ext = os.path.splitext(filename_raw)[1].lower()
    if ext not in allowed_exts:
        raise HTTPException(status_code=400, detail=f"不支持的文件格式: {ext}，支持图像、视频与音频文件")

    MAX_UPLOAD_SIZE = 30 * 1024 * 1024
    chunk_size = 1024 * 512
    total_size = 0
    buffer = bytearray()
    
    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
        total_size += len(chunk)
        if total_size > MAX_UPLOAD_SIZE:
            raise HTTPException(status_code=413, detail="素材文件过大，单文件上传上限为 30MB")
        buffer.extend(chunk)

    file_bytes = bytes(buffer)
    upload_url = "https://www.runninghub.ai/openapi/v2/media/upload/binary"
    headers = {"Authorization": f"Bearer {api_key}"}

    try:
        files = {"file": (filename_raw, file_bytes, file.content_type)}
        res = await asyncio.to_thread(HTTP_SESSION.post, upload_url, headers=headers, files=files, timeout=120)
        resp_data = res.json()
        if resp_data.get("code") == 0:
            data = resp_data.get("data", {})
            inferred_type = "audio" if ext in allowed_audio_exts else ("video" if ext in allowed_video_exts else "image")
            return {
                "status": "ok",
                "fileName": data.get("fileName"),
                "downloadUrl": data.get("download_url"),
                "fileType": data.get("type") or inferred_type
            }
        else:
            raise HTTPException(status_code=400, detail=resp_data.get("msg") or "上传失败")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"上传至 RunningHub 发生异常: {str(e)}")
