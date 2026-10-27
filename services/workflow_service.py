import os
import json
import time
import requests
from typing import Dict, Any, Optional, List, Tuple
from core.config import DATA_DIR, RUNNINGHUB_API_URL

OBJECT_INFO_CACHE_PATH = os.path.join(DATA_DIR, "object_info_cache.json")
_MEMORY_OBJECT_INFO: Optional[Dict[str, Any]] = None

def get_cached_object_info(api_key: str) -> Dict[str, Any]:
    """
    获取或缓存 RunningHub 云端全部节点的完整定义（19800+ 节点定义）
    用于在用户上传普通 Web 画布格式工作流时，自动将其无缝编译为标准的 ComfyUI API Prompt 格式
    """
    global _MEMORY_OBJECT_INFO
    if _MEMORY_OBJECT_INFO is not None:
        return _MEMORY_OBJECT_INFO

    # 1. 尝试从本地磁盘缓存加载
    if os.path.exists(OBJECT_INFO_CACHE_PATH):
        try:
            mtime = os.path.getmtime(OBJECT_INFO_CACHE_PATH)
            # 7天内缓存有效
            if time.time() - mtime < 86400 * 7:
                with open(OBJECT_INFO_CACHE_PATH, "r", encoding="utf-8") as f:
                    _MEMORY_OBJECT_INFO = json.load(f)
                    return _MEMORY_OBJECT_INFO
        except Exception:
            pass

    # 2. 从云端 proxy 获取
    if not api_key:
        return {}

    for host in ["www.runninghub.cn", "www.runninghub.ai"]:
        try:
            url = f"https://{host}/proxy/{api_key}/object_info"
            res = requests.get(url, timeout=12)
            if res.status_code == 200:
                data = res.json()
                if isinstance(data, dict) and len(data) > 50:
                    _MEMORY_OBJECT_INFO = data
                    try:
                        with open(OBJECT_INFO_CACHE_PATH, "w", encoding="utf-8") as f:
                            json.dump(data, f, ensure_ascii=False)
                    except Exception:
                        pass
                    return _MEMORY_OBJECT_INFO
        except Exception:
            continue

    return _MEMORY_OBJECT_INFO or {}

def convert_ui_workflow_to_prompt(ui_json: Dict[str, Any], obj_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    将 ComfyUI Web 画布工程文件 (LiteGraph 格式) 自动转换为云端可执行的 API Prompt 格式。
    自动解析并穿透前端虚拟总线节点 (Set_*/Get_* 无线总线节点、Reroute 重定向节点、Primitive 原生数值节点、Note 视觉便签等)。
    """
    nodes = ui_json.get("nodes", [])
    links = ui_json.get("links", [])
    nodes_by_id = {str(n.get("id")): n for n in nodes if n.get("id") is not None}

    # 1. 建立基础 link_id 映射：link_id -> [origin_node_id, origin_slot_index]
    link_map = {}
    for l in links:
        if isinstance(l, (list, tuple)) and len(l) >= 4:
            lid, src_id, src_slot = l[0], str(l[1]), int(l[2])
            link_map[lid] = [src_id, src_slot]

    # 2. 识别与提取虚拟节点元数据
    def extract_var_name(node: dict, prefix: str) -> str:
        ntype = str(node.get("type", "")).strip()
        title = str(node.get("title", "")).strip()
        props = node.get("properties") or {}
        if ntype.lower().startswith(prefix.lower() + "_"):
            return ntype[len(prefix) + 1:].strip()
        if title.lower().startswith(prefix.lower() + "_"):
            return title[len(prefix) + 1:].strip()
        for k in ["name", "var_name", "variable_name", "key"]:
            if props.get(k):
                return str(props[k]).strip()
        wv = node.get("widgets_values")
        if isinstance(wv, list) and len(wv) > 0 and isinstance(wv[0], str) and wv[0].strip():
            return wv[0].strip()
        elif isinstance(wv, dict):
            for k in ["name", "var_name", "variable_name", "key"]:
                if wv.get(k):
                    return str(wv[k]).strip()
        if title and title != ntype and not title.lower().startswith("set") and not title.lower().startswith("get"):
            return title.strip()
        return ""

    def is_virtual_node(node: dict) -> bool:
        ntype = str(node.get("type", "")).strip().lower()
        title = str(node.get("title", "")).strip().lower()
        if ntype == "reroute" or title == "reroute":
            return True
        if ntype.startswith("set_") or ntype.startswith("get_"):
            return True
        if ntype in ["setnode", "getnode", "set", "get"]:
            return True
        if ntype.startswith("primitive"):
            return True
        if ntype in ["note", "markdown", "textnote", "group"]:
            return True
        return False

    reroute_node_map = {}
    for nid, node in nodes_by_id.items():
        ntype = str(node.get("type", "")).strip().lower()
        title = str(node.get("title", "")).strip().lower()
        if ntype == "reroute" or title == "reroute":
            for inp in node.get("inputs", []):
                if inp.get("link") is not None:
                    reroute_node_map[nid] = inp.get("link")
                    break

    get_node_map = {}
    for nid, node in nodes_by_id.items():
        ntype = str(node.get("type", "")).strip().lower()
        if ntype.startswith("get_") or ntype in ["getnode", "get"]:
            get_node_map[nid] = extract_var_name(node, "get")

    wireless_bus = {}
    for nid, node in nodes_by_id.items():
        ntype = str(node.get("type", "")).strip().lower()
        if ntype.startswith("set_") or ntype in ["setnode", "set"]:
            var_name = extract_var_name(node, "set")
            for inp in node.get("inputs", []):
                in_lid = inp.get("link")
                if in_lid is not None:
                    wireless_bus[var_name] = in_lid
                    break

    primitive_node_map = {}
    for nid, node in nodes_by_id.items():
        ntype = str(node.get("type", "")).strip().lower()
        if ntype.startswith("primitive"):
            wv = node.get("widgets_values")
            if isinstance(wv, list) and len(wv) > 0:
                primitive_node_map[nid] = wv[0]

    # 3. 递归穿透解析真实信号源
    def resolve_source(nid: str, slot: int, visited=None):
        if visited is None:
            visited = set()
        if (nid, slot) in visited or len(visited) > 30:
            return [nid, slot]
        visited.add((nid, slot))

        if nid in reroute_node_map:
            in_lid = reroute_node_map[nid]
            if in_lid in link_map:
                up_nid, up_slot = link_map[in_lid]
                return resolve_source(up_nid, up_slot, visited)

        if nid in get_node_map:
            var_name = get_node_map[nid]
            if var_name in wireless_bus:
                in_lid = wireless_bus[var_name]
                if in_lid in link_map:
                    up_nid, up_slot = link_map[in_lid]
                    return resolve_source(up_nid, up_slot, visited)

        return [nid, slot]

    # 4. 全局替换所有连线映射至最终实体节点
    for lid in list(link_map.keys()):
        src_id, src_slot = link_map[lid]
        final_src_id, final_src_slot = resolve_source(src_id, src_slot)
        link_map[lid] = [final_src_id, final_src_slot]

    # 5. 生成 API Prompt 字典
    prompt = {}
    for node in nodes:
        nid = str(node.get("id"))
        ntype = node.get("type")
        if not nid or not ntype:
            continue
        if is_virtual_node(node):
            continue

        inputs = {}
        # A. 关联所有输入连线
        for inp in node.get("inputs", []):
            name = inp.get("name")
            lid = inp.get("link")
            if lid is not None and lid in link_map:
                src_nid, src_slot = link_map[lid]
                if src_nid in primitive_node_map:
                    inputs[name] = primitive_node_map[src_nid]
                else:
                    inputs[name] = [src_nid, src_slot]

        # B. 映射 widgets_values 参数
        w_values = node.get("widgets_values")
        if isinstance(w_values, dict):
            inputs.update(w_values)
        elif isinstance(w_values, list):
            node_def = obj_info.get(ntype, {})
            req_inputs = node_def.get("input", {}).get("required", {})
            opt_inputs = node_def.get("input", {}).get("optional", {})

            def is_widget_type(spec):
                if not isinstance(spec, (list, tuple)) or len(spec) == 0:
                    return False
                t = spec[0]
                if isinstance(t, list):
                    return True
                if isinstance(t, str) and t.upper() in ["INT", "FLOAT", "STRING", "BOOLEAN", "BOOLEAN_NOT"]:
                    return True
                return False

            widget_field_names = []
            for fname, fspec in req_inputs.items():
                if is_widget_type(fspec) and fname not in inputs:
                    widget_field_names.append((fname, fspec))
            for fname, fspec in opt_inputs.items():
                if is_widget_type(fspec) and fname not in inputs:
                    widget_field_names.append((fname, fspec))

            w_idx = 0
            for fname, fspec in widget_field_names:
                if w_idx >= len(w_values):
                    break
                val = w_values[w_idx]
                w_idx += 1
                inputs[fname] = val
                if w_idx < len(w_values) and isinstance(w_values[w_idx], str) and w_values[w_idx] in ["randomize", "fixed", "increment", "decrement"]:
                    w_idx += 1

        prompt[nid] = {
            "class_type": ntype,
            "inputs": inputs,
            "_meta": {"title": node.get("title") or ntype}
        }

    return prompt

def parse_nodes_to_dynamic_schema(nodes: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """从 ComfyUI 节点结构深度动态提取提示词、尺寸、参考图、视频以及全部节点可编辑项"""
    prompt_nodes = []
    sampler_nodes = []
    latent_nodes = []
    image_nodes = []
    video_nodes = []
    audio_nodes = []
    quality_nodes = []
    output_nodes = []
    all_editable_nodes = []

    for nid, node in nodes.items():
        ctype = node.get("class_type", "")
        inputs = node.get("inputs", {})
        meta = node.get("_meta", {})
        title = meta.get("title", ctype)

        fields = []
        for field_name, field_val in inputs.items():
            if isinstance(field_val, list):
                continue
            fields.append({
                "fieldName": field_name,
                "currentValue": field_val,
                "type": type(field_val).__name__
            })

        all_editable_nodes.append({
            "nodeId": str(nid),
            "title": title,
            "classType": ctype,
            "fields": fields
        })

        ctype_lower = ctype.lower()
        title_lower = title.lower()

        # 提示词节点
        if "cliptextencode" in ctype_lower or "prompt" in title_lower or "text" in ctype_lower:
            text_val = inputs.get("text", "")
            is_neg = any(k in title_lower or k in ctype_lower for k in ["neg", "负向", "反向", "bad", "negative"])
            prompt_nodes.append({
                "nodeId": str(nid),
                "title": title,
                "classType": ctype,
                "fieldName": "text",
                "defaultValue": text_val if isinstance(text_val, str) else "",
                "isNegative": is_neg
            })

        # 采样器节点
        elif "ksampler" in ctype_lower or "sampler" in title_lower:
            sampler_nodes.append({
                "nodeId": str(nid),
                "title": title,
                "classType": ctype,
                "seed": inputs.get("seed", 0) if isinstance(inputs.get("seed"), (int, float)) else 0,
                "steps": inputs.get("steps", 20) if isinstance(inputs.get("steps"), (int, float)) else 20,
                "cfg": inputs.get("cfg", 7.0) if isinstance(inputs.get("cfg"), (int, float)) else 7.0,
                "sampler_name": inputs.get("sampler_name", "euler"),
                "scheduler": inputs.get("scheduler", "normal"),
                "denoise": inputs.get("denoise", 1.0) if isinstance(inputs.get("denoise"), (int, float)) else 1.0
            })

        # 空 Latent 尺寸节点
        elif "emptylatent" in ctype_lower or ("width" in inputs and "height" in inputs and not isinstance(inputs.get("width"), list)):
            latent_nodes.append({
                "nodeId": str(nid),
                "title": title,
                "classType": ctype,
                "width": inputs.get("width", 512),
                "height": inputs.get("height", 512),
                "batch_size": inputs.get("batch_size", 1)
            })

        # 图像输入节点
        elif "loadimage" in ctype_lower or ("image" in inputs and isinstance(inputs.get("image"), str)):
            image_nodes.append({
                "nodeId": str(nid),
                "title": title,
                "classType": ctype,
                "fieldName": "image",
                "defaultValue": inputs.get("image", "")
            })

        # 视频输入节点
        elif "loadvideo" in ctype_lower or "vhs_loadvideo" in ctype_lower:
            video_nodes.append({
                "nodeId": str(nid),
                "title": title,
                "classType": ctype,
                "fieldName": "video",
                "defaultValue": inputs.get("video", "")
            })

        # 音频输入节点
        elif "loadaudio" in ctype_lower or "audio" in ctype_lower:
            audio_nodes.append({
                "nodeId": str(nid),
                "title": title,
                "classType": ctype,
                "fieldName": "audio",
                "defaultValue": inputs.get("audio", "")
            })

        # 最终保存输出节点
        elif any(k in ctype_lower for k in ["saveimage", "previewimage", "vhs_videocombine", "saveaudio"]):
            output_nodes.append({
                "nodeId": str(nid),
                "title": title,
                "classType": ctype
            })

    return {
        "hiddenAuxiliaryNodeIds": [],
        "dynamicSchema": {
            "promptNodes": prompt_nodes,
            "samplerNodes": sampler_nodes,
            "latentNodes": latent_nodes,
            "imageNodes": image_nodes,
            "videoNodes": video_nodes,
            "audioNodes": audio_nodes,
            "outputNodes": output_nodes,
            "qualityNodes": quality_nodes,
            "allEditableNodes": all_editable_nodes
        }
    }
