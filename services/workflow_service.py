import os
import json
import time
import requests
from typing import Dict, Any, Optional, List, Tuple, Set
from core.config import DATA_DIR, RUNNINGHUB_API_URL, load_config, get_active_api_key
from core.http_client import HTTP_SESSION

OBJECT_INFO_CACHE_PATH = os.path.join(DATA_DIR, "object_info_cache.json")
_MEMORY_OBJECT_INFO: Optional[Dict[str, Any]] = None
_CATEGORY_MODELS: Optional[Dict[str, List[str]]] = None

CATEGORY_LABELS = {
    "checkpoint": "主模型 (Checkpoint)",
    "unet": "扩散骨架 (UNet)",
    "lora": "微调模型 (LoRA)",
    "vae": "色彩编解码器 (VAE)",
    "controlnet": "控制网络 (ControlNet)",
    "clip": "文本编码器 (CLIP)",
    "upscale": "超分放大模型 (Upscaler)",
    "sampler": "采样器算法 (Sampler)",
    "scheduler": "降噪调度器 (Scheduler)",
}

IS_MODEL_CATEGORY = {"checkpoint", "unet", "lora", "vae", "controlnet", "clip", "upscale"}

def get_category_models(obj_info: Optional[Dict[str, Any]] = None) -> Dict[str, List[str]]:
    """
    从 ComfyUI object_info 缓存中全量聚合不同模型分类的可用模型候选池
    """
    global _CATEGORY_MODELS
    if _CATEGORY_MODELS is not None:
        return _CATEGORY_MODELS

    if obj_info is None:
        obj_info = get_cached_object_info("")

    from collections import defaultdict
    category_sets = defaultdict(set)
    if isinstance(obj_info, dict):
        for ctype, info in obj_info.items():
            if not isinstance(info, dict):
                continue
            inp = info.get("input", {})
            if not isinstance(inp, dict):
                continue
            all_fields = {**inp.get("required", {}), **inp.get("optional", {})}
            for fname, spec in all_fields.items():
                if isinstance(spec, list) and len(spec) > 0 and isinstance(spec[0], list):
                    items = [
                        str(x).strip() for x in spec[0]
                        if isinstance(x, (str, int, float)) and str(x).strip() and str(x).strip().lower() not in ("none", "(none)")
                    ]
                    if not items:
                        continue
                    fname_lower = fname.lower()
                    ctype_lower = ctype.lower()
                    if "ckpt" in fname_lower or "checkpoint" in fname_lower:
                        category_sets["checkpoint"].update(items)
                    elif "lora" in fname_lower:
                        category_sets["lora"].update(items)
                    elif "vae" in fname_lower:
                        category_sets["vae"].update(items)
                    elif "control_net" in fname_lower or "controlnet" in fname_lower:
                        category_sets["controlnet"].update(items)
                    elif "clip" in fname_lower and "clip_skip" not in fname_lower:
                        category_sets["clip"].update(items)
                    elif "unet" in fname_lower or "diffusion_model" in fname_lower:
                        category_sets["unet"].update(items)
                    elif "upscale" in fname_lower or "upscalemodel" in ctype_lower:
                        category_sets["upscale"].update(items)
                    elif fname_lower == "sampler_name":
                        category_sets["sampler"].update(items)
                    elif fname_lower == "scheduler":
                        category_sets["scheduler"].update(items)

    _CATEGORY_MODELS = {k: sorted(list(v)) for k, v in category_sets.items()}
    return _CATEGORY_MODELS

def get_field_options_and_category(
    ctype: str,
    field_name: str,
    current_value: Any = "",
    obj_info: Optional[Dict[str, Any]] = None
) -> Tuple[List[str], Optional[str], Optional[str]]:
    """
    智能推断指定节点的指定字段是否为模型/枚举选项，并返回 (候选列表, 分类, 分类中文名)
    """
    if obj_info is None:
        obj_info = get_cached_object_info("")

    fname_lower = field_name.lower()
    ctype_lower = ctype.lower()

    # 1. 判断字段分类
    category = None
    if "ckpt" in fname_lower or "checkpoint" in fname_lower or ("checkpoint" in ctype_lower and fname_lower in ("ckpt_name", "model_name")):
        category = "checkpoint"
    elif "lora" in fname_lower:
        category = "lora"
    elif "vae" in fname_lower:
        category = "vae"
    elif "control_net" in fname_lower or "controlnet" in fname_lower:
        category = "controlnet"
    elif "unet" in fname_lower or ("diffusion" in ctype_lower and "model" in fname_lower):
        category = "unet"
    elif "clip" in fname_lower and "clip_skip" not in fname_lower:
        category = "clip"
    elif "upscale" in fname_lower or "upscale" in ctype_lower:
        category = "upscale"
    elif fname_lower == "sampler_name":
        category = "sampler"
    elif fname_lower == "scheduler":
        category = "scheduler"

    # 2. 从当前节点定义中尝试获取 spec options
    node_options: List[str] = []
    if isinstance(obj_info, dict) and ctype in obj_info:
        inp = obj_info[ctype].get("input", {})
        if isinstance(inp, dict):
            all_fields = {**inp.get("required", {}), **inp.get("optional", {})}
            if field_name in all_fields:
                spec = all_fields[field_name]
                if isinstance(spec, list) and len(spec) > 0 and isinstance(spec[0], list):
                    node_options = [
                        str(x).strip() for x in spec[0]
                        if isinstance(x, (str, int, float)) and str(x).strip() and str(x).strip().lower() not in ("none", "(none)")
                    ]

    # 3. 如果当前节点选项为空或过少，尝试从聚合分类模型池扩充
    cat_pool = get_category_models(obj_info)
    candidates = list(node_options)
    if category and category in cat_pool:
        # 如果当前节点没有候选项，或者只有极少候选项，采用分类模型池
        if len(candidates) <= 1:
            candidates = list(cat_pool[category])
        else:
            # 合并分类模型池以提供更全的选择
            merged_set = set(candidates)
            for item in cat_pool[category]:
                if item not in merged_set:
                    candidates.append(item)
                    merged_set.add(item)

    # 4. 如果既不是预定义分类，当前节点也没有枚举选项
    if not candidates:
        cv_str = str(current_value).strip() if current_value is not None else ""
        if category in IS_MODEL_CATEGORY and cv_str and cv_str.lower() not in ("none", "(none)"):
            candidates = [cv_str]
        else:
            return [], category, CATEGORY_LABELS.get(category) if category else None

    # 5. 确保 current_value 始终位于候选项列表的第 0 位（默认选中且不丢失当前配置）
    cv_str = str(current_value).strip() if current_value is not None else ""
    if cv_str and cv_str.lower() not in ("none", "(none)"):
        if cv_str in candidates:
            candidates = [cv_str] + [c for c in candidates if c != cv_str]
        else:
            candidates = [cv_str] + candidates

    return candidates, category, CATEGORY_LABELS.get(category) if category else None

def get_cached_object_info(api_key: str = "") -> Dict[str, Any]:
    """
    获取或缓存 RunningHub 云端全部节点的完整定义（19800+ 节点定义）
    用于在用户上传普通 Web 画布格式工作流时，自动将其无缝编译为标准的 ComfyUI API Prompt 格式
    """
    global _MEMORY_OBJECT_INFO
    if _MEMORY_OBJECT_INFO is not None and len(_MEMORY_OBJECT_INFO) > 50:
        return _MEMORY_OBJECT_INFO

    # 1. 尝试从本地磁盘缓存加载（永久兜底保证 19800+ 节点定义绝不丢失）
    disk_data = None
    if os.path.exists(OBJECT_INFO_CACHE_PATH):
        try:
            with open(OBJECT_INFO_CACHE_PATH, "r", encoding="utf-8") as f:
                disk_data = json.load(f)
                if isinstance(disk_data, dict) and len(disk_data) > 50:
                    _MEMORY_OBJECT_INFO = disk_data
                    # 30天内缓存视为新鲜，直接返回
                    mtime = os.path.getmtime(OBJECT_INFO_CACHE_PATH)
                    if time.time() - mtime < 86400 * 30:
                        return _MEMORY_OBJECT_INFO
        except Exception as e:
            print(f"[WorkflowService] Warning loading object_info_cache: {e}")

    # 2. 如果未指定 key，自动从系统配置中提取活跃 API Key
    if not api_key:
        try:
            cfg = load_config()
            api_key = get_active_api_key(cfg)
        except Exception:
            pass

    # 3. 若有 key，尝试从云端代理获取最新拓扑并刷新磁盘缓存
    if api_key:
        for host in ["www.runninghub.cn", "www.runninghub.ai"]:
            try:
                url = f"https://{host}/proxy/{api_key}/object_info"
                res = HTTP_SESSION.get(url, timeout=12)
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

    # 4. 若云端获取失败（无网络/无Key/超时），只要本地存在磁盘缓存就必须降级复用，杜绝返回空字典！
    if disk_data and isinstance(disk_data, dict) and len(disk_data) > 50:
        _MEMORY_OBJECT_INFO = disk_data
        return _MEMORY_OBJECT_INFO

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

def detect_silent_audio_subgraphs(nodes: Dict[str, Any]) -> Set[str]:
    """
    拓扑检测 ComfyUI 中常见的静音/占位音频生成 4 节点流水线：
    Node 1 (GetImageSize / GetImageSizeAndCount)
      -> Node 2 (SimpleCalculator / SimpleCalculatorKJ)
        -> Node 3 (EmptyAudio)
          -> Node 4 (SaveAudio / SaveAudioAdvanced)
    
    严格限制：只有当这 4 个节点严格按照此有向无环依赖链级联连接时，才认定为辅助占位链路并隐藏。
    若任意节点独立存在或未形成该完整 4 节点链路，则视为用户真实操作节点，正常展示。
    """
    def normalize_type(ctype: Any) -> str:
        return str(ctype).replace("_", "").replace(" ", "").lower()

    def is_node_type(node: Dict[str, Any], candidates: List[str]) -> bool:
        norm = normalize_type(node.get("class_type", ""))
        return any(c in norm for c in candidates)

    def get_node_incoming_sources(node: Dict[str, Any]) -> Set[str]:
        sources = set()
        inputs = node.get("inputs", {})
        if isinstance(inputs, dict):
            for val in inputs.values():
                if isinstance(val, (list, tuple)) and len(val) >= 1:
                    sources.add(str(val[0]))
        return sources

    hidden_ids: Set[str] = set()
    for n4_id, n4 in nodes.items():
        if is_node_type(n4, ["saveaudio"]):
            for n3_id in get_node_incoming_sources(n4):
                n3 = nodes.get(n3_id)
                if n3 and is_node_type(n3, ["emptyaudio"]):
                    for n2_id in get_node_incoming_sources(n3):
                        n2 = nodes.get(n2_id)
                        if n2 and is_node_type(n2, ["simplecalculator"]):
                            for n1_id in get_node_incoming_sources(n2):
                                n1 = nodes.get(n1_id)
                                if n1 and is_node_type(n1, ["getimagesize"]):
                                    chain = {str(n1_id), str(n2_id), str(n3_id), str(n4_id)}
                                    hidden_ids.update(chain)
    return hidden_ids

def build_visual_graph(
    nodes: Dict[str, Any],
    hidden_node_ids: Optional[Set[str]] = None,
    obj_info: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    将 ComfyUI API Prompt 节点字典自动编译为高保真可视化画布拓扑模型：
    1. 自动计算 DAG 拓扑分层深度（从左至右自然排布，清晰展示数据流向）
    2. 严格区分端口连线输入与字面量可编辑参数（支持模型/枚举下拉选项自动装配）
    3. 提取输出端口与下游连线引用
    4. 标注辅助静音占位节点（以便前端画布自由显隐过滤）
    5. 自动推断端口数据类型与色彩规范 (Model, Clip, VAE, Latent, Image, etc.)
    """
    if not isinstance(nodes, dict):
        return {"nodes": [], "edges": []}

    if obj_info is None:
        obj_info = get_cached_object_info("")

    from collections import defaultdict
    hidden_set = set(str(x) for x in (hidden_node_ids or []))

    # 1. 深度优先搜索计算 DAG 拓扑层级 (Rank / Depth)
    depths = {}
    def get_node_depth(nid: str, visited: Optional[Set[str]] = None) -> int:
        if visited is None:
            visited = set()
        if nid in depths:
            return depths[nid]
        if nid in visited or len(visited) > 40:
            return 0
        visited.add(nid)

        node_spec = nodes.get(nid, {})
        inputs = node_spec.get("inputs", {}) if isinstance(node_spec, dict) else {}
        max_d = 0
        if isinstance(inputs, dict):
            for v in inputs.values():
                if isinstance(v, (list, tuple)) and len(v) >= 1:
                    src_id = str(v[0])
                    if src_id in nodes:
                        max_d = max(max_d, get_node_depth(src_id, visited) + 1)
        depths[nid] = max_d
        return max_d

    for nid in nodes.keys():
        get_node_depth(str(nid))

    # 2. 分列分组排布坐标
    cols = defaultdict(list)
    for nid, d in depths.items():
        cols[d].append(str(nid))

    for d in cols:
        def _sort_key(n):
            try:
                return (0, int(n))
            except Exception:
                return (1, str(n))
        cols[d].sort(key=_sort_key)

    NODE_WIDTH = 300
    COL_GAP = 140
    
    graph_nodes = []
    graph_edges = []

    # 统计每个节点的下游引用（生成输出端口）
    downstream_refs = defaultdict(list)
    for target_id, n_data in nodes.items():
        target_id_str = str(target_id)
        if not isinstance(n_data, dict):
            continue
        inputs = n_data.get("inputs", {})
        if isinstance(inputs, dict):
            for param_name, val in inputs.items():
                if isinstance(val, (list, tuple)) and len(val) >= 2:
                    src_id = str(val[0])
                    src_slot = int(val[1]) if str(val[1]).isdigit() else 0
                    downstream_refs[src_id].append((src_slot, target_id_str, param_name))

    for depth, nids in sorted(cols.items()):
        for row_idx, nid in enumerate(nids):
            n_data = nodes.get(nid, {})
            if not isinstance(n_data, dict):
                continue
            ctype = str(n_data.get("class_type", "Node"))
            meta = n_data.get("_meta", {})
            title = meta.get("title") if isinstance(meta, dict) else None
            title = title or ctype
            is_aux = nid in hidden_set

            inputs = n_data.get("inputs", {}) if isinstance(n_data.get("inputs"), dict) else {}
            literals = []
            linked_inputs = []

            for k, v in inputs.items():
                if isinstance(v, (list, tuple)) and len(v) >= 2:
                    src_id = str(v[0])
                    src_slot = int(v[1]) if str(v[1]).isdigit() else 0
                    linked_inputs.append({
                        "name": k,
                        "sourceId": src_id,
                        "sourceSlot": src_slot
                    })
                    
                    k_lower = k.lower()
                    data_type = "generic"
                    if "model" in k_lower: data_type = "model"
                    elif "clip" in k_lower or "conditioning" in k_lower or "prompt" in k_lower: data_type = "clip"
                    elif "vae" in k_lower: data_type = "vae"
                    elif "latent" in k_lower: data_type = "latent"
                    elif "image" in k_lower or "mask" in k_lower: data_type = "image"
                    elif "video" in k_lower or "audio" in k_lower: data_type = "media"

                    graph_edges.append({
                        "id": f"e_{src_id}_{src_slot}->{nid}_{k}",
                        "from": src_id,
                        "fromSlot": src_slot,
                        "to": nid,
                        "toParam": k,
                        "dataType": data_type,
                        "isAuxiliary": is_aux or (src_id in hidden_set)
                    })
                else:
                    opts, cat, cat_label = get_field_options_and_category(ctype, k, v, obj_info)
                    ftype = "str"
                    if isinstance(v, bool):
                        ftype = "bool"
                    elif isinstance(v, int):
                        ftype = "int"
                    elif isinstance(v, float):
                        ftype = "float"

                    lit_dict = {
                        "name": k,
                        "value": v,
                        "type": "combo" if opts else ftype
                    }
                    if opts:
                        lit_dict["options"] = opts[:300]
                        lit_dict["category"] = cat
                        lit_dict["categoryLabel"] = cat_label
                        lit_dict["isModel"] = bool(cat in IS_MODEL_CATEGORY)
                    literals.append(lit_dict)

            outputs = []
            slots_used = {slot for slot, _, _ in downstream_refs.get(nid, [])}
            if not slots_used:
                slots_used = {0}
            for s in sorted(slots_used):
                outputs.append({"slot": s, "name": f"OUT {s}" if s > 0 else "OUT"})

            ctype_lower = ctype.lower()
            category = "other"
            if any(w in ctype_lower for w in ["load", "loader", "checkpoint", "lora"]): category = "loader"
            elif any(w in ctype_lower for w in ["clip", "text", "prompt"]): category = "prompt"
            elif any(w in ctype_lower for w in ["sampler", "ksampler", "scheduler"]): category = "sampler"
            elif any(w in ctype_lower for w in ["latent", "resize", "scale", "crop", "image"]): category = "latent"
            elif any(w in ctype_lower for w in ["save", "preview", "output"]): category = "output"

            init_x = depth * (NODE_WIDTH + COL_GAP) + 60
            init_y = row_idx * 290 + 60

            graph_nodes.append({
                "id": str(nid),
                "class_type": ctype,
                "title": title,
                "category": category,
                "isAuxiliary": is_aux,
                "x": init_x,
                "y": init_y,
                "width": NODE_WIDTH,
                "literals": literals,
                "linkedInputs": linked_inputs,
                "outputs": outputs
            })

    return {
        "nodes": graph_nodes,
        "edges": graph_edges
    }

def parse_nodes_to_dynamic_schema(
    nodes: Dict[str, Any],
    cfg: Dict[str, Any],
    obj_info: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """对 ComfyUI 节点结构做深度动态解析，提取基底模型、提示词、尺寸、采样器、参考图视频、以及全节点可调项"""
    if obj_info is None:
        obj_info = get_cached_object_info("")

    model_nodes = []
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
        title = meta.get("title") if isinstance(meta, dict) else None
        title = title or ctype

        # 获取当前节点中所有的常量字面量字段（排除 link 引用列表，如 ['1', 0]）
        literal_fields = {k: v for k, v in inputs.items() if not isinstance(v, (list, dict))}

        # 0. 核心基底与模型节点 (Checkpoint, UNet, LoRA, VAE, ControlNet, CLIP, Upscaler 等)
        for fname, fval in literal_fields.items():
            opts, cat, cat_label = get_field_options_and_category(ctype, fname, fval, obj_info)
            if cat in IS_MODEL_CATEGORY:
                model_nodes.append({
                    "nodeId": str(nid),
                    "class_type": ctype,
                    "category": cat,
                    "categoryLabel": cat_label or cat.upper(),
                    "nodeTitle": f"{title} #{nid}",
                    "fieldName": fname,
                    "defaultValue": str(fval),
                    "currentValue": str(fval),
                    "options": opts[:300]
                })

        # 1. 提示词与文本节点
        if "CLIPTextEncode" in ctype or "RH_Prompter" in ctype or "Prompt" in ctype or "JjkText" in ctype or ("text" in literal_fields and isinstance(literal_fields["text"], str) and len(literal_fields["text"]) > 0):
            field_name = "text" if "text" in literal_fields else "prompt"
            if field_name in literal_fields:
                prompt_nodes.append({
                    "nodeId": str(nid),
                    "class_type": ctype,
                    "title": f"提示词节点 #{nid} ({ctype})",
                    "fieldName": field_name,
                    "defaultValue": str(literal_fields[field_name])
                })

        # 2. 采样器与步数/调度器节点 (优先匹配真实带有 steps 的调度器或采样器)
        if ("steps" in literal_fields and "cfg" in literal_fields) or ctype in ("KSampler", "KSamplerAdvanced"):
            sampler_fields = {
                k: v for k, v in literal_fields.items()
                if k in ["steps", "cfg", "sampler_name", "scheduler", "seed", "denoise"]
            }
            if sampler_fields:
                sampler_nodes.append({
                    "nodeId": str(nid),
                    "class_type": ctype,
                    "title": f"采样器节点 #{nid} ({ctype})",
                    "fields": sampler_fields
                })
        elif "steps" in literal_fields:
            sched_fields = {
                k: v for k, v in literal_fields.items()
                if k in ["steps", "scheduler", "denoise"]
            }
            if sched_fields:
                sampler_nodes.append({
                    "nodeId": str(nid),
                    "class_type": ctype,
                    "title": f"步数与调度器 #{nid} ({ctype})",
                    "fields": sched_fields
                })

        # 3. 画面尺寸与批次节点 (EmptyLatentImage)
        if "EmptyLatentImage" in ctype or "Latent" in ctype or ("width" in literal_fields and "height" in literal_fields):
            latent_fields = {
                k: v for k, v in literal_fields.items()
                if k in ["width", "height", "batch_size"]
            }
            if latent_fields:
                latent_nodes.append({
                    "nodeId": str(nid),
                    "class_type": ctype,
                    "title": f"尺寸节点 #{nid} ({ctype})",
                    "fields": latent_fields
                })

        # 4. 参考图输入节点 (LoadImage / UploadImage)
        if "LoadImage" in ctype or "UploadImage" in ctype or ("image" in literal_fields and isinstance(literal_fields["image"], str)):
            if "image" in literal_fields:
                image_nodes.append({
                    "nodeId": str(nid),
                    "class_type": ctype,
                    "title": f"参考图输入 #{nid} ({ctype})",
                    "fieldName": "image",
                    "defaultValue": str(literal_fields.get("image", ""))
                })

        # 5. 参考视频输入节点 (VHS_LoadVideo / LoadVideo)
        if "LoadVideo" in ctype or ("video" in literal_fields and isinstance(literal_fields["video"], str)):
            if "video" in literal_fields:
                video_nodes.append({
                    "nodeId": str(nid),
                    "class_type": ctype,
                    "title": f"参考视频输入 #{nid} ({ctype})",
                    "fieldName": "video",
                    "defaultValue": str(literal_fields.get("video", ""))
                })

        # 5.1 参考音频输入节点 (LoadAudio / VHS_LoadAudio / AudioLoader / 或包含 audio 参数)
        if any(k.lower() in ctype.lower() for k in ["loadaudio", "audioloader"]) or any(k in literal_fields for k in ["audio", "audio_file", "audio_path", "sound", "voice", "speech"]):
            audio_field = next((k for k in ["audio", "audio_file", "audio_path", "sound", "voice", "speech"] if k in literal_fields and isinstance(literal_fields[k], str)), None)
            if audio_field:
                audio_nodes.append({
                    "nodeId": str(nid),
                    "class_type": ctype,
                    "title": f"参考音频输入 #{nid} ({ctype})",
                    "fieldName": audio_field,
                    "defaultValue": str(literal_fields.get(audio_field, ""))
                })

        # 6. 画质/基准分辨率节点 (如 PrimitiveInt: 1280)
        if ctype in ("PrimitiveInt", "Int") and "value" in literal_fields:
            val = literal_fields["value"]
            if isinstance(val, int) and (val >= 256 or val in [512, 720, 768, 1024, 1080, 1280, 1920]):
                quality_nodes.append({
                    "nodeId": str(nid),
                    "class_type": ctype,
                    "title": f"画质/分辨率尺寸 #{nid} ({ctype})",
                    "fieldName": "value",
                    "defaultValue": val
                })

        # 7. 输出类节点 (SaveImage, PreviewImage, SaveVideo, VHS_VideoCombine, 等)
        if any(k in ctype for k in ["SaveImage", "PreviewImage", "SaveVideo", "VHS_VideoCombine", "Preview", "SaveAudio", "Output"]):
            output_nodes.append({
                "nodeId": str(nid),
                "class_type": ctype,
                "title": f"输出节点 #{nid} ({ctype})",
                "isVideo": any(v in ctype for v in ["Video", "VHS"]),
                "isAudio": "Audio" in ctype
            })

        # 8. 全节点字面量清单（带详细字段元数据，供前端全量可调参数面板渲染）
        if literal_fields:
            field_meta = []
            for k, v in literal_fields.items():
                opts, cat, cat_label = get_field_options_and_category(ctype, k, v, obj_info)
                ftype = "str"
                if isinstance(v, bool):
                    ftype = "bool"
                elif isinstance(v, int):
                    ftype = "int"
                elif isinstance(v, float):
                    ftype = "float"

                meta_item = {
                    "name": k,
                    "value": v,
                    "type": "combo" if opts else ftype
                }
                if opts:
                    meta_item["options"] = opts[:300]
                    meta_item["category"] = cat
                    meta_item["categoryLabel"] = cat_label
                    meta_item["isModel"] = bool(cat in IS_MODEL_CATEGORY)
                field_meta.append(meta_item)

            all_editable_nodes.append({
                "nodeId": str(nid),
                "class_type": ctype,
                "fields": literal_fields,
                "fieldMeta": field_meta
            })

    # 拓扑检测静音音频占位辅助链路 (GetImageSize -> Simple Calculator -> Empty Audio -> Save Audio)
    hide_auxiliary = bool(cfg.get("system", {}).get("hideAuxiliaryAudioChain", True))
    hidden_node_ids: Set[str] = detect_silent_audio_subgraphs(nodes) if hide_auxiliary else set()

    if hidden_node_ids:
        model_nodes = [m for m in model_nodes if str(m.get("nodeId")) not in hidden_node_ids]
        prompt_nodes = [p for p in prompt_nodes if str(p.get("nodeId")) not in hidden_node_ids]
        sampler_nodes = [s for s in sampler_nodes if str(s.get("nodeId")) not in hidden_node_ids]
        latent_nodes = [l for l in latent_nodes if str(l.get("nodeId")) not in hidden_node_ids]
        image_nodes = [im for im in image_nodes if str(im.get("nodeId")) not in hidden_node_ids]
        video_nodes = [vm for vm in video_nodes if str(vm.get("nodeId")) not in hidden_node_ids]
        audio_nodes = [am for am in audio_nodes if str(am.get("nodeId")) not in hidden_node_ids]
        quality_nodes = [q for q in quality_nodes if str(q.get("nodeId")) not in hidden_node_ids]
        output_nodes = [o for o in output_nodes if str(o.get("nodeId")) not in hidden_node_ids]
        all_editable_nodes = [n for n in all_editable_nodes if str(n.get("nodeId")) not in hidden_node_ids]

    # 智能区分正向、负向与主体提示词
    categorized_prompts = []
    for p in prompt_nodes:
        text_val = p["defaultValue"].strip().lower()
        if any(w in text_val for w in ["bad", "blurry", "worst quality", "low quality", "deformed", "distorted", "artifacts", "lowres"]) or "negative" in p["class_type"].lower():
            role = "negative"
            label = "负向提示词 (Negative Prompt)"
        elif len(text_val) > 20 or "positive" in p["class_type"].lower() or any(w in text_val for w in ["masterpiece", "detailed", "描述", "人物", "衣服", "服装", "背景", "镜头"]):
            role = "positive"
            label = "正向主提示词 (Positive Prompt)"
        else:
            role = "subject"
            label = "主体/特征描述"
        categorized_prompts.append({**p, "role": role, "label": f"{label} #{p['nodeId']}"})

    if categorized_prompts and not any(p["role"] == "positive" for p in categorized_prompts):
        categorized_prompts[0]["role"] = "positive"
        categorized_prompts[0]["label"] = f"正向主提示词 #{categorized_prompts[0]['nodeId']}"

    # 对全节点列表按 nodeId 数字排序
    def node_sort_key(n):
        try:
            return (0, int(n["nodeId"]))
        except Exception:
            return (1, str(n["nodeId"]))
    all_editable_nodes.sort(key=node_sort_key)

    return {
        "hiddenAuxiliaryNodeIds": list(hidden_node_ids) if hidden_node_ids else [],
        "dynamicSchema": {
            "modelNodes": model_nodes,
            "promptNodes": categorized_prompts,
            "samplerNode": sampler_nodes[0] if sampler_nodes else None,
            "latentNode": latent_nodes[0] if latent_nodes else None,
            "imageNodes": image_nodes,
            "videoNodes": video_nodes,
            "audioNodes": audio_nodes,
            "qualityNodes": quality_nodes,
            "outputNodes": output_nodes,
            "allEditableNodes": all_editable_nodes
        }
    }
