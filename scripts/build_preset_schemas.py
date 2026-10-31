import json
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core.config import load_config, get_active_api_key, RUNNINGHUB_API_URL, DATA_DIR
from core.http_client import HTTP_SESSION
from routers.workflows_router import parse_nodes_to_dynamic_schema, build_visual_graph

cfg = load_config()
api_key = get_active_api_key(cfg)

cached_schemas = {}

for w in cfg.get("workflows", []):
    wid = str(w.get("id"))
    name = w.get("name")
    url = f"{RUNNINGHUB_API_URL}/api/openapi/getJsonApiFormat"
    try:
        res = HTTP_SESSION.post(url, json={"apiKey": api_key, "workflowId": wid}, timeout=15)
        d = res.json()
        if d.get("code") == 0:
            prompt_str = d.get("data", {}).get("prompt", "{}")
            nodes = json.loads(prompt_str)
            parsed = parse_nodes_to_dynamic_schema(nodes, cfg)
            visual_graph = build_visual_graph(nodes, set(parsed.get("hiddenAuxiliaryNodeIds") or []))
            cached_schemas[wid] = {
                "status": "ok",
                "workflowId": wid,
                "workflowName": name,
                "totalNodes": len(nodes),
                "rawPrompt": nodes,
                "visualGraph": visual_graph,
                "hiddenAuxiliaryNodeIds": parsed.get("hiddenAuxiliaryNodeIds", []),
                "dynamicSchema": parsed.get("dynamicSchema", [])
            }
            print(f"Cached {name} ({wid}): {len(nodes)} nodes, {len(parsed.get('dynamicSchema', []))} fields")
        else:
            print(f"Failed {name}: {d.get('msg')}")
    except Exception as e:
        print(f"Error {name}: {e}")

out_path = os.path.join(DATA_DIR, "preset_workflow_schemas.json")
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(cached_schemas, f, ensure_ascii=False, indent=2)

print(f"Saved {out_path} with {len(cached_schemas)} presets, size: {os.path.getsize(out_path)} bytes")
