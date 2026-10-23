import os
import time
import requests
from typing import List, Dict, Any, Optional

API_KEY = os.getenv("RUNNINGHUB_API_KEY", "")
BASE_URL = "https://www.runninghub.cn"


def inspect_workflow(workflow_id: str, api_key: str = API_KEY) -> Optional[Dict[str, Any]]:
    """查询指定工作流的节点结构与配置信息"""
    url = f"{BASE_URL}/api/openapi/getJsonApiFormat"
    res = requests.post(url, json={"apiKey": api_key, "workflowId": str(workflow_id)})
    data = res.json()
    if data.get("code") == 0:
        return data.get("data", {})
    print(f"[!] 查询工作流失败: {data}")
    return None


def run_workflow(
    workflow_id: str,
    node_info_list: Optional[List[Dict[str, Any]]] = None,
    output_dir: str = "./outputs",
    api_key: str = API_KEY,
    timeout_seconds: int = 180,
    poll_interval: int = 3,
) -> List[str]:
    """
    提交并运行 RunningHub 工作流任务，任务完成后自动下载生成结果。

    :param workflow_id: 工作流 ID
    :param node_info_list: 需要动态覆盖的节点参数列表，如 [{'nodeId': '6', 'fieldName': 'text', 'fieldValue': '...'}]
    :param output_dir: 本地保存生成结果的目录
    :param api_key: 用户的 RunningHub API Key
    :param timeout_seconds: 最大等待超时时间（秒）
    :param poll_interval: 轮询查询间隔（秒）
    :return: 本地保存的文件路径列表
    """
    headers = {
        "Host": "www.runninghub.cn",
        "Content-Type": "application/json"
    }

    payload = {
        "apiKey": api_key,
        "workflowId": str(workflow_id),
        "nodeInfoList": node_info_list or []
    }

    # 1. 创建任务
    print(f"[*] 正在提交任务到 RunningHub (Workflow ID: {workflow_id})...")
    create_res = requests.post(f"{BASE_URL}/task/openapi/create", json=payload, headers=headers).json()

    if create_res.get("code") != 0:
        print(f"[!] 任务提交失败: {create_res}")
        return []

    task_id = create_res.get("data", {}).get("taskId")
    print(f"[+] 任务创建成功！TaskId: {task_id}")
    print("[*] 开始轮询生成状态...")

    # 2. 轮询结果
    start_time = time.time()
    outputs_url = f"{BASE_URL}/task/openapi/outputs"
    saved_files = []

    while time.time() - start_time < timeout_seconds:
        out_res = requests.post(outputs_url, json={"apiKey": api_key, "taskId": str(task_id)}, headers=headers).json()
        code = out_res.get("code")
        msg = out_res.get("msg")

        # 任务完成
        if code == 0 and out_res.get("data"):
            data = out_res["data"]
            print(f"[+] 任务执行完毕！耗时: {int(time.time() - start_time)}秒")
            
            os.makedirs(output_dir, exist_ok=True)
            for idx, item in enumerate(data):
                file_url = item.get("fileUrl")
                coins = item.get("consumeCoins", "未知")
                print(f"    - 输出项 {idx + 1}: 消耗RH币: {coins}, 链接: {file_url}")
                if file_url:
                    content = requests.get(file_url).content
                    ext = item.get("fileType", "png")
                    filename = os.path.join(output_dir, f"{task_id}_{idx}.{ext}")
                    with open(filename, "wb") as f:
                        f.write(content)
                    print(f"    -> 已保存至本地: {filename}")
                    saved_files.append(filename)
            return saved_files

        # 正在排队或执行中
        elif code in (803, 804) or "RUNNING" in str(msg) or "QUEUED" in str(msg):
            print(f"    [~] 云端运行中... ({int(time.time() - start_time)}s)")
        else:
            print(f"[!] 任务异常或失败: {out_res}")
            return []

        time.sleep(poll_interval)

    print(f"[!] 任务超时（超过 {timeout_seconds} 秒）")
    return []


if __name__ == "__main__":
    # 示例：使用轻量 SDXL 默认工作流测试文生图
    sample_workflow_id = "1904136902449209346"

    # 自定义修改节点参数：提示词 + 仅生成 5 步（极低耗时与费用）
    params = [
        {"nodeId": "6", "fieldName": "text", "fieldValue": "a cute robotic cat in cyberpunk street, 3d render"},
        {"nodeId": "3", "fieldName": "steps", "fieldValue": 5},
        {"nodeId": "5", "fieldName": "width", "fieldValue": 512},
        {"nodeId": "5", "fieldName": "height", "fieldValue": 512}
    ]

    downloaded = run_workflow(
        workflow_id=sample_workflow_id,
        node_info_list=params,
        output_dir="./outputs"
    )

    print("\n已完成全部流程，下载的文件列表:", downloaded)
