import json
from datetime import datetime
from pathlib import Path
from loguru import logger

def save_results(result: dict, result_dir: str = "results") -> str:
    """保存测试结果为 JSON 文件"""
    Path(result_dir).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    result_file = Path(result_dir) / f"webshell_test_{timestamp}.json"
    
    try:
        with result_file.open("w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        logger.info(f"测试结果已保存至: {result_file}")
        return str(result_file)
    except Exception as e:
        logger.error(f"保存测试结果失败: {e}")
        return ""
    
def save_results_as_html(result: dict, output_dir: str = "outputs"):
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    filename = f"{output_dir}/result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    html = f"""
    <html>
    <head><meta charset="utf-8"><title>WebShell 测试报告</title></head>
    <body>
    <h1>WebShell 测试报告</h1>
    <p><strong>总命令数:</strong> {result['total_commands']}</p>
    <p><strong>成功执行:</strong> {result['successful_commands']}</p>
    <p><strong>总执行时间:</strong> {result['total_execution_time']:.2f} 秒</p>
    <p><strong>平均执行时间:</strong> {result['average_execution_time']:.2f} 秒</p>
    <hr>
    <h2>详细结果</h2>
    <ul>
    """
    for res in result["results"]:
        html += f"<li><strong>命令:</strong> {res['command']}<br>"
        html += f"<strong>状态:</strong> {'成功' if res['success'] else '失败'}<br>"
        if res["success"]:
            html += f"<strong>输出:</strong><pre>{res['output']}</pre>"
        else:
            html += f"<strong>错误:</strong><pre>{res.get('error', '未知错误')}</pre>"
        html += "</li><hr>"

    html += "</ul></body></html>"

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)