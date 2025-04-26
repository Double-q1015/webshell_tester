import json
from datetime import datetime
from pathlib import Path
from loguru import logger

def save_results(result: dict, result_dir: str = "results") -> str:
    """Save test results as a JSON file"""
    Path(result_dir).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    result_file = Path(result_dir) / f"webshell_test_{timestamp}.json"
    
    try:
        with result_file.open("w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        logger.info(f"Test results saved to: {result_file}")
        return str(result_file)
    except Exception as e:
        logger.error(f"Failed to save test results: {e}")
        return ""
    
def save_results_as_html(result: dict, output_dir: str = "outputs"):
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    filename = f"{output_dir}/result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    html = f"""
    <html>
    <head><meta charset="utf-8"><title>WebShell Test Report</title></head>
    <body>
    <h1>WebShell Test Report</h1>
    <p><strong>Total Commands:</strong> {result['total_commands']}</p>
    <p><strong>Successful:</strong> {result['successful_commands']}</p>
    <p><strong>Total Execution Time:</strong> {result['total_execution_time']:.2f} seconds</p>
    <p><strong>Average Execution Time:</strong> {result['average_execution_time']:.2f} seconds</p>
    <hr>
    <h2>Detailed Results</h2>
    <ul>
    """
    for res in result["results"]:
        html += f"<li><strong>Command:</strong> {res['command']}<br>"
        html += f"<strong>Status:</strong> {'Success' if res['success'] else 'Failed'}<br>"
        if res["success"]:
            html += f"<strong>Output:</strong><pre>{res['output']}</pre>"
        else:
            html += f"<strong>Error:</strong><pre>{res.get('error', 'Unknown error')}</pre>"
        html += "</li><hr>"

    html += "</ul></body></html>"

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)