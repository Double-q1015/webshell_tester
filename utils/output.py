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
    """生成HTML格式的测试报告"""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    filename = f"{output_dir}/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    
    stats = result.get('stats', {})
    
    html = f"""
    <html>
    <head>
        <meta charset="utf-8">
        <title>WebShell 测试报告</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .success {{ color: green; }}
            .error {{ color: red; }}
            .stats {{ background-color: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
            .file-list {{ margin: 20px 0; }}
            .file-item {{ margin: 10px 0; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }}
            .step-item {{ margin: 10px 20px; padding: 10px; background-color: #f9f9f9; border-left: 3px solid #ddd; }}
            .step-success {{ border-left-color: green; }}
            .step-error {{ border-left-color: red; }}
            .details-container {{ margin: 10px 0; }}
            .details-toggle {{ cursor: pointer; color: blue; text-decoration: underline; }}
            .details-content {{ display: none; margin: 10px 0; padding: 10px; background-color: #f0f0f0; border-radius: 5px; }}
            pre {{ background-color: #f0f0f0; padding: 10px; border-radius: 5px; overflow-x: auto; }}
            .command {{ background-color: #f0f0f0; color: #fff; padding: 10px; border-radius: 5px; margin: 5px 0; }}
            .response {{ background-color: #f0f0f0; padding: 10px; border-radius: 5px; margin: 5px 0; }}
            .test-pair {{ margin: 10px 0; padding: 10px; background-color: #fff; border: 1px solid #ddd; border-radius: 5px; }}
            .request-data {{ background-color: #f0f0f0; color: #fff; padding: 10px; border-radius: 5px 5px 0 0; }}
            .response-data {{ background-color: #f0f0f0; padding: 10px; border-radius: 0 0 5px 5px; border-top: 2px solid #ddd; }}
            .http-method {{ color: #ff9800; font-weight: bold; }}
            .http-url {{ color: #2196f3; }}
            .http-headers {{ color: #4caf50; }}
            .http-body {{ color: #9c27b0; }}
        </style>
        <script>
            function toggleDetails(id) {{
                var content = document.getElementById(id);
                if (content.style.display === "none") {{
                    content.style.display = "block";
                }} else {{
                    content.style.display = "none";
                }}
            }}
        </script>
    </head>
    <body>
        <h1>WebShell 测试报告</h1>
        <div class="stats">
            <h2>统计信息</h2>
            <p><strong>总文件数:</strong> {stats.get('total_files', 0)}</p>
            <p><strong>成功处理:</strong> {stats.get('successful_files', 0)} 个文件</p>
            <p><strong>处理失败:</strong> {stats.get('failed_files', 0)} 个文件</p>
            <p><strong>跳过已存在:</strong> {stats.get('skipped_files', 0)} 个文件</p>
            <p><strong>处理总时间:</strong> {stats.get('total_execution_time', 0):.2f} 秒</p>
            <p><strong>平均处理时间:</strong> {stats.get('average_execution_time', 0):.2f} 秒</p>
        </div>
    """

    # 添加详细的执行记录
    if result.get('execution_details'):
        html += "<h2>详细执行记录</h2>"
        for idx, detail in enumerate(result['execution_details']):
            status_class = "success" if detail['success'] else "error"
            html += f"""
            <div class="file-item {status_class}">
                <h3>文件: {detail['file']}</h3>
                <p><strong>开始时间:</strong> {detail['start_time']}</p>
                <p><strong>结束时间:</strong> {detail['end_time']}</p>
                <p><strong>状态:</strong> {'成功' if detail['success'] else '失败'}</p>
            """
            
            if detail.get('error'):
                html += f'<p class="error"><strong>错误信息:</strong> {detail["error"]}</p>'
            
            if detail.get('steps'):
                html += "<h4>执行步骤:</h4>"
                for step_idx, step in enumerate(detail['steps']):
                    step_class = "step-success" if step['success'] else "step-error"
                    html += f"""
                    <div class="step-item {step_class}">
                        <h4>{step['step']}</h4>
                        <p><strong>开始时间:</strong> {step.get('start_time', 'N/A')}</p>
                        <p><strong>结束时间:</strong> {step.get('end_time', 'N/A')}</p>
                        <p><strong>执行时间:</strong> {step.get('duration', 0):.2f} 秒</p>
                        <p><strong>状态:</strong> {'成功' if step['success'] else '失败'}</p>
                    """
                    
                    if step.get('details'):
                        details_id = f"details_{idx}_{step_idx}"
                        html += f"""
                        <div class="details-container">
                            <span class="details-toggle" onclick="toggleDetails('{details_id}')">显示详细信息</span>
                            <div class="details-content" id="{details_id}">
                        """
                        
                        # 处理不同类型的详细信息
                        if step['step'] == '文件分析':
                            if step['details'].get('file_type'):
                                html += f"<p><strong>文件类型:</strong> {step['details']['file_type']}</p>"
                            if step['details'].get('size'):
                                html += f"<p><strong>文件大小:</strong> {step['details']['size']} 字节</p>"
                            if step['details'].get('md5'):
                                html += f"<p><strong>MD5:</strong> {step['details']['md5']}</p>"
                            if step['details'].get('features'):
                                html += "<p><strong>特征:</strong></p><pre>" + json.dumps(step['details']['features'], indent=2, ensure_ascii=False) + "</pre>"
                                
                        elif step['step'] == '连接测试':
                            # 显示连接信息
                            if step['details'].get('connection_info'):
                                conn_info = step['details']['connection_info']
                                html += "<div class='test-pair'>"
                                html += "<h4>连接信息</h4>"
                                html += "<pre>" + json.dumps(conn_info, indent=2, ensure_ascii=False) + "</pre>"
                                html += "</div>"

                            # 显示测试命令和响应
                            if step['details'].get('test_commands') and step['details'].get('test_responses'):
                                for i, (cmd, resp) in enumerate(zip(
                                    step['details']['test_commands'], 
                                    step['details']['test_responses']
                                )):
                                    html += f"<div class='test-pair'>"
                                    html += f"<h4>测试 #{i+1}</h4>"
                                    
                                    # 解析并格式化发送的命令
                                    try:
                                        cmd_data = json.loads(cmd) if isinstance(cmd, str) else cmd
                                        html += "<div class='request-data'>"
                                        html += "<p><strong>发送的数据:</strong></p>"
                                        if isinstance(cmd_data, dict):
                                            if 'method' in cmd_data:
                                                html += f"<span class='http-method'>{cmd_data.get('method', 'GET')}</span> "
                                            if 'url' in cmd_data:
                                                html += f"<span class='http-url'>{cmd_data.get('url', '')}</span><br>"
                                            if 'headers' in cmd_data:
                                                html += "<span class='http-headers'>请求头:</span><br>"
                                                html += "<pre>" + json.dumps(cmd_data.get('headers', {}), indent=2) + "</pre>"
                                            if 'data' in cmd_data:
                                                html += "<span class='http-body'>请求体:</span><br>"
                                                html += "<pre>" + json.dumps(cmd_data.get('data', {}), indent=2) + "</pre>"
                                        else:
                                            html += f"<pre>{cmd}</pre>"
                                        html += "</div>"
                                    except:
                                        html += f"<div class='request-data'><pre>{cmd}</pre></div>"

                                    # 显示服务器响应
                                    html += "<div class='response-data'>"
                                    html += "<p><strong>服务器响应:</strong></p>"
                                    try:
                                        resp_data = json.loads(resp) if isinstance(resp, str) else resp
                                        html += "<pre>" + json.dumps(resp_data, indent=2, ensure_ascii=False) + "</pre>"
                                    except:
                                        html += f"<pre>{resp}</pre>"
                                    html += "</div>"
                                    
                                    html += "</div>"
                                
                        elif step['step'] == '保存配置' and step['details'].get('config'):
                            html += "<p><strong>配置信息:</strong></p><pre>" + json.dumps(step['details']['config'], indent=2, ensure_ascii=False) + "</pre>"
                            
                        html += "</div></div>"
                    
                    html += "</div>"
            
            html += "</div>"

    # 添加处理结果摘要
    if result.get('processed_files'):
        html += "<h2>成功处理的文件</h2>"
        for file in result['processed_files']:
            html += f"""
            <div class="file-item success">
                <p><strong>源文件:</strong> {file['source']}</p>
                <p><strong>目标文件:</strong> {file['target']}</p>
                <p><strong>状态:</strong> {'工作' if file['working'] else '未测试'}</p>
            </div>
            """

    if result.get('failed_files'):
        html += "<h2>处理失败的文件</h2>"
        for file_path in result['failed_files']:
            error_type = "连接测试失败" if file_path in result.get('test_results', {}).get('failed', []) else "处理失败"
            html += f"""
            <div class="file-item error">
                <p><strong>文件:</strong> {file_path}</p>
                <p><strong>状态:</strong> 失败</p>
                <p><strong>错误原因:</strong> {error_type}</p>
            </div>
            """

    html += """
        </div>
    </body>
    </html>
    """

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)
    
    logger.info(f"HTML报告已生成: {filename}")
    return filename