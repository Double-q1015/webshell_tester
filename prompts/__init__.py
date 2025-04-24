def get_prompt(prompt_name: str) -> str:
    """获取提示"""
    return prompts[prompt_name]

prompts = {
    "analysis_php_webshell": """
    你是一个PHP安全分析专家，请根据以下PHP代码判断其是否为WebShell，并尝试回答以下问题：

    1. 是否存在WebShell特征？
    2. 使用的连接方式是 password / assert / eval / system / mysql / file download 等哪种？
    3. 如果是password类型，请找出密码变量名、值（如果硬编码）、执行命令的参数名。
    4. 如果可执行命令，返回一个典型的 curl 请求示例。
    5. 是否支持上传功能？
    6. 是否有文件浏览功能？
    7. 有什么风险建议？

    代码如下：
    $$code$$    
    
    输出结果：
    {
    "is_webshell": true,
    "connection_type": "password",
    "password_info": {
        "variable_name": "pwd",
        "value": "test123",
        "command_param": "cmd",
        "command_method": "POST"
    },
    "command_example": "curl -X POST http://example.com/webshell.php -d 'pwd=test123&cmd=whoami'",
    "upload_support": false,
    "upload_params": null,
    "file_browse_support": false,
    "file_browse_params": null,
    "rce_capability": true,
    "obfuscation_detected": false,
    "risk_suggestions": [
        "使用硬编码密码进行命令执行，存在严重安全风险，建议更换验证方式。",
        "限制允许执行的命令集，避免任意命令执行。",
        "开启访问控制与日志监控，防止滥用和溯源。",
        "尽快清理该webshell，或对服务器进行全面安全加固。"
    ],
    "analysis_time": "2025-04-24T15:00:00Z",
    "file_path": "/var/www/html/webshell.php",
    "file_hash": "a1b2c3d4e5f67890"
    }

    """
}