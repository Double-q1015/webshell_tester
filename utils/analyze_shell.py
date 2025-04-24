import re
import base64
from typing import Optional

class ConnectionInfo:
    def __init__(self, method, password, cmd_param, encoding, key, exec_func):
        self.method = method
        self.password = password
        self.cmd_param = cmd_param
        self.encoding = encoding
        self.key = key
        self.exec_func = exec_func

    def __str__(self):
        return (f"请求方法: {self.method}\n"
                f"密码参数: {self.password}\n"
                f"命令参数: {self.cmd_param}\n"
                f"编码方式: {self.encoding}\n"
                f"加密密钥: {self.key}\n"
                f"执行函数: {self.exec_func}\n")

def analyze_webshell(content: str) -> Optional[ConnectionInfo]:
    # 密码参数
    password_param = None
    method = "POST"
    cmd_param = None
    encoding = "raw"
    key = None
    exec_func = None

    # 常见密码参数匹配
    param_patterns = [
        (r"\$_POST\[['\"](\w+)['\"]\]", "POST"),
        (r"\$_GET\[['\"](\w+)['\"]\]", "GET"),
        (r"\$_REQUEST\[['\"](\w+)['\"]\]", "POST"),
    ]

    # 执行函数匹配
    exec_funcs = ['eval', 'assert', 'preg_replace', '__invoke', 'system', 'shell_exec', 'passthru', 'call_user_func']

    # 先找密码参数和命令参数
    for pattern, mtd in param_patterns:
        matches = re.findall(pattern, content)
        if matches:
            for m in matches:
                low = m.lower()
                if low in ['cmd','command','exec','system','shell']:
                    cmd_param = m
                else:
                    password_param = m
                    method = mtd

    # 找执行函数
    for func in exec_funcs:
        if func == '__invoke':
            # 特殊处理 __invoke 类执行
            if re.search(r'class\s+\w+.*?function\s+__invoke', content, re.S):
                exec_func = '__invoke'
                break
        else:
            if func in content:
                exec_func = func
                break

    # 编码检测
    if 'base64_decode' in content or 'base64_encode' in content:
        encoding = 'base64'

    # AES Key检测
    key_match = re.search(r"\$key\s*=\s*['\"]([0-9a-fA-F]+)['\"]", content)
    if key_match:
        key = key_match.group(1)

    # XOR密钥匹配：简单匹配变量名或硬编码字符串
    if not key:
        xor_key_match = re.search(r"\$key\s*=\s*['\"](.{8,16})['\"]", content)
        if xor_key_match:
            key = xor_key_match.group(1)

    # 默认命令参数
    if not cmd_param:
        cmd_param = 'cmd'

    if not password_param:
        password_param = 'pass'

    return ConnectionInfo(method, password_param, cmd_param, encoding, key, exec_func)


def generate_curl(shell_url: str, info: ConnectionInfo) -> str:
    example_cmd = "echo 'test'"
    key = info.key

    if info.encoding == 'base64' and key:
        # 这里示例用python生成加密payload伪代码
        enc_cmd = f"base64_encoded_encrypted_payload"
        data = f"{info.password}={enc_cmd}"
    else:
        data = f"{info.password}={example_cmd}"

    curl_cmd = (f"curl -X {info.method} '{shell_url}' "
                f"-d '{data}'")

    return curl_cmd


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("用法: python analyze_shell.py [shell_path.php] [shell_url]")
        sys.exit(1)

    shell_path = sys.argv[1]
    shell_url = sys.argv[2]

    with open(shell_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    info = analyze_webshell(content)
    if not info:
        print("未能分析出连接信息")
        sys.exit(1)

    print("=== WebShell连接分析结果 ===")
    print(info)

    print("=== 示例curl连接命令 ===")
    print(generate_curl(shell_url, info))
