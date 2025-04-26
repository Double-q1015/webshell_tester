import os
import sys
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.webshell_analyzer import WebshellAnalyzer

test_path = os.path.join(os.path.dirname(__file__), "data")

def test_analyze_connection_eval_php():
    analyzer = WebshellAnalyzer()
    file_path = os.path.join(test_path, "php/eval.php")
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    connection_info = analyzer._analyze_connection(content)
    logger.info("Connection Info: %s", connection_info.to_dict())
    assert connection_info.method == "POST"
    assert connection_info.param_name == "code"

def test_analyze_connection_assert_php():
    analyzer = WebshellAnalyzer()
    file_path = os.path.join(test_path, "php/assert.php")
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    connection_info = analyzer._analyze_connection(content)
    logger.info("Connection Info: %s", connection_info.to_dict())
    assert connection_info.method == 'POST'
    assert connection_info.param_name == "_"

def test_analyze_connection_password():
    analyzer = WebshellAnalyzer()
    file_path = os.path.join(test_path, "php/password.php")
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    connection_info = analyzer._analyze_connection(content)
    logger.info("Connection Info: %s", connection_info.to_dict())
    assert connection_info.method == 'POST'
    assert connection_info.password == 'cmd'
    assert connection_info.param_name == "pwd"

def test_analyze_connection_simple_backdoor():
    analyzer = WebshellAnalyzer()
    file_path = os.path.join(test_path, "php/simple-backdoor.php")
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    connection_info = analyzer._analyze_connection(content)
    logger.info("Connection Info: %s", connection_info.to_dict())
    assert connection_info.method == 'POST'
    assert connection_info.password == 'cmd'
    assert connection_info.param_name == "cmd"

def test_analyze_connection_qsd_php_backdoor():
    analyzer = WebshellAnalyzer()
    file_path = os.path.join(test_path, "php/qsd-php-backdoor.php")
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
    connection_info = analyzer._analyze_connection(content)
    logger.info("Connection Info: %s", connection_info.to_dict())


if __name__ == "__main__":
    test_analyze_connection_qsd_php_backdoor()
    