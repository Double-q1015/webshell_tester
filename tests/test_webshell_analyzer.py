import unittest
import os
from pathlib import Path
from utils.webshell_organizer import WebshellAnalyzer
from utils.models import ConnectionInfo

class TestWebshellAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = WebshellAnalyzer()
        self.samples_dir = Path(__file__).parent / "samples"
        if not self.samples_dir.exists():
            self.samples_dir.mkdir(parents=True)

    def read_sample(self, filename: str) -> str:
        """读取测试样本文件"""
        with open(self.samples_dir / filename, 'r') as f:
            return f.read()

    def test_analyze_connection_simple_eval(self):
        """测试简单的eval型webshell"""
        content = self.read_sample("eval_simple.php")
        connection = self.analyzer._analyze_connection(content)
        self.assertEqual(connection.method, "POST")
        self.assertEqual(connection.param_name, "cmd")
        self.assertTrue(connection.eval_usage)
        self.assertFalse(connection.obfuscated)

    def test_analyze_connection_obfuscated_eval(self):
        """测试混淆的eval型webshell"""
        content = self.read_sample("obfuscated_eval.php")
        connection = self.analyzer._analyze_connection(content)
        self.assertEqual(connection.method, "POST")
        self.assertEqual(connection.param_name, "rcoil")
        self.assertTrue(connection.eval_usage)
        self.assertTrue(connection.obfuscated)

    def test_analyze_connection_request_param(self):
        """测试REQUEST参数型webshell"""
        content = self.read_sample("request_param.php")
        connection = self.analyzer._analyze_connection(content)
        self.assertEqual(connection.method, "POST")
        self.assertEqual(connection.param_name, "command")
        self.assertFalse(connection.eval_usage)

    def test_analyze_connection_special_features(self):
        """测试特殊特征检测"""
        # 从文件读取特殊认证样本
        user_agent_content = self.read_sample("user_agent_auth.php")
        
        # 测试特殊认证
        connection = self.analyzer._analyze_connection(user_agent_content)
        self.assertEqual(connection.method, "POST")
        self.assertEqual(connection.param_name, "cmd")
        self.assertTrue(connection.eval_usage)
        self.assertEqual(connection.special_auth.get('type'), 'user_agent')
        self.assertEqual(connection.special_auth.get('value'), 'special_key')
        
        # 测试其他特殊特征
        samples = {
            "base64": """<?php eval(base64_decode($_POST['b64'])); ?>""",
            "preg_replace": """<?php preg_replace("/\./e", $_POST['code'], "."); ?>""",
            "raw_post": """<?php $raw = file_get_contents("php://input"); eval($raw); ?>"""
        }
        
        for feature, content in samples.items():
            with self.subTest(feature=feature):
                connection = self.analyzer._analyze_connection(content)
                self.assertEqual(connection.method, "POST")
                
                if feature == "base64":
                    self.assertEqual(connection.encoding, "base64")
                    self.assertEqual(connection.param_name, "b64")
                elif feature == "preg_replace":
                    self.assertTrue(connection.preg_replace)
                    self.assertEqual(connection.param_name, "code")
                elif feature == "raw_post":
                    self.assertTrue(connection.use_raw_post)

    def test_analyze_connection_multiple_params(self):
        """测试多参数webshell"""
        content = """<?php
        if (isset($_POST['pass']) && $_POST['pass'] === 'secret') {
            eval($_POST['cmd']);
        }
        ?>"""
        connection = self.analyzer._analyze_connection(content)
        self.assertEqual(connection.method, "POST")
        self.assertEqual(connection.param_name, "cmd")
        self.assertEqual(connection.password, "secret")
        self.assertEqual(connection.password_param, "pass")

    def test_analyze_connection_no_params(self):
        """测试无参数的情况"""
        content = """<?php phpinfo(); ?>"""
        connection = self.analyzer._analyze_connection(content)
        self.assertIsInstance(connection, ConnectionInfo)
        self.assertIsNone(connection.param_name)
        self.assertFalse(connection.eval_usage)

if __name__ == '__main__':
    unittest.main() 