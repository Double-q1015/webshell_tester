import os
import unittest
import shutil
from core.shell_generator import ShellGenerator

class TestShellGenerator(unittest.TestCase):
    def setUp(self):
        self.generator = ShellGenerator()
        self.test_dir = 'test_shells'
        os.makedirs(self.test_dir, exist_ok=True)
        self.test_output_dir = "test_shells"
        
    def tearDown(self):
        # 清理测试生成的文件
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
        if os.path.exists(self.test_output_dir):
            for file in os.listdir(self.test_output_dir):
                os.remove(os.path.join(self.test_output_dir, file))
            os.rmdir(self.test_output_dir)
            
    def test_generate_php_shell(self):
        # 测试生成基本PHP shell
        file_path = self.generator.generate_shell(
            shell_type='php',
            template_type='basic',
            output_dir=self.test_output_dir
        )
        self.assertTrue(os.path.exists(file_path))
        self.assertTrue(file_path.endswith('.php'))
        
        # 验证文件内容
        with open(file_path, 'r') as f:
            content = f.read()
            self.assertIn('<?php', content)
            self.assertIn('system($cmd)', content)
            
    def test_generate_jsp_shell(self):
        # 测试生成JSP shell
        file_path = self.generator.generate_shell(
            shell_type='jsp',
            output_dir=self.test_output_dir
        )
        self.assertTrue(os.path.exists(file_path))
        self.assertTrue(file_path.endswith('.jsp'))
        
    def test_custom_filename(self):
        # 测试使用自定义文件名
        custom_filename = "my_shell.php"
        file_path = self.generator.generate_shell(
            shell_type='php',
            output_dir=self.test_output_dir,
            filename=custom_filename
        )
        self.assertEqual(os.path.basename(file_path), custom_filename)
        
    def test_add_template(self):
        # 测试添加新模板
        new_template = "<?php echo 'test'; ?>"
        self.generator.add_template('php', 'custom', new_template)
        
        file_path = self.generator.generate_shell(
            shell_type='php',
            template_type='custom',
            output_dir=self.test_output_dir
        )
        
        with open(file_path, 'r') as f:
            content = f.read()
            self.assertEqual(content, new_template)
            
    def test_invalid_shell_type(self):
        # 测试无效的shell类型
        with self.assertRaises(ValueError):
            self.generator.generate_shell(
                shell_type='invalid',
                output_dir=self.test_output_dir
            )

    def test_php_curl_shell(self):
        # 测试PHP curl shell
        file_path = self.generator.generate_shell(
            shell_type='php',
            template_type='curl',
            output_dir=self.test_output_dir
        )
        with open(file_path, 'r') as f:
            content = f.read()
            self.assertIn('curl_init()', content)
            self.assertIn('CURLOPT_URL', content)

    def test_php_wget_shell(self):
        # 测试PHP wget shell
        file_path = self.generator.generate_shell(
            shell_type='php',
            template_type='wget',
            output_dir=self.test_output_dir
        )
        with open(file_path, 'r') as f:
            content = f.read()
            self.assertIn('wget', content)
            self.assertIn('$url', content)

    def test_jsp_file_browser(self):
        # 测试JSP文件浏览器
        file_path = self.generator.generate_shell(
            shell_type='jsp',
            template_type='file_browser',
            output_dir=self.test_output_dir
        )
        with open(file_path, 'r') as f:
            content = f.read()
            self.assertIn('File[] files', content)
            self.assertIn('listFiles()', content)

    def test_aspx_powershell(self):
        # 测试ASPX PowerShell shell
        file_path = self.generator.generate_shell(
            shell_type='aspx',
            template_type='powershell',
            output_dir=self.test_output_dir
        )
        with open(file_path, 'r') as f:
            content = f.read()
            self.assertIn('powershell.exe', content)
            self.assertIn('-ExecutionPolicy Bypass', content)

    def test_file_upload_shells(self):
        # 测试文件上传功能
        for shell_type in ['php', 'aspx']:
            file_path = self.generator.generate_shell(
                shell_type=shell_type,
                template_type='file_upload',
                output_dir=self.test_output_dir
            )
            with open(file_path, 'r') as f:
                content = f.read()
                self.assertIn('upload', content.lower())
                self.assertIn('file', content.lower())

    def test_weevely_shell_generation(self):
        # 测试weevely shell生成
        test_password = "mypass123"
        file_path = self.generator.generate_shell(
            shell_type='weevely',
            password=test_password,
            output_dir=self.test_output_dir,
            filename='weevely_shell.php'
        )
        self.assertTrue(os.path.exists(file_path))
        self.assertTrue(file_path.endswith('.php'))
        
        # 验证文件内容（weevely生成的shell是加密的，所以只能检查文件是否存在和不为空）
        self.assertTrue(os.path.getsize(file_path) > 0)

    def test_weevely_shell_without_password(self):
        # 测试没有密码时的weevely shell生成
        with self.assertRaises(ValueError):
            self.generator.generate_shell(
                shell_type='weevely',
                output_dir=self.test_output_dir,
                filename='weevely_shell.php'
            )

    def test_weevely_convenience_method(self):
        # 测试便捷方法
        test_password = "mypass123"
        output_path = os.path.join(self.test_output_dir, 'weevely_shell.php')
        file_path = self.generator.generate_weevely_shell(
            password=test_password,
            output_path=output_path
        )
        self.assertTrue(os.path.exists(file_path))
        self.assertEqual(file_path, output_path)
        self.assertTrue(os.path.getsize(file_path) > 0)

    def test_get_available_types_includes_weevely(self):
        # 测试可用类型中包含weevely
        available_types = self.generator.get_available_types()
        self.assertIn('weevely', available_types)
        self.assertIn('default', available_types['weevely'])

    def test_generate_weevely_shell(self):
        """测试生成weevely shell"""
        password = "test_password"
        filename = "test_weevely.php"
        try:
            output_path = self.generator.generate_shell(
                shell_type='php',
                template_type='weevely',
                filename=filename,
                output_dir=self.test_dir,
                password=password
            )
            
            self.assertTrue(os.path.exists(output_path))
            self.assertEqual(os.path.basename(output_path), filename)
            
            # 检查文件内容（weevely生成的shell是加密的，所以只检查基本特征）
            with open(output_path, 'r') as f:
                content = f.read()
                self.assertIn('<?php', content)
                self.assertGreater(len(content), 100)  # weevely shell通常较长
                
        except RuntimeError as e:
            if "weevely命令执行失败" in str(e):
                self.skipTest("Weevely工具未安装，跳过测试")
                
    def test_generate_weevely_shell_without_password(self):
        """测试在没有提供密码的情况下生成weevely shell"""
        with self.assertRaises(ValueError) as context:
            self.generator.generate_shell(
                shell_type='php',
                template_type='weevely',
                output_dir=self.test_dir
            )
        self.assertIn("生成weevely shell需要提供密码", str(context.exception))

if __name__ == '__main__':
    unittest.main() 