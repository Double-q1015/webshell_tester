import asyncio
from loguru import logger
import argparse
from pathlib import Path
import os
import shutil
import tarfile
import io
import glob

from core.config import config
from core.environment import EnvironmentManager
from core.executor import test_webshell, create_connector
from core.shell_generator import ShellGenerator
from utils.mylogger import setup_logger

class WebShellTester:
    def __init__(self):
        self.env_manager = EnvironmentManager()
        self.shell_generator = ShellGenerator()
        self.shells_dir = "generated_shells"
        self.existing_shells_dir = "shells"
        self.test_commands = [
            "whoami",
            "id",
            "pwd",
            "ls -la",
            "uname -a"
        ]
        
        # 环境类型到支持的shell类型的映射
        self.env_shell_mapping = {
            'php7.4_apache': ['php'],  # PHP环境只测试PHP webshell
            'tomcat': ['jsp'],         # Tomcat环境测试JSP webshell
            'iis': ['aspx']           # IIS环境测试ASPX webshell
        }
        
        # Shell类型到连接器类型的映射
        self.shell_type_mapping = {
            'php': {
                'basic': 'password',
                'eval': 'eval',
                'curl': 'password',
                'wget': 'password',
                'file_upload': 'password'
            },
            'jsp': {
                'basic': 'parameter',
                'file_browser': 'parameter'
            },
            'aspx': {
                'basic': 'parameter',
                'powershell': 'parameter'
            }
        }
        
        # 添加现有shell的配置
        self.existing_shell_configs = {
            'simple-backdoor.php': {'type': 'password', 'params': {'password': 'test123', 'param_name': 'cmd'}},
            'eval.php': {'type': 'eval', 'params': {'param_name': 'code'}},
            'assert.php': {'type': 'assert', 'params': {'param_name': '_'}},
            'php-backdoor.php': {'type': 'password', 'params': {'password': 'test123', 'param_name': 'cmd'}},
            'qsd-php-backdoor.php': {'type': 'password', 'params': {'password': 'test123', 'param_name': 'cmd'}}
        }

    def generate_shells(self, env_type: str) -> list:
        """根据环境类型生成对应的webshell"""
        logger.info("开始生成WebShell")
        os.makedirs(self.shells_dir, exist_ok=True)
        
        generated_shells = []
        supported_types = self.env_shell_mapping.get(env_type, [])
        
        if not supported_types:
            logger.warning(f"未知的环境类型: {env_type}")
            return generated_shells
            
        logger.info(f"当前环境 {env_type} 支持的shell类型: {supported_types}")
        
        # 只生成环境支持的shell类型
        if 'php' in supported_types:
            # 生成PHP shells
            php_types = ['basic', 'eval', 'curl', 'wget', 'file_upload']
            for shell_type in php_types:
                filename = f"shell_php_{shell_type}.php"
                path = self.shell_generator.generate_shell(
                    shell_type='php',
                    template_type=shell_type,
                    output_dir=self.shells_dir,
                    filename=filename
                )
                generated_shells.append({
                    'path': path,
                    'type': self.shell_type_mapping['php'][shell_type],
                    'name': filename
                })
                
            # 生成Weevely shell
            try:
                weevely_path = self.shell_generator.generate_shell(
                    shell_type='php',
                    template_type='weevely',
                    output_dir=self.shells_dir,
                    filename="shell_weevely.php",
                    password="mypass123"
                )
                generated_shells.append({
                    'path': weevely_path,
                    'type': 'weevely',
                    'name': "shell_weevely.php",
                    'password': "mypass123"
                })
            except Exception as e:
                logger.error(f"生成weevely shell失败: {str(e)}")
                
        if 'jsp' in supported_types:
            # 生成JSP shells
            jsp_types = ['basic', 'file_browser']
            for shell_type in jsp_types:
                filename = f"shell_jsp_{shell_type}.jsp"
                path = self.shell_generator.generate_shell(
                    shell_type='jsp',
                    template_type=shell_type,
                    output_dir=self.shells_dir,
                    filename=filename
                )
                generated_shells.append({
                    'path': path,
                    'type': self.shell_type_mapping['jsp'][shell_type],
                    'name': filename
                })
                
        if 'aspx' in supported_types:
            # 生成ASPX shells
            aspx_types = ['basic', 'powershell']
            for shell_type in aspx_types:
                filename = f"shell_aspx_{shell_type}.aspx"
                path = self.shell_generator.generate_shell(
                    shell_type='aspx',
                    template_type=shell_type,
                    output_dir=self.shells_dir,
                    filename=filename
                )
                generated_shells.append({
                    'path': path,
                    'type': self.shell_type_mapping['aspx'][shell_type],
                    'name': filename
                })
            
        logger.info(f"成功生成 {len(generated_shells)} 个WebShell")
        return generated_shells

    def copy_to_container(self, container, shell_path: str, shell_name: str) -> bool:
        """复制webshell到容器web目录"""
        try:
            # 获取容器web目录
            web_root = "/var/www/html"  # 默认Apache路径
            
            # 创建内存中的tar文件
            tar_stream = io.BytesIO()
            with tarfile.open(fileobj=tar_stream, mode='w') as tar:
                # 添加文件到tar
                tar.add(shell_path, arcname=shell_name)
            
            # 将tar流定位到开始
            tar_stream.seek(0)
            
            # 复制文件到容器
            container.put_archive(web_root, tar_stream.read())
            
            logger.info(f"成功复制 {shell_name} 到容器 {container.name}")
            return True
        except Exception as e:
            logger.error(f"复制文件到容器失败: {str(e)}")
            return False

    async def test_shell(self, container, shell_info: dict) -> dict:
        """测试单个webshell"""
        try:
            # 获取容器IP
            container.reload()
            container_ip = container.attrs['NetworkSettings']['Networks'][config.docker_network]['IPAddress']
            
            # 构建WebShell URL
            webshell_url = f"http://{container_ip}/{shell_info['name']}"
            
            # 根据shell类型准备连接器参数
            connector_kwargs = {}
            if shell_info['type'] == 'password':
                connector_kwargs = {
                    "password": "test123",
                    "param_name": "cmd"
                }
            elif shell_info['type'] == 'eval':
                connector_kwargs = {
                    "param_name": "code"
                }
            elif shell_info['type'] == 'parameter':
                connector_kwargs = {
                    "param_name": "cmd"
                }
            elif shell_info['type'] == 'weevely':
                connector_kwargs = {
                    "password": shell_info.get('password', 'test123')
                }
            
            # 创建连接器
            connector = create_connector(shell_info['type'], **connector_kwargs)
            
            # 执行测试
            test_results = await test_webshell(
                url=webshell_url,
                connector=connector,
                commands=self.test_commands
            )
            
            return {
                'shell_name': shell_info['name'],
                'results': test_results
            }
            
        except Exception as e:
            logger.error(f"测试 {shell_info['name']} 失败: {str(e)}")
            return {
                'shell_name': shell_info['name'],
                'error': str(e)
            }

    def get_existing_shells(self, env_type: str) -> list:
        """获取与环境类型匹配的现有webshell"""
        shells = []
        supported_types = self.env_shell_mapping.get(env_type, [])
        
        if os.path.exists(self.existing_shells_dir):
            for shell_file in os.listdir(self.existing_shells_dir):
                shell_type = shell_file.split('.')[-1]  # 获取文件扩展名
                if shell_type in supported_types:  # 只添加环境支持的shell类型
                    shell_path = os.path.join(self.existing_shells_dir, shell_file)
                    if shell_file in self.existing_shell_configs:
                        shells.append({
                            'path': shell_path,
                            'name': shell_file,
                            **self.existing_shell_configs[shell_file]
                        })
                    
        return shells

    async def test_existing_shells(self, container) -> list:
        """测试现有的webshell文件"""
        results = []
        existing_shells = self.get_existing_shells()
        
        for shell_info in existing_shells:
            logger.info(f"正在测试现有shell: {shell_info['name']}")
            
            # 复制shell到容器
            if self.copy_to_container(container, shell_info['path'], shell_info['name']):
                # 获取容器IP
                container.reload()
                container_ip = container.attrs['NetworkSettings']['Networks'][config.docker_network]['IPAddress']
                
                # 构建WebShell URL
                webshell_url = f"http://{container_ip}/{shell_info['name']}"
                
                # 创建连接器
                connector = create_connector(shell_info['type'], **shell_info['params'])
                
                try:
                    # 执行测试
                    test_results = await test_webshell(
                        url=webshell_url,
                        connector=connector,
                        commands=self.test_commands
                    )
                    
                    results.append({
                        'shell_name': shell_info['name'],
                        'results': test_results
                    })
                    
                except Exception as e:
                    logger.error(f"测试 {shell_info['name']} 失败: {str(e)}")
                    results.append({
                        'shell_name': shell_info['name'],
                        'error': str(e)
                    })
                    
        return results

    async def run_tests(self, env_name: str):
        """运行所有测试"""
        logger.info("开始WebShell测试流程")
        
        try:
            # 生成对应环境支持的webshell
            generated_shells = self.generate_shells(env_name)
            
            # 构建测试环境
            container = self.env_manager.build_environment(env_name)
            logger.info(f"环境构建成功: {container.name}")
            
            # 等待环境就绪
            if not self.env_manager.wait_for_ready(container):
                raise Exception("环境启动超时")
            
            # 测试结果
            test_results = []
            
            # 测试生成的shells
            for shell_info in generated_shells:
                if self.copy_to_container(container, shell_info['path'], shell_info['name']):
                    result = await self.test_shell(container, shell_info)
                    test_results.append(result)
            
            # 测试现有的shells
            existing_shells = self.get_existing_shells(env_name)
            existing_results = await self.test_existing_shells(container)
            test_results.extend(existing_results)
            
            # 输出测试结果
            logger.info("\n=== 测试结果汇总 ===")
            for result in test_results:
                logger.info(f"\nWebShell: {result['shell_name']}")
                if 'error' in result:
                    logger.error(f"测试失败: {result['error']}")
                else:
                    logger.info(f"总命令数: {result['results']['total_commands']}")
                    logger.info(f"成功执行: {result['results']['successful_commands']}")
                    logger.info(f"平均执行时间: {result['results']['average_execution_time']:.2f}秒")
        
        except Exception as e:
            logger.error(f"测试过程中发生错误: {str(e)}")
        
        finally:
            # 清理环境
            if 'container' in locals():
                self.env_manager.destroy_environment(container)
                logger.info("测试环境已清理")
            
            # 清理生成的shells
            if os.path.exists(self.shells_dir):
                shutil.rmtree(self.shells_dir)
                logger.info("已清理生成的WebShell文件")

if __name__ == "__main__":
    # 配置命令行参数
    parser = argparse.ArgumentParser(description="WebShell自动化测试工具")
    parser.add_argument("--env", default="php7.4_apache", help="测试环境名称")
    
    args = parser.parse_args()
    
    # 配置日志
    setup_logger()
    
    # 创建测试器并运行测试
    tester = WebShellTester()
    asyncio.run(tester.run_tests(args.env))