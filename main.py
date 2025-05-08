import asyncio
from loguru import logger
import argparse
from pathlib import Path
import os
import shutil
import tarfile
import io
import glob
import sys

from core.config import config
from core.environment import EnvironmentManager
from core.executor import test_webshell, create_connector
from core.shell_generator import ShellGenerator
from utils.mylogger import setup_logger
from utils.webshell_organizer import WebshellAnalyzer
from tools.prebuild_images import DockerImageBuilder
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

    async def run_tests(self, env_name: str, keep_container: bool = False):
        """运行所有测试"""
        logger.info("开始WebShell测试流程")
        container = None
        
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

            if keep_container:
                # 如果需要保持容器运行，输出容器信息
                container.reload()
                container_ip = container.attrs['NetworkSettings']['Networks'][config.docker_network]['IPAddress']
                logger.info("\n=== 容器信息 ===")
                logger.info(f"容器ID: {container.id}")
                logger.info(f"容器名称: {container.name}")
                logger.info(f"容器IP: {container_ip}")
                logger.info(f"Web根目录: /var/www/html")
                logger.info("\n使用以下命令停止并删除容器:")
                logger.info(f"docker stop {container.name}")
                logger.info(f"docker rm {container.name}")
                return container
        
        except Exception as e:
            logger.error(f"测试过程中发生错误: {str(e)}")
            if not keep_container and container:
                # 如果不需要保持容器运行，且发生错误，清理容器
                self.env_manager.destroy_environment(container)
                logger.info("测试环境已清理")
        
        finally:
            # 只有在不保持容器运行的情况下才清理环境
            if not keep_container:
                if 'container' in locals() and container:
                    self.env_manager.destroy_environment(container)
                    logger.info("测试环境已清理")
                
                # 清理生成的shells
                if os.path.exists(self.shells_dir):
                    shutil.rmtree(self.shells_dir)
                    logger.info("已清理生成的WebShell文件")

def analyze_single_file(file_path: str, verbose: bool = False, keep_container: bool = False) -> dict:
    """
    详细分析单个WebShell文件
    Args:
        file_path: WebShell文件路径
        verbose: 是否显示详细信息
        keep_container: 是否保持容器运行
    Returns:
        分析结果字典
    """
    logger.info(f"开始分析文件: {file_path}")
    
    if not os.path.exists(file_path):
        logger.error(f"文件不存在: {file_path}")
        return {
            'success': False,
            'error': '文件不存在'
        }
    
    try:
        analyzer = WebshellAnalyzer()
        config = analyzer.analyze_file(file_path)
        
        if not config:
            return {
                'success': False,
                'error': '文件分析失败'
            }
            
        # 基本信息分析
        result = {
            'success': True,
            'basic_info': {
                'file_type': config.type,
                'size': config.size,
                'md5': config.md5,
                'filename': config.filename
            },
            'connection_info': {},
            'features': {},
            'risk_level': 'low'  # 默认风险等级
        }
        
        # 连接方式分析
        if config.connection:
            result['connection_info'] = {
                'method': config.connection.method,
                'param_name': config.connection.param_name,
                'password': config.connection.password,
                'password_param': config.connection.password_param,
                'eval_usage': config.connection.eval_usage,
                'use_raw_post': config.connection.use_raw_post,
                'encoding': config.connection.encoding,
                'special_auth': config.connection.special_auth
            }
            
            # 根据连接方式评估风险
            if config.connection.eval_usage:
                result['risk_level'] = 'high'
            elif config.connection.use_raw_post:
                result['risk_level'] = 'medium'
                
        # 特征分析
        if config.features:
            result['features'] = {
                'file_upload': config.features.file_upload,
                'command_exec': config.features.command_exec,
                'eval_usage': config.features.eval_usage,
                'database_ops': config.features.database_ops,
                'obfuscated': config.features.obfuscated
            }
            
            # 根据特征评估风险
            if config.features.eval_usage or config.features.obfuscated:
                result['risk_level'] = 'high'
            elif config.features.file_upload or config.features.command_exec:
                result['risk_level'] = 'medium'
                
        # 代码分析
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        # 检测危险函数
        dangerous_functions = {
            'system': '系统命令执行',
            'exec': '命令执行',
            'shell_exec': 'Shell命令执行',
            'passthru': '命令执行并直接输出',
            'popen': '创建进程',
            'proc_open': '进程操作',
            'eval': '代码执行',
            'assert': '代码执行',
            'preg_replace': '正则替换（可能用于代码执行）',
            'create_function': '动态创建函数',
            'include': '文件包含',
            'include_once': '文件包含',
            'require': '文件包含',
            'require_once': '文件包含',
            'mysql_': '数据库操作',
            'mysqli_': '数据库操作',
            'sqlite': '数据库操作',
            'pdo': '数据库操作',
            'fwrite': '文件写入',
            'file_put_contents': '文件写入',
            'move_uploaded_file': '文件上传'
        }
        
        result['dangerous_functions'] = []
        for func, desc in dangerous_functions.items():
            if func in content:
                result['dangerous_functions'].append({
                    'function': func,
                    'description': desc
                })
                
        # 检测混淆特征
        obfuscation_features = {
            'base64_decode': 'Base64解码',
            'str_rot13': 'ROT13编码',
            'gzinflate': 'Gzip解压',
            'gzuncompress': 'Gzip解压',
            'strrev': '字符串反转',
            '\\x[0-9a-fA-F]{2}': '十六进制编码'
        }
        
        result['obfuscation_techniques'] = []
        for feature, desc in obfuscation_features.items():
            if feature in content:
                result['obfuscation_techniques'].append({
                    'technique': feature,
                    'description': desc
                })
                
        # 输出分析结果
        logger.info("\n=== WebShell分析报告 ===")
        logger.info(f"文件: {file_path}")
        logger.info(f"类型: {result['basic_info']['file_type']}")
        logger.info(f"大小: {result['basic_info']['size']} 字节")
        logger.info(f"MD5: {result['basic_info']['md5']}")
        logger.info(f"风险等级: {result['risk_level']}")
        
        if result['connection_info']:
            logger.info("\n连接信息:")
            logger.info(f"方法: {result['connection_info']['method']}")
            if result['connection_info']['param_name']:
                logger.info(f"命令参数名: {result['connection_info']['param_name']}")
            if result['connection_info']['password']:
                logger.info(f"密码: {result['connection_info']['password']}")
            if result['connection_info']['eval_usage']:
                logger.info("使用eval执行")
            if result['connection_info']['use_raw_post']:
                logger.info("使用原始POST数据")
            if result['connection_info']['special_auth']:
                logger.info(f"特殊认证: {result['connection_info']['special_auth']}")
        
        if result['features']:
            logger.info("\n特征:")
            if result['features']['file_upload']:
                logger.info("- 具有文件上传功能")
            if result['features']['command_exec']:
                logger.info("- 具有命令执行功能")
            if result['features']['eval_usage']:
                logger.info("- 使用eval执行代码")
            if result['features']['database_ops']:
                logger.info("- 具有数据库操作功能")
            if result['features']['obfuscated']:
                logger.info("- 代码已混淆")
        
        if result['dangerous_functions']:
            logger.info("\n发现危险函数:")
            for func in result['dangerous_functions']:
                logger.info(f"- {func['function']}: {func['description']}")
        
        if result['obfuscation_techniques']:
            logger.info("\n发现混淆技术:")
            for tech in result['obfuscation_techniques']:
                logger.info(f"- {tech['technique']}: {tech['description']}")
        
        if verbose:
            logger.info("\n完整配置信息:")
            import json
            logger.info(json.dumps(config.to_dict(), indent=2, ensure_ascii=False))

        # 如果需要测试连接，启动容器并测试
        if keep_container:
            logger.info("\n=== 开始连接测试 ===")
            tester = WebShellTester()
            container = asyncio.run(tester.run_tests('php7.4_apache', keep_container=True))
            if container:
                logger.info("\n容器已启动并保持运行")
                logger.info("请在测试完成后手动停止和删除容器")
        
        return result
        
    except Exception as e:
        logger.error(f"分析过程出错: {str(e)}")
        import traceback
        logger.debug(f"错误详情:\n{traceback.format_exc()}")
        return {
            'success': False,
            'error': str(e)
        }

def main():
    setup_logger()
    
    parser = argparse.ArgumentParser(description='WebShell Tester')
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    
    # 添加analyze命令
    analyze_parser = subparsers.add_parser('analyze', help='Analyze a single WebShell file')
    analyze_parser.add_argument('file', help='The path to the file to analyze')
    analyze_parser.add_argument('-v', '--verbose', action='store_true', help='Show detailed information')
    
    # 添加test命令
    test_parser = subparsers.add_parser('test', help='Test WebShell')
    test_parser.add_argument('--env', default='php7.4_apache', help='Test environment type')
    # 列出支持的环境
    list_envs_parser = subparsers.add_parser('list-envs', help='List supported environments')
    
    args = parser.parse_args()
    
    if args.command == 'analyze':
        result = analyze_single_file(args.file, args.verbose)
        if not result['success']:
            logger.error(f"分析失败: {result.get('error', '未知错误')}")
            sys.exit(1)
    elif args.command == 'test':
        tester = WebShellTester()
        asyncio.run(tester.run_tests(args.env))

    elif args.command == 'list-envs':
        builder = DockerImageBuilder()
        logger.info("Supported environments:")
        for status in builder.list_images():
            logger.info(f"\n- {status['name']}:")
            logger.info(f"  Image: {status['tag']}")
            if 'status' in status:
                logger.info(f"  Status: {status['status']}")
            else:
                logger.info(f"  ID: {status['id']}")
                logger.info(f"  Size: {status['size']}")
                logger.info(f"  Created: {status['created']}")
                if status['containers']:
                    logger.info(f"  Running containers: {', '.join(status['containers'])}")
                if status.get('build_args'):
                    logger.info(f"  Default build arguments: {status['build_args']}")
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()