#!/usr/bin/env python3
import os
import sys
import time
import docker
import requests
import tempfile
import shutil
from typing import Optional, Dict, Any, Tuple
from loguru import logger
import base64
import urllib.parse
import traceback
import asyncio
import aiohttp

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.models import WebshellConfig, ConnectionInfo
from core.executor import (
    BaseConnector, PasswordConnector, EvalConnector, 
    AssertConnector, ParameterConnector, test_webshell,
    BaseExecutor
)

class WebshellTester:
    def __init__(self, keep_container: bool = False):
        self.client = docker.from_env()
        self.test_commands = ["echo 'test';", "id;", "pwd;"]  # 基本测试命令
        self.network_name = 'webshell_test'
        self.logger = logger
        self.last_commands = []  # 记录最后一次测试的命令
        self.last_responses = []  # 记录最后一次测试的响应
        self._ensure_network()
        self.logger.debug("WebshellTester初始化完成")
        self.keep_container = keep_container

    def _ensure_network(self):
        """确保Docker网络存在"""
        try:
            # 检查网络是否存在
            networks = self.client.networks.list(names=[self.network_name])
            if not networks:
                logger.debug(f"创建Docker网络: {self.network_name}")
                self.client.networks.create(
                    name=self.network_name,
                    driver="bridge",
                    check_duplicate=True
                )
            else:
                logger.debug(f"使用现有Docker网络: {self.network_name}")
        except Exception as e:
            logger.error(f"设置Docker网络失败: {str(e)}")
            logger.debug(traceback.format_exc())

    def _create_connector(self, webshell_config: WebshellConfig) -> BaseConnector:
        """根据webshell配置创建合适的连接器"""
        # 检查是否是eval/assert类型
        if webshell_config.features.eval_usage:
            if 'assert' in webshell_config.filename.lower():
                return AssertConnector(param_name=webshell_config.connection.password)
            else:
                return EvalConnector(param_name=webshell_config.connection.password)
        
        # 检查是否是JSP/ASPX
        if webshell_config.type in ['jsp', 'aspx']:
            return ParameterConnector(param_name=webshell_config.connection.param_name)
        
        # 默认使用密码型连接器
        return PasswordConnector(
            password=webshell_config.connection.password,
            param_name=webshell_config.connection.param_name
        )

    def setup_test_env(self, temp_dir: str) -> Optional[docker.models.containers.Container]:
        """设置测试环境"""
        try:
            self.logger.debug(f"开始设置测试环境，临时目录: {temp_dir}")
            
            # 设置目录权限
            os.chmod(temp_dir, 0o755)
            for root, dirs, files in os.walk(temp_dir):
                for d in dirs:
                    os.chmod(os.path.join(root, d), 0o755)
                for f in files:
                    os.chmod(os.path.join(root, f), 0o644)
            
            # 选择合适的Docker镜像
            image = 'webshell_test_php7.4_apache:latest'  # 默认使用PHP环境
            mount_point = '/var/www/html'
            
            # 启动容器
            self.logger.debug(f"开始启动容器: {image}")
            container = self.client.containers.run(
                image,
                detach=True,
                network=self.network_name,  # 使用类变量
                volumes={
                    temp_dir: {
                        'bind': mount_point,
                        'mode': 'rw'
                    }
                },
                remove=True
            )
            self.logger.debug(f"容器启动成功: {container.id}")

            # 等待容器启动
            self.logger.debug("等待容器初始化...")
            time.sleep(2)

            # 检查容器状态
            container.reload()
            self.logger.debug(f"容器状态: {container.status}")
            
            # 检查容器日志
            logs = container.logs().decode('utf-8', errors='ignore')
            self.logger.debug(f"容器日志:\n{logs}")

            return container

        except Exception as e:
            self.logger.error(f"设置测试环境失败: {str(e)}")
            self.logger.debug(traceback.format_exc())
            return None

    def _get_container_ip(self, container: docker.models.containers.Container) -> Optional[str]:
        """获取容器IP地址"""
        try:
            container.reload()
            return container.attrs['NetworkSettings']['Networks'][self.network_name]['IPAddress']
        except Exception as e:
            self.logger.error(f"获取容器IP失败: {str(e)}")
            return None

    def cleanup_env(self, container: docker.models.containers.Container):
        """清理测试环境"""
        try:
            if container:
                container.stop()
                self.logger.debug(f"停止容器: {container.id}")
        except Exception as e:
            self.logger.error(f"清理测试环境失败: {str(e)}")
            self.logger.debug(traceback.format_exc())

    async def test_connection(self, webshell_file: str, connection_info: ConnectionInfo) -> bool:
        """
        测试WebShell连接
        """
        container = None
        temp_dir = None
        self.last_commands = []  # 清空上次的记录
        self.last_responses = []  # 清空上次的记录
        
        try:
            # 创建临时目录
            temp_dir = tempfile.mkdtemp()
            self.logger.debug(f"创建临时目录: {temp_dir}")
            
            # 复制文件到临时目录
            target_file = os.path.join(temp_dir, os.path.basename(webshell_file))
            shutil.copy2(webshell_file, target_file)
            self.logger.debug(f"复制文件到: {target_file}")
            
            # 设置测试环境
            container = self.setup_test_env(temp_dir)
            if not container:
                self.logger.error("设置测试环境失败")
                return False
            
            # 等待容器就绪
            await asyncio.sleep(2)
            
            # 获取容器IP
            container_ip = self._get_container_ip(container)
            if not container_ip:
                self.logger.error("获取容器IP失败")
                return False
            
            self.logger.debug(f"容器IP: {container_ip}")
            
            # 构建WebShell URL
            webshell_url = f"http://{container_ip}/{os.path.basename(webshell_file)}"
            self.logger.debug(f"WebShell URL: {webshell_url}")
            
            # 测试连接
            executor = BaseExecutor()
            test_results = await test_webshell(
                webshell_url,
                connection_info,
                executor
            )
            
            # 记录测试命令和响应
            if 'requests' in test_results:
                self.last_commands = test_results['requests']
            if 'responses' in test_results:
                self.last_responses = test_results['responses']
            
            if not test_results['success']:
                self.logger.error(f"连接测试失败: {test_results.get('error', '未知错误')}")
                if 'details' in test_results:
                    self.logger.debug(f"错误详情: {test_results['details']}")
                return False
            
            self.logger.info("连接测试成功")
            return True
            
        except Exception as e:
            self.logger.error(f"测试连接时发生错误: {str(e)}")
            self.logger.debug(f"错误详情:\n{traceback.format_exc()}")
            return False
            
        finally:
            if not self.keep_container:
                # 清理环境
                if container:
                    self.cleanup_env(container)
                
                    # 删除临时文件
                    if temp_dir and os.path.exists(temp_dir):
                        shutil.rmtree(temp_dir)
                        self.logger.debug("清理临时文件完成")
            else:
                self.logger.info("容器保持运行. 请手动清理.")

    def test_connection_sync(self, webshell_config: WebshellConfig) -> bool:
        """同步版本的测试方法（用于兼容现有代码）"""
        return asyncio.run(self.test_connection(webshell_config.metadata.source_path, webshell_config.connection)) 