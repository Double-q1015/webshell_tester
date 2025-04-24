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
from utils.models import WebshellConfig
from core.executor import (
    BaseConnector, PasswordConnector, EvalConnector, 
    AssertConnector, ParameterConnector, test_webshell
)

class WebshellTester:
    def __init__(self):
        self.client = docker.from_env()
        self.test_commands = ["echo 'test';", "id;", "pwd;"]  # 基本测试命令
        self.network_name = 'webshell_test'
        self._ensure_network()
        logger.debug("WebshellTester初始化完成")

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
            logger.debug(f"开始设置测试环境，临时目录: {temp_dir}")
            
            # 选择合适的Docker镜像
            image = 'webshell_test_php7.4_apache:latest'  # 默认使用PHP环境
            mount_point = '/var/www/html'
            
            # 启动容器
            logger.debug(f"开始启动容器: {image}")
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
            logger.debug(f"容器启动成功: {container.id}")

            # 等待容器启动
            logger.debug("等待容器初始化...")
            time.sleep(2)

            # 检查容器状态
            container.reload()
            logger.debug(f"容器状态: {container.status}")
            
            # 检查容器日志
            logs = container.logs().decode('utf-8', errors='ignore')
            logger.debug(f"容器日志:\n{logs}")

            return container

        except Exception as e:
            logger.error(f"设置测试环境失败: {str(e)}")
            logger.debug(traceback.format_exc())
            return None

    def cleanup_env(self, container: docker.models.containers.Container):
        """清理测试环境"""
        try:
            if container:
                container.stop()
                logger.debug(f"停止容器: {container.id}")
        except Exception as e:
            logger.error(f"清理测试环境失败: {str(e)}")
            logger.debug(traceback.format_exc())

    async def test_connection(self, webshell_config: WebshellConfig) -> bool:
        """测试webshell连接"""
        temp_dir = None
        container = None
        
        try:
            logger.debug(f"开始测试连接: {webshell_config.filename}")
            
            # 创建临时目录
            temp_dir = tempfile.mkdtemp()
            logger.debug(f"创建临时目录: {temp_dir}")
            os.chmod(temp_dir, 0o755)
            
            # 复制webshell文件到临时目录
            target_path = os.path.join(temp_dir, os.path.basename(webshell_config.filename))
            shutil.copy2(webshell_config.metadata.source_path, target_path)
            os.chmod(target_path, 0o644)
            logger.debug(f"复制文件到: {target_path}")
            
            # 设置Docker环境
            container = self.setup_test_env(temp_dir)
            if not container:
                logger.error("Docker环境设置失败")
                return False
                
            try:
                # 等待服务器启动
                time.sleep(2)
                
                # 获取容器IP
                container.reload()
                container_ip = container.attrs['NetworkSettings']['Networks']['webshell_test']['IPAddress']
                logger.debug(f"容器IP: {container_ip}")
                
                # 创建合适的连接器
                connector = self._create_connector(webshell_config)
                
                # 构建WebShell URL
                url = f"http://{container_ip}/{os.path.basename(webshell_config.filename)}"
                logger.debug(f"WebShell URL: {url}")
                
                # 执行测试
                test_results = await test_webshell(
                    url=url,
                    connector=connector,
                    commands=self.test_commands
                )
                
                # 检查测试结果
                successful_commands = test_results.get('successful_commands', 0)
                total_commands = test_results.get('total_commands', 0)
                
                # 如果至少有一个命令成功执行，就认为测试通过
                if successful_commands > 0:
                    logger.debug(f"测试成功: {successful_commands}/{total_commands} 个命令成功执行")
                    return True
                else:
                    logger.error(f"测试失败: 所有命令都执行失败")
                    return False
                
            finally:
                # 清理Docker环境
                self.cleanup_env(container)
            
        except Exception as e:
            logger.error(f"连接测试失败: {str(e)}")
            logger.debug(traceback.format_exc())
            return False
            
        finally:
            # 清理临时文件
            if temp_dir:
                try:
                    shutil.rmtree(temp_dir)
                    logger.debug("清理临时文件完成")
                except:
                    pass

    def test_connection_sync(self, webshell_config: WebshellConfig) -> bool:
        """同步版本的测试方法（用于兼容现有代码）"""
        return asyncio.run(self.test_connection(webshell_config)) 