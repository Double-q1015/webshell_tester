#!/usr/bin/env python3
import os
import sys
import docker
from typing import Optional, Dict, Any, Tuple
from loguru import logger
import traceback
import asyncio

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.models import WebshellConfig, ConnectionInfo
from core.executor import (
    BaseConnector, PasswordConnector, EvalConnector, 
    AssertConnector, ParameterConnector, test_webshell,
    BaseExecutor
)
from core.environment import EnvironmentManager
from core.config import config
from utils.webshell_analyzer import WebshellAnalyzer

class WebshellTester:
    def __init__(self, env_name: str = 'php7.4_apache', keep_container: bool = False):
        self.client = docker.from_env()
        self.test_commands = ["echo 'test';", "id;", "pwd;"]  # basic test commands
        self.network_name = config.docker_network
        logger.debug("WebshellTester initialized")
        self.keep_container = keep_container
        self.env_manager = EnvironmentManager(env_name=env_name, keep_container=keep_container)
        self.analyzer = WebshellAnalyzer()

    def _create_connector(self, webshell_config: WebshellConfig) -> BaseConnector:
        """Create appropriate connector based on webshell config"""
        # check if it's eval/assert type
        if webshell_config.features.eval_usage:
            if 'assert' in webshell_config.filename.lower():
                return AssertConnector(param_name=webshell_config.connection.password)
            else:
                return EvalConnector(param_name=webshell_config.connection.password)
        
        # check if it's JSP/ASPX
        if webshell_config.type in ['jsp', 'aspx']:
            return ParameterConnector(param_name=webshell_config.connection.param_name)
        
        # default use password connector
        return PasswordConnector(
            password=webshell_config.connection.password,
            param_name=webshell_config.connection.param_name
        )



    async def test_connection(self, webshell_file: str) -> bool:
        """
        Test WebShell connection
        """
        container = None
        try:
            container = self.env_manager.setup_test_env(webshell_file)
            if not container:
                logger.error("Failed to setup test environment")
                return False
            
            # wait for container to be ready
            await asyncio.sleep(2)
            
            # get container IP
            container_ip = self.env_manager._get_container_ip(container)
            if not container_ip:
                logger.error("Failed to get container IP")
                return False
            
            logger.debug(f"Container IP: {container_ip}")
            
            # build WebShell URL
            webshell_url = f"http://{container_ip}/{os.path.basename(webshell_file)}"
            logger.debug(f"WebShell URL: {webshell_url}")
            
            connection_info = self.analyzer._analyze_connection(webshell_file)

            # test connection
            executor = BaseExecutor()
            test_results = await test_webshell(
                webshell_url,
                connection_info,
                executor
            )
            
            if not test_results['success']:
                logger.error(f"Failed to test connection: {test_results.get('error', 'Unknown error')}")
                if 'details' in test_results:
                    logger.debug(f"Error details: {test_results['details']}")
                return False
            
            logger.info("Connection test successful")
            return True
            
        except Exception as e:
            logger.error(f"Error occurred during connection test: {str(e)}")
            logger.debug(f"Error details:\n{traceback.format_exc()}")
            return False
            
        finally:
            if not self.keep_container:
                # clean up environment
                if container and not self.keep_container:
                    self.env_manager.cleanup_env(container)
            else:
                logger.debug("Keep container, Please clean up the environment manually")

    def test_connection_sync(self, webshell_file: str) -> bool:
        """Synchronous version of test method (for compatibility with existing code)"""
        return asyncio.run(self.test_connection(webshell_file)) 