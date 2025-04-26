import os
from pathlib import Path
from typing import Dict, Any
import yaml
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

class Config:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self.docker_templates_dir = self.base_dir / "docker_templates"
        self.shells_dir = self.base_dir / "shells"
        
        # Docker配置
        self.docker_network = "webshell_test"
        self.docker_timeout = int(os.getenv("DOCKER_TIMEOUT", "300"))
        
        # 执行配置
        self.execution_timeout = int(os.getenv("EXECUTION_TIMEOUT", "30"))
        self.max_retries = int(os.getenv("MAX_RETRIES", "3"))
        self.concurrent_limit = int(os.getenv("CONCURRENT_LIMIT", "5"))
        
        # 测试命令
        self.default_test_commands = [
            "whoami",
            "pwd",
            "id",
            "uname -a"
        ]
    
    def load_environment_config(self, env_name: str) -> Dict[str, Any]:
        """加载指定环境的配置"""
        config_file = self.docker_templates_dir / env_name / "config.yml"
        if not config_file.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_file}")
            
        with open(config_file, 'r') as f:
            return yaml.safe_load(f)
    
    def get_shell_path(self, shell_name: str) -> Path:
        """获取WebShell文件路径"""
        shell_path = self.shells_dir / shell_name
        if not shell_path.exists():
            raise FileNotFoundError(f"WebShell file not found: {shell_path}")
        return shell_path

# 全局配置实例
config = Config() 