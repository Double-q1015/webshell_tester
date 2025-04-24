import docker
from docker.models.containers import Container
from docker.models.networks import Network
from pathlib import Path
from typing import Optional, Dict, Any
import time
from loguru import logger

from .config import config

class EnvironmentManager:
    def __init__(self):
        self.client = docker.from_env()
        self.network: Optional[Network] = None
        self._ensure_network()
    
    def _ensure_network(self):
        """确保Docker网络存在"""
        try:
            self.network = self.client.networks.get(config.docker_network)
            logger.info(f"使用已存在的网络: {config.docker_network}")
        except docker.errors.NotFound:
            self.network = self.client.networks.create(
                config.docker_network,
                driver="bridge",
                internal=True,  # 禁止访问外网
                enable_ipv6=False,
                attachable=True,
                labels={
                    "purpose": "webshell_testing",
                    "managed_by": "webshell_tester"
                }
            )
            logger.info(f"创建新的网络: {config.docker_network}")
    
    def build_environment(self, env_name: str) -> Container:
        """构建并启动环境容器"""
        env_path = config.docker_templates_dir / env_name
        if not env_path.exists():
            raise ValueError(f"环境目录不存在: {env_path}")
        
        # 加载环境配置
        env_config = config.load_environment_config(env_name)
        logger.info(f"环境配置: {env_config}")
        
        # 检查是否存在可用的缓存镜像
        image_tag = f"webshell_test_{env_name}"
        try:
            image = self.client.images.get(image_tag)
            logger.info(f"使用缓存镜像: {image_tag}")
        except docker.errors.ImageNotFound:
            # 复制shells目录到构建上下文
            build_context = env_path
            shells_dir = config.base_dir / "shells"
            if shells_dir.exists():
                import shutil
                temp_shells_dir = env_path / "shells"
                if temp_shells_dir.exists():
                    shutil.rmtree(temp_shells_dir)
                shutil.copytree(shells_dir, temp_shells_dir)
                logger.info(f"复制WebShell文件到构建上下文: {temp_shells_dir}")
            
            # 构建新镜像
            logger.info(f"开始构建新镜像: {env_name}")
            image, _ = self.client.images.build(
                path=str(build_context),
                tag=image_tag,
                rm=True,
                forcerm=True,
                pull=True,
                nocache=False  # 启用Docker层缓存
            )
            logger.info("镜像构建完成")
        
        # 准备容器配置
        container_config = {
            "image": image.id,
            "detach": True,
            "network": self.network.name,
            "environment": env_config.get("environment", {}),
            "mem_limit": "512m",
            "cpu_period": 100000,
            "cpu_quota": 50000,
            "restart_policy": {"Name": "no"},
            "healthcheck": {
                "test": ["CMD", "curl", "-f", "http://localhost/index.php"],
                "interval": 5000000000,  # 5秒
                "timeout": 3000000000,   # 3秒
                "retries": 3
            }
        }
        
        # 添加端口映射
        if "ports" in env_config:
            container_config["ports"] = {
                port.split(":")[0]: port.split(":")[1]
                for port in env_config["ports"]
            }
        
        # 添加卷挂载
        if "volumes" in env_config:
            container_config["volumes"] = {
                str(Path(vol.split(":")[0]).resolve()): {
                    "bind": vol.split(":")[1],
                    "mode": vol.split(":")[2] if len(vol.split(":")) > 2 else "rw"
                }
                for vol in env_config["volumes"]
            }
        
        # 启动容器
        container = self.client.containers.run(**container_config)
        logger.info(f"容器启动成功: {container.name}")
        return container
    
    def destroy_environment(self, container: Container):
        """销毁环境容器"""
        try:
            container.stop(timeout=10)
            container.remove(force=True, v=True)  # v=True 同时删除关联的匿名卷
            logger.info(f"容器已销毁: {container.name}")
        except Exception as e:
            logger.error(f"销毁容器失败: {e}")
    
    def get_container_status(self, container: Container) -> Dict[str, Any]:
        """获取容器状态信息"""
        container.reload()
        stats = container.stats(stream=False)
        
        # 计算CPU使用率
        cpu_delta = stats["cpu_stats"]["cpu_usage"]["total_usage"] - \
                   stats["precpu_stats"]["cpu_usage"]["total_usage"]
        system_delta = stats["cpu_stats"]["system_cpu_usage"] - \
                      stats["precpu_stats"]["system_cpu_usage"]
        cpu_usage = (cpu_delta / system_delta) * 100.0 if system_delta > 0 else 0.0
        
        return {
            "status": container.status,
            "cpu_usage": round(cpu_usage, 2),
            "memory_usage": stats["memory_stats"]["usage"],
            "memory_limit": stats["memory_stats"]["limit"],
            "memory_percent": round(stats["memory_stats"]["usage"] / stats["memory_stats"]["limit"] * 100, 2),
            "network_rx": stats["networks"][list(stats["networks"].keys())[0]]["rx_bytes"],
            "network_tx": stats["networks"][list(stats["networks"].keys())[0]]["tx_bytes"]
        }
    
    def wait_for_ready(self, container: Container, timeout: int = 60) -> bool:
        """等待容器准备就绪"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            container.reload()
            
            # 检查容器状态
            if container.status != "running":
                logger.warning(f"容器状态: {container.status}")
                time.sleep(1)
                continue
            
            # 检查健康状态
            health = container.attrs.get("State", {}).get("Health", {})
            if health.get("Status") == "healthy":
                logger.info("容器健康检查通过")
                return True
            elif health.get("Status") == "unhealthy":
                logger.error(f"容器健康检查失败: {health.get('Log', [])}")
                return False
            
            time.sleep(1)
        
        logger.error("容器启动超时")
        return False

    def __del__(self):
        """清理资源"""
        try:
            if self.network:
                self.network.remove()
        except Exception as e:
            logger.error(f"清理网络资源失败: {e}")
