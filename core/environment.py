import os
import sys
import time
import tempfile
import docker
import shutil
from docker.models.containers import Container
from docker.models.networks import Network
from pathlib import Path
from typing import Optional, Dict, Any
from loguru import logger
import traceback

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import config
from tools.prebuild_images import DockerImageBuilder

class EnvironmentManager:
    def __init__(self, env_name: str = 'php7.4_apache', keep_container: bool = False):
        """
        Initialize the EnvironmentManager
        """
        self.client = docker.from_env()
        self.network: Optional[Network] = None
        self.network_name = config.docker_network
        self._ensure_network()
        self.keep_container = keep_container
        _docker_builder = DockerImageBuilder()
        self.temp_dir = None
        self.image = _docker_builder.get_supported_image_name_by_env_name(env_name)
        if not self.image:
            logger.error(f"Unsupported environment: {env_name}")
            raise ValueError(f"Unsupported environment: {env_name}")

    def _ensure_network(self):
        """Ensure Docker network exists"""
        try:
            self.network = self.client.networks.get(self.network_name)
            logger.info(f"Using existing network: {self.network_name}")
        except docker.errors.NotFound:
            self.network = self.client.networks.create(
                self.network_name,
                driver="bridge",
                internal=True,  # disable access to the outside network
                enable_ipv6=False,
                attachable=True,
                labels={
                    "purpose": "webshell_testing",
                    "managed_by": "webshell_tester"
                }
            )
            logger.info(f"Created new network: {self.network_name}")
    
    def build_environment(self, env_name: str) -> Container:
        """Build and start environment container"""
        env_path = config.docker_templates_dir / env_name
        if not env_path.exists():
            raise ValueError(f"Environment directory does not exist: {env_path}")
        
        # load environment configuration
        env_config = config.load_environment_config(env_name)
        logger.info(f"Environment configuration: {env_config}")
        
        # check if there is a cached image
        image_tag = f"webshell_test_{env_name}"
        try:
            image = self.client.images.get(image_tag)
            logger.info(f"Using cached image: {image_tag}")
        except docker.errors.ImageNotFound:
            # copy shells directory to build context
            build_context = env_path
            shells_dir = config.base_dir / "shells"
            if shells_dir.exists():
                import shutil
                temp_shells_dir = env_path / "shells"
                if temp_shells_dir.exists():
                    shutil.rmtree(temp_shells_dir)
                shutil.copytree(shells_dir, temp_shells_dir)
                logger.info(f"Copy WebShell files to build context: {temp_shells_dir}")
            
            # build new image
            logger.info(f"Building new image: {env_name}")
            image, _ = self.client.images.build(
                path=str(build_context),
                tag=image_tag,
                rm=True,
                forcerm=True,
                pull=True,
                nocache=False  # enable Docker layer caching
            )
            logger.info("Image built")
        
        # prepare container configuration
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
                "interval": 5000000000,  # 5 seconds
                "timeout": 3000000000,   # 3 seconds
                "retries": 3
            }
        }
        
        # add port mapping
        if "ports" in env_config:
            container_config["ports"] = {
                port.split(":")[0]: port.split(":")[1]
                for port in env_config["ports"]
            }
        
        # add volume mounting
        if "volumes" in env_config:
            container_config["volumes"] = {
                str(Path(vol.split(":")[0]).resolve()): {
                    "bind": vol.split(":")[1],
                    "mode": vol.split(":")[2] if len(vol.split(":")) > 2 else "rw"
                }
                for vol in env_config["volumes"]
            }
        
        # start container
        container = self.client.containers.run(**container_config)
        logger.info(f"Container started successfully: {container.name}")
        return container
    
    def destroy_environment(self, container: Container):
        """Destroy environment container"""
        try:
            container.stop(timeout=10)
            # delete container and associated volumes
            container.remove(force=True, v=True)
            logger.info(f"Container destroyed: {container.name}")
        except Exception as e:
            logger.error(f"Failed to destroy container: {e}")
    
    def get_container_status(self, container: Container) -> Dict[str, Any]:
        """Get container status information"""
        container.reload()
        stats = container.stats(stream=False)
        
        # CPU usage calculation
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
    
    def copy_to_container(self, container: Container, source_path: str, target_path: str) -> bool:
        """Copy file to container"""
        try:
            container.put_archive(target_path, source_path)
            return True
        except Exception as e:
            logger.error(f"Failed to copy file to container: {e}")
            return False
        
    def wait_for_ready(self, container: Container, timeout: int = 60) -> bool:
        """Wait for container to be ready"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            container.reload()
            
            # check container status
            if container.status != "running":
                logger.warning(f"Container status: {container.status}")
                time.sleep(1)
                continue
            
            # check health status
            health = container.attrs.get("State", {}).get("Health", {})
            if health.get("Status") == "healthy":
                logger.info("Container health check passed")
                return True
            elif health.get("Status") == "unhealthy":
                logger.error(f"Container health check failed: {health.get('Log', [])}")
                return False
            
            time.sleep(1)
        
        logger.error("Container startup timeout")
        return False

    def init_test_container(self, mount_point: str, temp_dir: str) -> Optional[Container]:
        """
        Initialize test container
        Args:
            mount_point: The mount point of the test container
            temp_dir: The temporary directory
        """
        try:
            logger.debug(f"Start setting up test environment, temporary directory: {temp_dir}")
            
            # set directory permissions
            os.chmod(temp_dir, 0o755)
            for root, dirs, files in os.walk(temp_dir):
                for d in dirs:
                    os.chmod(os.path.join(root, d), 0o755)
                for f in files:
                    os.chmod(os.path.join(root, f), 0o644)
            
            # select appropriate Docker image
            # mount_point = '/var/www/html'
            
            # start container
            logger.debug(f"Start container: {self.image}")
            container = self.client.containers.run(
                self.image,
                detach=True,
                network=self.network_name,  # use class variable
                volumes={
                    temp_dir: {
                        'bind': mount_point,
                        'mode': 'rw'
                    }
                },
                healthcheck={
                    'test': ['CMD', 'curl', '-f', 'http://localhost/index.php'],
                    'interval': 5000000000,  # 5 seconds
                    'timeout': 3000000000,   # 3 seconds
                    'retries': 3,
                    'start_period': 10000000000  # 10 seconds
                },
                working_dir=mount_point,
                remove=True
            )
            logger.debug(f"Container started: {container.id}")

            # wait for container to start
            logger.debug("Waiting for container to initialize...")
            time.sleep(2)

            # check container status
            container.reload()
            logger.debug(f"Container status: {container.status}")
            
            # check container logs
            logs = container.logs().decode('utf-8', errors='ignore')
            logger.debug(f"Container logs:\n{logs}")

            return container

        except Exception as e:
            logger.error(f"Failed to setup test environment: {str(e)}")
            logger.debug(traceback.format_exc())
            return None

    def setup_test_env(self, webshell_file: str) -> Optional[Container]:
        """Setup test environment"""
        # set mount point based on image
        try:
            mount_point = None
            if 'apache' in self.image.lower():
                mount_point = '/var/www/html'
            elif 'nginx' in self.image.lower():
                mount_point = '/usr/share/nginx/html'
            else:
                logger.error(f"Unsupported image: {self.image}")
                return None
            # copy file to temporary directory
            self.temp_dir = tempfile.mkdtemp()
            logger.debug(f"Temporary directory: {self.temp_dir}")
            target_file = os.path.join(self.temp_dir, os.path.basename(webshell_file))
            shutil.copy2(webshell_file, target_file)
            logger.debug(f"Copy file to: {target_file}")
            test_container = self.init_test_container(mount_point, self.temp_dir)
            if test_container:
                container_ip = self._get_container_ip(test_container)
                logger.info(f"Test container started: {container_ip}\n"
                            f"You can access the container at: http://{container_ip}/{os.path.basename(webshell_file)}")
                
                return test_container
            else:
                logger.error("Failed to start test container")
                return None
        except Exception as e:
            logger.error(f"Failed to setup test environment: {str(e)}")
            logger.debug(traceback.format_exc())
            return None
        # finally:
        #     if not self.keep_container:
        #         # clean up environment
        #         if test_container:
        #             self.cleanup_env(test_container)
        #         # delete temporary files
        #         if temp_dir and os.path.exists(temp_dir):
        #             shutil.rmtree(temp_dir)
        #             logger.debug("Cleaned up temporary files")
        #     else:
        #         logger.debug("Keep container, Please clean up the environment manually")

    def _get_container_ip(self, container: Container) -> Optional[str]:
        """Get container IP address"""
        try:
            container.reload()
            return container.attrs['NetworkSettings']['Networks'][self.network.name]['IPAddress']
        except Exception as e:
            logger.error(f"Failed to get container IP: {str(e)}")
            return None

    def cleanup_env(self, container: Container):
        """Clean up test environment"""
        try:
            if container:
                container.stop()
                logger.debug(f"Stop container: {container.id}")
            if self.temp_dir and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
                logger.debug(f"Cleaned up temporary files: {self.temp_dir}")
        except Exception as e:
            logger.error(f"Failed to clean up test environment: {str(e)}")
            logger.debug(traceback.format_exc())

    def __del__(self):
        """Clean up resources"""
        try:
            if self.network:
                self.network.remove()
        except Exception as e:
            logger.error(f"Failed to clean up network resources: {e}")

if __name__ == "__main__":
    docker_builder = DockerImageBuilder()
    print(docker_builder.get_supported_image_name_by_env_name("php7.4_apache"))
