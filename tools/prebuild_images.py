#!/usr/bin/env python3
import os
import sys
import argparse
import docker
from loguru import logger
from typing import Dict, Any, Optional
import datetime
import tarfile
import tempfile
import shutil

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.mylogger import setup_logger

class DockerImageBuilder:
    def __init__(self):
        self.client = docker.from_env()
        self.base_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'docker_templates')
        self.environments = {
            'php7.4_apache': {
                'path': 'php7.4_apache',
                'tag': 'webshell_test_php7.4_apache:latest'
            },
            'tomcat9': {
                'path': 'tomcat9',
                'tag': 'webshell_test_tomcat9:latest',
                'build_args': {
                    'TOMCAT_VERSION': '9.0.71',
                    'JAVA_VERSION': '11'
                }
            },
            'python_flask': {
                'path': 'python_flask',
                'tag': 'webshell_test_python_flask:latest',
                'build_args': {
                    'PYTHON_VERSION': '3.9'
                }
            },
            'nodejs_express': {
                'path': 'nodejs_express',
                'tag': 'webshell_test_nodejs_express:latest',
                'build_args': {
                    'NODE_VERSION': '16'
                }
            },
            'spring_boot': {
                'path': 'spring_boot',
                'tag': 'webshell_test_spring_boot:latest',
                'build_args': {
                    'JAVA_VERSION': '11',
                    'MAVEN_VERSION': '3.8.4'
                }
            }
        }
        # 添加导出目录配置
        self.export_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'exports')
        os.makedirs(self.export_dir, exist_ok=True)

    def build_image(self, env_name: str, build_options: Dict[str, Any]) -> bool:
        """构建单个环境的Docker镜像"""
        if env_name not in self.environments:
            logger.error(f"未知的环境: {env_name}")
            return False

        env_info = self.environments[env_name]
        env_path = os.path.join(self.base_path, env_info['path'])

        if not os.path.exists(env_path):
            logger.error(f"环境目录不存在: {env_path}")
            return False

        try:
            # 合并默认和自定义构建参数
            build_args = {**env_info.get('build_args', {})}
            if build_options.get('build_args'):
                build_args.update(build_options['build_args'])

            # 添加代理设置到构建参数中
            if build_options.get('http_proxy'):
                build_args['http_proxy'] = build_options['http_proxy']
                build_args['HTTP_PROXY'] = build_options['http_proxy']
            if build_options.get('https_proxy'):
                build_args['https_proxy'] = build_options['https_proxy']
                build_args['HTTPS_PROXY'] = build_options['https_proxy']
            if build_options.get('no_proxy'):
                build_args['no_proxy'] = build_options['no_proxy']
                build_args['NO_PROXY'] = build_options['no_proxy']

            logger.info(f"开始构建 {env_name} 环境...")
            logger.info(f"构建选项: {build_options}")
            logger.info(f"构建参数: {build_args}")
            
            # 检查Dockerfile
            dockerfile_path = os.path.join(env_path, 'Dockerfile')
            if not os.path.exists(dockerfile_path):
                logger.error(f"Dockerfile不存在: {dockerfile_path}")
                return False
                
            # 读取并显示Dockerfile内容
            logger.info("Dockerfile内容:")
            with open(dockerfile_path, 'r') as f:
                for i, line in enumerate(f, 1):
                    logger.debug(f"{i:3d} | {line.rstrip()}")
            
            # 检查构建上下文
            context_files = os.listdir(env_path)
            logger.info(f"构建上下文文件: {', '.join(context_files)}")
            
            # 构建镜像
            logger.info("开始Docker构建过程...")
            image = None
            step_count = 0
            current_step = ""
            
            for chunk in self.client.api.build(
                path=env_path,
                tag=env_info['tag'],
                buildargs=build_args,
                nocache=build_options.get('no_cache', False),
                rm=True,
                forcerm=True,
                pull=build_options.get('pull', False),
                network_mode=build_options.get('network', 'default'),
                platform=build_options.get('platform'),
                squash=build_options.get('squash', False),
                decode=True
            ):
                if 'stream' in chunk:
                    line = chunk['stream'].strip()
                    if line:
                        # 检测构建步骤
                        if line.startswith('Step '):
                            step_count += 1
                            current_step = line
                            logger.info(f"\n构建步骤 {step_count}:")
                            logger.info(line)
                        else:
                            logger.info(f"  {line}")
                elif 'error' in chunk:
                    error_msg = chunk['error'].strip()
                    logger.error(f"构建错误: {error_msg}")
                    if current_step:
                        logger.error(f"失败步骤: {current_step}")
                    return False
                elif 'aux' in chunk:
                    if 'ID' in chunk['aux']:
                        image = chunk['aux']['ID']
                        
            if not image:
                logger.error("构建完成但未获取到镜像ID")
                return False
                
            # 获取构建后的镜像信息
            image = self.client.images.get(env_info['tag'])
            image.reload()
            
            # 输出镜像详细信息
            logger.success(f"成功构建镜像: {env_info['tag']}")
            logger.info(f"镜像ID: {image.short_id}")
            logger.info(f"镜像大小: {self.format_size(image.attrs['Size'])}")
            logger.info(f"创建时间: {image.attrs['Created']}")
            
            # 显示镜像层信息
            logger.info("\n镜像层信息:")
            for layer in image.attrs['RootFS']['Layers']:
                logger.debug(f"- {layer}")
            
            # 显示环境变量
            if 'Config' in image.attrs and 'Env' in image.attrs['Config']:
                logger.info("\n环境变量:")
                for env in image.attrs['Config']['Env']:
                    logger.debug(f"- {env}")
            
            return True
            
        except docker.errors.BuildError as e:
            logger.error(f"构建失败: {str(e)}")
            if hasattr(e, 'build_log'):
                logger.error("\n构建日志:")
                for log in e.build_log:
                    if 'stream' in log:
                        logger.error(f"  {log['stream'].strip()}")
                    elif 'error' in log:
                        logger.error(f"  错误: {log['error'].strip()}")
            return False
        except docker.errors.APIError as e:
            logger.error(f"Docker API错误: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"发生错误: {str(e)}")
            import traceback
            logger.error(f"错误追踪:\n{traceback.format_exc()}")
            return False

    def build_all(self, build_options: Dict[str, Any]) -> dict:
        """构建所有环境的Docker镜像"""
        results = {}
        for env_name in self.environments:
            results[env_name] = self.build_image(env_name, build_options)
        return results

    def clean_image(self, env_name: str, force: bool = False) -> bool:
        """清理指定环境的Docker镜像
        
        Args:
            env_name: 环境名称
            force: 是否强制删除（即使正在使用）
        """
        if env_name not in self.environments:
            logger.error(f"未知的环境: {env_name}")
            return False

        env_info = self.environments[env_name]
        try:
            # 获取镜像
            image = self.client.images.get(env_info['tag'])
            
            # 检查是否有容器在使用该镜像
            containers = self.client.containers.list(all=True, filters={'ancestor': env_info['tag']})
            if containers and not force:
                container_ids = [c.short_id for c in containers]
                logger.warning(f"镜像 {env_info['tag']} 正在被以下容器使用: {', '.join(container_ids)}")
                logger.warning("使用 --force 参数强制删除")
                return False
            
            # 删除镜像
            self.client.images.remove(image.id, force=force)
            logger.success(f"成功删除镜像: {env_info['tag']}")
            return True
            
        except docker.errors.ImageNotFound:
            logger.warning(f"镜像不存在: {env_info['tag']}")
            return True
        except docker.errors.APIError as e:
            logger.error(f"删除镜像失败: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"发生错误: {str(e)}")
            return False

    def clean_all(self, force: bool = False) -> dict:
        """清理所有环境的Docker镜像"""
        results = {}
        for env_name in self.environments:
            results[env_name] = self.clean_image(env_name, force)
        return results

    def list_images(self) -> list:
        """列出所有环境的Docker镜像状态"""
        image_status = []
        for env_name, env_info in self.environments.items():
            try:
                # 获取镜像信息
                image = self.client.images.get(env_info['tag'])
                # 获取使用该镜像的容器
                containers = self.client.containers.list(all=True, filters={'ancestor': env_info['tag']})
                
                image_status.append({
                    'name': env_name,
                    'tag': env_info['tag'],
                    'id': image.short_id,
                    'size': self.format_size(image.attrs['Size']),
                    'created': image.attrs['Created'],
                    'containers': [c.short_id for c in containers]
                })
            except docker.errors.ImageNotFound:
                image_status.append({
                    'name': env_name,
                    'tag': env_info['tag'],
                    'status': 'not_found'
                })
            except Exception as e:
                image_status.append({
                    'name': env_name,
                    'tag': env_info['tag'],
                    'status': f'error: {str(e)}'
                })
        return image_status

    def export_image(self, env_name: str, output_path: str = None, compress: bool = True) -> bool:
        """导出指定环境的Docker镜像
        
        Args:
            env_name: 环境名称
            output_path: 输出文件路径或目录，如果是目录则自动生成文件名
            compress: 是否使用gzip压缩
        """
        if env_name not in self.environments:
            logger.error(f"未知的环境: {env_name}")
            return False

        env_info = self.environments[env_name]
        try:
            # 获取镜像
            image = self.client.images.get(env_info['tag'])
            
            # 处理输出路径
            if output_path:
                # 如果是目录，生成默认文件名
                if os.path.isdir(output_path):
                    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                    filename = f"{env_name}_{timestamp}.tar{'.gz' if compress else ''}"
                    output_path = os.path.join(output_path, filename)
            else:
                # 使用默认导出目录
                timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"{env_name}_{timestamp}.tar{'.gz' if compress else ''}"
                output_path = os.path.join(self.export_dir, filename)
            
            # 确保输出目录存在
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            # 创建临时目录用于存储导出文件
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_file = os.path.join(temp_dir, 'image.tar')
                
                # 导出镜像
                logger.info(f"正在导出镜像 {env_info['tag']}...")
                image_data = image.save()
                
                # 写入临时文件
                with open(temp_file, 'wb') as f:
                    for chunk in image_data:
                        f.write(chunk)
                
                # 如果需要压缩，使用gzip
                if compress:
                    logger.info("正在压缩镜像...")
                    with tarfile.open(output_path, 'w:gz') as tar:
                        tar.add(temp_file, arcname=os.path.basename(temp_file))
                else:
                    shutil.copy2(temp_file, output_path)
            
            size = os.path.getsize(output_path)
            logger.success(f"成功导出镜像到: {output_path}")
            logger.info(f"文件大小: {self.format_size(size)}")
            return True
            
        except docker.errors.ImageNotFound:
            logger.error(f"镜像不存在: {env_info['tag']}")
            return False
        except Exception as e:
            logger.error(f"导出镜像失败: {str(e)}")
            return False

    def export_all(self, output_dir: str = None, compress: bool = True) -> dict:
        """导出所有环境的Docker镜像
        
        Args:
            output_dir: 输出目录，如果不指定则使用默认目录
            compress: 是否使用gzip压缩
        """
        # 如果指定了输出目录，确保它存在
        if output_dir:
            if not os.path.isdir(output_dir):
                logger.error(f"指定的输出路径不是目录: {output_dir}")
                return {env_name: False for env_name in self.environments}
            os.makedirs(output_dir, exist_ok=True)
        
        results = {}
        for env_name in self.environments:
            results[env_name] = self.export_image(env_name, output_dir, compress)
        return results

    @staticmethod
    def format_size(size: int) -> str:
        """格式化文件大小"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.2f}{unit}"
            size /= 1024
        return f"{size:.2f}TB"


def parse_build_args(args_str: Optional[str]) -> Dict[str, str]:
    """解析构建参数字符串"""
    if not args_str:
        return {}
    
    build_args = {}
    try:
        for arg in args_str.split(','):
            key, value = arg.split('=')
            build_args[key.strip()] = value.strip()
        return build_args
    except ValueError:
        logger.error("构建参数格式错误，应为: KEY1=VALUE1,KEY2=VALUE2")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='WebShell测试环境Docker镜像构建工具')
    
    # 添加子命令
    subparsers = parser.add_subparsers(dest='command', help='可用命令')
    
    # build 命令
    build_parser = subparsers.add_parser('build', help='构建Docker镜像')
    build_parser.add_argument('--env', help='要构建的环境名称，不指定则构建所有环境')
    build_parser.add_argument('--no-cache', action='store_true', help='禁用Docker构建缓存')
    build_parser.add_argument('--pull', action='store_true', help='强制拉取基础镜像')
    build_parser.add_argument('--network', default='default', help='构建时使用的网络')
    build_parser.add_argument('--build-args', help='自定义构建参数 (格式: KEY1=VALUE1,KEY2=VALUE2)')
    build_parser.add_argument('--platform', help='目标平台 (例如: linux/amd64, linux/arm64)')
    build_parser.add_argument('--squash', action='store_true', help='压缩镜像层')
    # 添加代理相关参数
    build_parser.add_argument('--http-proxy', help='HTTP代理地址 (例如: http://proxy.example.com:8080)')
    build_parser.add_argument('--https-proxy', help='HTTPS代理地址 (例如: http://proxy.example.com:8080)')
    build_parser.add_argument('--no-proxy', help='不使用代理的地址列表 (例如: localhost,127.0.0.1)')
    
    # clean 命令
    clean_parser = subparsers.add_parser('clean', help='清理Docker镜像')
    clean_parser.add_argument('--env', help='要清理的环境名称，不指定则清理所有环境')
    clean_parser.add_argument('--force', '-f', action='store_true', help='强制删除（即使正在使用）')
    
    # list 命令
    list_parser = subparsers.add_parser('list', help='列出环境信息')
    
    # export 命令
    export_parser = subparsers.add_parser('export', help='导出Docker镜像')
    export_parser.add_argument('--env', help='要导出的环境名称，不指定则导出所有环境')
    export_parser.add_argument('--output', '-o', help='输出文件路径（单个环境）或目录（多个环境）')
    export_parser.add_argument('--no-compress', action='store_true', help='不压缩导出文件')
    
    args = parser.parse_args()
    
    setup_logger()
    builder = DockerImageBuilder()

    if args.command == 'list':
        logger.info("环境状态:")
        for status in builder.list_images():
            logger.info(f"\n- {status['name']}:")
            logger.info(f"  镜像: {status['tag']}")
            if 'status' in status:
                logger.info(f"  状态: {status['status']}")
            else:
                logger.info(f"  ID: {status['id']}")
                logger.info(f"  大小: {status['size']}")
                logger.info(f"  创建时间: {status['created']}")
                if status['containers']:
                    logger.info(f"  正在使用的容器: {', '.join(status['containers'])}")
                if status.get('build_args'):
                    logger.info(f"  默认构建参数: {status['build_args']}")
    
    elif args.command == 'clean':
        if args.env:
            # 清理单个环境
            if args.env not in builder.environments:
                logger.error(f"未知的环境: {args.env}")
                sys.exit(1)
            success = builder.clean_image(args.env, args.force)
            sys.exit(0 if success else 1)
        else:
            # 清理所有环境
            logger.info("开始清理所有环境...")
            results = builder.clean_all(args.force)
            
            # 输出清理结果摘要
            logger.info("\n=== 清理结果摘要 ===")
            all_success = True
            for env_name, success in results.items():
                status = "成功" if success else "失败"
                logger.info(f"{env_name}: {status}")
                if not success:
                    all_success = False
            
            sys.exit(0 if all_success else 1)
    
    elif args.command == 'build':
        # 收集构建选项
        build_options = {
            'no_cache': args.no_cache,
            'pull': args.pull,
            'network': args.network,
            'build_args': parse_build_args(args.build_args),
            'platform': args.platform,
            'squash': args.squash,
            'http_proxy': args.http_proxy,
            'https_proxy': args.https_proxy,
            'no_proxy': args.no_proxy
        }

        if args.env:
            # 构建单个环境
            if args.env not in builder.environments:
                logger.error(f"未知的环境: {args.env}")
                sys.exit(1)
            success = builder.build_image(args.env, build_options)
            sys.exit(0 if success else 1)
        else:
            # 构建所有环境
            logger.info("开始构建所有环境...")
            results = builder.build_all(build_options)
            
            # 输出构建结果摘要
            logger.info("\n=== 构建结果摘要 ===")
            all_success = True
            for env_name, success in results.items():
                status = "成功" if success else "失败"
                logger.info(f"{env_name}: {status}")
                if not success:
                    all_success = False
            
            sys.exit(0 if all_success else 1)
    
    elif args.command == 'export':
        if args.env:
            # 导出单个环境
            if args.env not in builder.environments:
                logger.error(f"未知的环境: {args.env}")
                sys.exit(1)
            success = builder.export_image(args.env, args.output, not args.no_compress)
            sys.exit(0 if success else 1)
        else:
            # 导出所有环境
            logger.info("开始导出所有环境...")
            results = builder.export_all(args.output, not args.no_compress)
            
            # 输出导出结果摘要
            logger.info("\n=== 导出结果摘要 ===")
            all_success = True
            for env_name, success in results.items():
                status = "成功" if success else "失败"
                logger.info(f"{env_name}: {status}")
                if not success:
                    all_success = False
            
            sys.exit(0 if all_success else 1)
    
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()