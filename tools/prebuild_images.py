#!/usr/bin/env python3
import os
import sys
import argparse
import docker
from loguru import logger
from typing import Dict, Any, Optional, List
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
            'php7.4_nginx': {
                'path': 'php7.4_nginx',
                'tag': 'webshell_test_php7.4_nginx:latest'
            },
            'php8.1_apache': {
                'path': 'php8.1_apache',
                'tag': 'webshell_test_php8.1_apache:latest'
            },
            'php8.1_nginx': {
                'path': 'php8.1_nginx',
                'tag': 'webshell_test_php8.1_nginx:latest'
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
        # export dir
        self.export_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'exports')
        os.makedirs(self.export_dir, exist_ok=True)
    
    def get_supported_environments(self) -> List[str]:
        """Get all supported environments"""
        return list(self.environments.keys())
    
    
    def get_supported_image_name_by_env_name(self, env_name: str) -> Optional[str]:
        """Get all supported images for a specific environment"""
        if env_name not in self.environments:
            logger.error(f"Unknown environment: {env_name}")
            return None
        return self.environments[env_name]['tag']

    def build_image(self, env_name: str, build_options: Dict[str, Any]) -> bool:
        """Build a single environment's Docker image"""
        if env_name not in self.environments:
            logger.error(f"Unknown environment: {env_name}")
            return False

        env_info = self.environments[env_name]
        env_path = os.path.join(self.base_path, env_info['path'])

        if not os.path.exists(env_path):
            logger.error(f"Environment directory does not exist: {env_path}")
            return False

        try:
            # merge default and custom build arguments
            build_args = {**env_info.get('build_args', {})}
            if build_options.get('build_args'):
                build_args.update(build_options['build_args'])

            # add proxy settings to build arguments
            if build_options.get('http_proxy'):
                build_args['http_proxy'] = build_options['http_proxy']
                build_args['HTTP_PROXY'] = build_options['http_proxy']
            if build_options.get('https_proxy'):
                build_args['https_proxy'] = build_options['https_proxy']
                build_args['HTTPS_PROXY'] = build_options['https_proxy']
            if build_options.get('no_proxy'):
                build_args['no_proxy'] = build_options['no_proxy']
                build_args['NO_PROXY'] = build_options['no_proxy']

            logger.info(f"Start building {env_name} environment...")
            logger.info(f"Build options: {build_options}")
            logger.info(f"Build arguments: {build_args}")
            
            # check Dockerfile
            dockerfile_path = os.path.join(env_path, 'Dockerfile')
            if not os.path.exists(dockerfile_path):
                logger.error(f"Dockerfile does not exist: {dockerfile_path}")
                return False
                
            # read and show Dockerfile content
            logger.info("Dockerfile content:")
            with open(dockerfile_path, 'r') as f:
                for i, line in enumerate(f, 1):
                    logger.debug(f"{i:3d} | {line.rstrip()}")
            
            # check build context
            context_files = os.listdir(env_path)
            logger.info(f"Build context files: {', '.join(context_files)}")
            
            # build image
            logger.info("Start Docker build process...")
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
                        # check build step
                        if line.startswith('Step '):
                            step_count += 1
                            current_step = line
                            logger.info(f"\nBuild step {step_count}:")
                            logger.info(line)
                        else:
                            logger.info(f"  {line}")
                elif 'error' in chunk:
                    error_msg = chunk['error'].strip()
                    logger.error(f"Build error: {error_msg}")
                    if current_step:
                        logger.error(f"Failed step: {current_step}")
                    return False
                elif 'aux' in chunk:
                    if 'ID' in chunk['aux']:
                        image = chunk['aux']['ID']
                        
            if not image:
                logger.error("Build completed but no image ID obtained")
                return False
                
            # get image info after build
            image = self.client.images.get(env_info['tag'])
            image.reload()
            
            # output image info
            logger.success(f"Successfully built image: {env_info['tag']}")
            logger.info(f"Image ID: {image.short_id}")
            logger.info(f"Image size: {self.format_size(image.attrs['Size'])}")
            logger.info(f"Created time: {image.attrs['Created']}")
            
            # show image layer info
            logger.info("\nImage layer info:")
            for layer in image.attrs['RootFS']['Layers']:
                logger.debug(f"- {layer}")
            
            # show environment variables
            if 'Config' in image.attrs and 'Env' in image.attrs['Config']:
                logger.info("\nEnvironment variables:")
                for env in image.attrs['Config']['Env']:
                    logger.debug(f"- {env}")
            
            return True
            
        except docker.errors.BuildError as e:
            logger.error(f"Build failed: {str(e)}")
            if hasattr(e, 'build_log'):
                logger.error("\nBuild log:")
                for log in e.build_log:
                    if 'stream' in log:
                        logger.error(f"  {log['stream'].strip()}")
                    elif 'error' in log:
                        logger.error(f"  Error: {log['error'].strip()}")
            return False
        except docker.errors.APIError as e:
            logger.error(f"Docker API error: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Error: {str(e)}")
            import traceback
            logger.error(f"Error trace:\n{traceback.format_exc()}")
            return False

    def build_all(self, build_options: Dict[str, Any]) -> dict:
        """Build all Docker images"""
        results = {}
        for env_name in self.environments:
            results[env_name] = self.build_image(env_name, build_options)
        return results

    def clean_image(self, env_name: str, force: bool = False) -> bool:
        """Clean specified environment's Docker image
        
        Args:
            env_name: environment name
            force: whether to force delete (even if in use)
        """
        if env_name not in self.environments:
            logger.error(f"Unknown environment: {env_name}")
            return False

        env_info = self.environments[env_name]
        try:
            # get image
            image = self.client.images.get(env_info['tag'])
            
            # check if there are containers using the image
            containers = self.client.containers.list(all=True, filters={'ancestor': env_info['tag']})
            if containers and not force:
                container_ids = [c.short_id for c in containers]
                logger.warning(f"Image {env_info['tag']} is being used by the following containers: {', '.join(container_ids)}")
                logger.warning("Use --force parameter to force delete")
                return False
            
            # delete image
            self.client.images.remove(image.id, force=force)
            logger.success(f"Successfully deleted image: {env_info['tag']}")
            return True
            
        except docker.errors.ImageNotFound:
            logger.warning(f"Image not found: {env_info['tag']}")
            return True
        except docker.errors.APIError as e:
            logger.error(f"Failed to delete image: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Error: {str(e)}")
            return False

    def clean_all(self, force: bool = False) -> dict:
        """Clean all Docker images"""
        results = {}
        for env_name in self.environments:
            results[env_name] = self.clean_image(env_name, force)
        return results

    def list_images(self) -> list:
        """List all environment's Docker image status"""
        image_status = []
        for env_name, env_info in self.environments.items():
            try:
                # get image info
                image = self.client.images.get(env_info['tag'])
                # get containers using the image
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

    def show_image_info(self):
        """Show all environment's Docker image status"""
        for status in self.list_images():
            logger.info(f"\n- {status['name']}:")
            logger.info(f"  Image: {status['tag']}")
            if 'status' in status:
                logger.info(f"  Status: {status['status']}")
            else:
                logger.info(f"  ID: {status['id']}")
                logger.info(f"  Size: {status['size']}")
                logger.info(f"  Created: {status['created']}")
                if status['containers']:
                    logger.info(f"  Containers in use: {', '.join(status['containers'])}")
                if status.get('build_args'):
                    logger.info(f"  Default build arguments: {status['build_args']}")
    
    def export_image(self, env_name: str, output_path: str = None, compress: bool = True) -> bool:
        """Export specified environment's Docker image
        
        Args:
            env_name: environment name
            output_path: output file path or directory, if it is a directory, the default file name will be generated
            compress: whether to use gzip compression
        """
        if env_name not in self.environments:
            logger.error(f"Unknown environment: {env_name}")
            return False

        env_info = self.environments[env_name]
        try:
            # get image
            image = self.client.images.get(env_info['tag'])
            
            # handle output path
            if output_path:
                # if it is a directory, generate default file name
                if os.path.isdir(output_path):
                    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                    filename = f"{env_name}_{timestamp}.tar{'.gz' if compress else ''}"
                    output_path = os.path.join(output_path, filename)
            else:
                # use default export directory
                timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"{env_name}_{timestamp}.tar{'.gz' if compress else ''}"
                output_path = os.path.join(self.export_dir, filename)
            
            # ensure output directory exists
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            # create temporary directory for storing export file
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_file = os.path.join(temp_dir, 'image.tar')
                
                # export image
                logger.info(f"Exporting image {env_info['tag']}...")
                image_data = image.save()
                
                # write to temporary file
                with open(temp_file, 'wb') as f:
                    for chunk in image_data:
                        f.write(chunk)
                
                # if compress is needed, use gzip
                if compress:
                    logger.info("Compressing image...")
                    with tarfile.open(output_path, 'w:gz') as tar:
                        tar.add(temp_file, arcname=os.path.basename(temp_file))
                else:
                    shutil.copy2(temp_file, output_path)
            
            size = os.path.getsize(output_path)
            logger.success(f"Successfully exported image to: {output_path}")
            logger.info(f"File size: {self.format_size(size)}")
            return True
            
        except docker.errors.ImageNotFound:
            logger.error(f"Image not found: {env_info['tag']}")
            return False
        except Exception as e:
            logger.error(f"Failed to export image: {str(e)}")
            return False

    def export_all(self, output_dir: str = None, compress: bool = True) -> dict:
        """Export all environment's Docker images
        
        Args:
            output_dir: output directory, if not specified, use default directory
            compress: whether to use gzip compression
        """
        # if output directory is specified, ensure it exists
        if output_dir:
            if not os.path.isdir(output_dir):
                logger.error(f"The specified output path is not a directory: {output_dir}")
                return {env_name: False for env_name in self.environments}
            os.makedirs(output_dir, exist_ok=True)
        
        results = {}
        for env_name in self.environments:
            results[env_name] = self.export_image(env_name, output_dir, compress)
        return results

    @staticmethod
    def format_size(size: int) -> str:
        """Format file size"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.2f}{unit}"
            size /= 1024
        return f"{size:.2f}TB"


def parse_build_args(args_str: Optional[str]) -> Dict[str, str]:
    """Parse build argument string"""
    if not args_str:
        return {}
    
    build_args = {}
    try:
        for arg in args_str.split(','):
            key, value = arg.split('=')
            build_args[key.strip()] = value.strip()
        return build_args
    except ValueError:
        logger.error("Build argument format error, should be: KEY1=VALUE1,KEY2=VALUE2")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='WebShell test environment Docker image build tool')
    
    # add subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # build command
    build_parser = subparsers.add_parser('build', help='Build Docker images')
    build_parser.add_argument('--env', help='Environment name to build, if not specified, build all environments')
    build_parser.add_argument('--no-cache', action='store_true', help='Disable Docker build cache')
    build_parser.add_argument('--pull', action='store_true', help='Force pull base image')
    build_parser.add_argument('--network', default='default', help='Network used when building')
    build_parser.add_argument('--build-args', help='Custom build arguments (format: KEY1=VALUE1,KEY2=VALUE2)')
    build_parser.add_argument('--platform', help='Target platform (e.g. linux/amd64, linux/arm64)')
    build_parser.add_argument('--squash', action='store_true', help='Squash image layers')
    # add proxy related parameters
    build_parser.add_argument('--http-proxy', help='HTTP proxy address (e.g. http://proxy.example.com:8080)')
    build_parser.add_argument('--https-proxy', help='HTTPS proxy address (e.g. http://proxy.example.com:8080)')
    build_parser.add_argument('--no-proxy', help='Address list not using proxy (e.g. localhost,127.0.0.1)')
    
    # clean command
    clean_parser = subparsers.add_parser('clean', help='Clean Docker images')
    clean_parser.add_argument('--env', help='Environment name to clean, if not specified, clean all environments')
    clean_parser.add_argument('--force', '-f', action='store_true', help='Force delete (even if in use)')
    
    # list command
    list_parser = subparsers.add_parser('list', help='List environment information')
    
    # export command
    export_parser = subparsers.add_parser('export', help='Export Docker images')
    export_parser.add_argument('--env', help='Environment name to export, if not specified, export all environments')
    export_parser.add_argument('--output', '-o', help='Output file path (single environment) or directory (multiple environments)')
    export_parser.add_argument('--no-compress', action='store_true', help='Not compress exported files')
    
    args = parser.parse_args()
    
    setup_logger()
    builder = DockerImageBuilder()

    if args.command == 'list':
        logger.info("Environment status:")
        builder.show_image_info()
    
    elif args.command == 'clean':
        if args.env:
            # clean single environment
            if args.env not in builder.environments:
                logger.error(f"Unknown environment: {args.env}")
                sys.exit(1)
            success = builder.clean_image(args.env, args.force)
            sys.exit(0 if success else 1)
        else:
            # clean all environments
            logger.info("Start cleaning all environments...")
            results = builder.clean_all(args.force)
            
            # output cleanup result summary
            logger.info("\n=== Cleanup result summary ===")
            all_success = True
            for env_name, success in results.items():
                status = "Success" if success else "Failed"
                logger.info(f"{env_name}: {status}")
                if not success:
                    all_success = False
            
            sys.exit(0 if all_success else 1)
    
    elif args.command == 'build':
        # collect build options
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
            # build single environment
            if args.env not in builder.environments:
                logger.error(f"Unknown environment: {args.env}")
                sys.exit(1)
            success = builder.build_image(args.env, build_options)
            sys.exit(0 if success else 1)
        else:
            # build all environments
            logger.info("Start building all environments...")
            results = builder.build_all(build_options)
            
            # output build result summary
            logger.info("\n=== Build result summary ===")
            all_success = True
            for env_name, success in results.items():
                status = "Success" if success else "Failed"
                logger.info(f"{env_name}: {status}")
                if not success:
                    all_success = False
            
            sys.exit(0 if all_success else 1)
    
    elif args.command == 'export':
        if args.env:
            # export single environment
            if args.env not in builder.environments:
                logger.error(f"Unknown environment: {args.env}")
                sys.exit(1)
            success = builder.export_image(args.env, args.output, not args.no_compress)
            sys.exit(0 if success else 1)
        else:
            # export all environments
            logger.info("Start exporting all environments...")
            results = builder.export_all(args.output, not args.no_compress)
            
            # output export result summary
            logger.info("\n=== Export result summary ===")
            all_success = True
            for env_name, success in results.items():
                status = "Success" if success else "Failed"
                logger.info(f"{env_name}: {status}")
                if not success:
                    all_success = False
            
            sys.exit(0 if all_success else 1)
    
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()