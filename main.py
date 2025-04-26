import asyncio
from loguru import logger
import argparse


from utils.mylogger import setup_logger
from tools.prebuild_images import DockerImageBuilder
from utils.webshell_organizer import WebshellTester
from core.environment import EnvironmentManager


if __name__ == "__main__":
    # configure command line arguments
    parser = argparse.ArgumentParser(description="WebShell automation test tool")
    subparsers = parser.add_subparsers(dest='command', help='Main commands')

    # prebuild Command
    prebuild_parser = subparsers.add_parser("prebuild", help="Prebuild images, more details see tools/prebuild_images.py")
    prebuild_parser.add_argument("--list-envs", action="store_true", help="List all supported environments")

    # test Command
    test_parser = subparsers.add_parser("test", help="Run WebShell tests")
    test_parser.add_argument("--env", default="php7.4_apache", help="Test environment name")
    test_parser.add_argument("--shell", default="webshell.php", help="WebShell file path to test")
    test_parser.add_argument("--keep-container", action="store_true", help="Keep container after test")

    # deploy Command
    deploy_parser = subparsers.add_parser("deploy", help="Deploy WebShell to environment")
    deploy_parser.add_argument("--env", required=True, help="Target environment name")
    deploy_parser.add_argument("--shell", required=True, help="WebShell file path to deploy")

    
    args = parser.parse_args()

    # setup logger
    setup_logger()

    if args.command == "test":
        tester = WebshellTester(env_name=args.env, keep_container=args.keep_container)
        tester.test_connection_sync(args.shell)
    elif args.command == "prebuild":
        builder = DockerImageBuilder()
        if args.list_envs:
            builder.show_image_info()
        else:
            logger.info("Please use tools/prebuild_images.py to build images")
    elif args.command == "deploy":
        # implement deploy logic
        logger.info(f"Deploying {args.shell} to {args.env}")
        env_manager = EnvironmentManager(env_name=args.env, keep_container=True)
        env_manager.setup_test_env(webshell_file=args.shell)
    else:
        parser.print_help()