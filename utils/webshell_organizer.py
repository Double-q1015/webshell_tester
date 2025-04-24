#!/usr/bin/env python3
import os
import sys
import json
import shutil
import hashlib
import datetime
from typing import Optional, Dict, List
from loguru import logger
import re
import magic
from dataclasses import asdict
import argparse
from tqdm import tqdm

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.mylogger import setup_logger
from utils.webshell_tester import WebshellTester
from utils.models import WebshellConfig, ConnectionInfo, Features, Detection, Metadata
from utils.logo import logo

class WebshellAnalyzer:
    def __init__(self):
        self.mime = magic.Magic(mime=True)
        self.logger = logger
        # initialize performance stats
        self.performance_stats = {
            'files_processed': 0,
            'processing_time': 0,
            'avg_processing_time': 0
        }
        # common webshell features
        self.feature_patterns = {
            'file_upload': [
                r'move_uploaded_file',
                r'copy\s*\(',
                r'fwrite\s*\(',
                r'file_put_contents'
            ],
            'command_exec': [
                r'system\s*\(',
                r'exec\s*\(',
                r'shell_exec',
                r'passthru',
                r'popen'
            ],
            'database_ops': [
                r'mysql_',
                r'mysqli_',
                r'pdo',
                r'sqlite'
            ],
            'eval_usage': [
                r'eval\s*\(',
                r'assert\s*\(',
                r'preg_replace\s*\([^,]+/e'
            ],
            'special_auth': [
                r'\$_SERVER\[\'HTTP_USER_AGENT\'\]\s*===\s*[\'"](.*?)[\'"]',
                r'\$_SERVER\[\'HTTP_USER_AGENT\'\]\s*!==\s*[\'"](.*?)[\'"]',
                r'strpos\s*\(\s*\$_SERVER\[\'HTTP_USER_AGENT\'\],\s*[\'"](.*?)[\'"]\s*\)'
            ]
        }

    def analyze_file(self, file_path: str) -> Optional[WebshellConfig]:
        """Analyze webshell file and generate config"""
        start_time = datetime.datetime.now()
        try:
            if not os.path.exists(file_path):
                logger.error(f"File does not exist: {file_path}")
                return None

            # 基本文件信息
            file_size = os.path.getsize(file_path)
            logger.debug(f"File size: {file_size} bytes")

            # 检测文件类型
            file_type = self._detect_file_type(file_path)
            logger.debug(f"Detected file type: {file_type}")
            if not file_type:
                logger.error(f"Unsupported file type: {file_path}")
                return None

            # 读取文件内容
            with open(file_path, 'rb') as f:
                content = f.read()
                text_content = content.decode('utf-8', errors='ignore')
            logger.debug(f"File content length: {len(text_content)} characters")

            # 计算MD5
            md5 = hashlib.md5(content).hexdigest()
            logger.debug(f"File MD5: {md5}")

            # 分析连接方法
            logger.debug("Starting to analyze connection method...")
            connection = self._analyze_connection(text_content)
            if not connection:
                logger.warning(f"Unable to identify connection method: {file_path}")
                logger.debug("File content preview:")
                preview = text_content[:500] + "..." if len(text_content) > 500 else text_content
                logger.debug(preview)
                return None

            logger.debug(f"Identified connection info: {connection}")

            # 分析特征
            # analyze file features
            logger.debug("Starting to analyze file features...")
            features = self._analyze_features(text_content)
            logger.debug(f"Identified features: {features}")

            # create config
            config = WebshellConfig(
                filename=os.path.basename(file_path),
                type=file_type,
                size=file_size,
                md5=md5,
                connection=connection,
                features=features,
                detection=Detection(),
                metadata=Metadata(
                    discovered_date=datetime.datetime.now().strftime("%Y-%m-%d"),
                    last_tested=datetime.datetime.now().strftime("%Y-%m-%d"),
                    original_filename=os.path.basename(file_path),
                    source_path=file_path
                )
            )

            # update performance stats
            end_time = datetime.datetime.now()
            processing_time = (end_time - start_time).total_seconds()
            self.performance_stats['files_processed'] += 1
            self.performance_stats['processing_time'] += processing_time
            self.performance_stats['avg_processing_time'] = (
                self.performance_stats['processing_time'] / 
                self.performance_stats['files_processed']
            )

            logger.debug(f"Generated config info: {asdict(config)}")
            return config

        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {str(e)}")
            import traceback
            logger.debug(f"Error stack:\n{traceback.format_exc()}")
            return None

    def get_performance_stats(self) -> Dict:
        """Get performance stats"""
        return self.performance_stats

    def _detect_file_type(self, file_path: str) -> Optional[str]:
        """Detect file type"""
        try:
            mime_type = self.mime.from_file(file_path)
            logger.debug(f"MIME type: {mime_type}")
            
            with open(file_path, 'rb') as f:
                content = f.read(1024).decode('utf-8', errors='ignore')
            logger.debug("File header content preview:")
            logger.debug(content[:200])

            if 'php' in mime_type.lower() or '<?php' in content.lower():
                return 'php'
            elif 'jsp' in mime_type.lower() or '<%' in content:
                return 'jsp'
            elif 'asp' in mime_type.lower():
                return 'asp'
            
            logger.debug(f"Unable to determine file type, MIME type: {mime_type}")
            return None
            
        except Exception as e:
            logger.error(f"Error detecting file type: {str(e)}")
            return None

    def _analyze_connection(self, content: str) -> ConnectionInfo:
        """分析WebShell连接方式"""
        # 初始化连接信息
        connection_info = ConnectionInfo()
        
        # 检测连接方法
        if "$_GET" in content:
            connection_info.method = "GET"
        elif "$_POST" in content or "php://input" in content:
            connection_info.method = "POST"
            if "php://input" in content:
                connection_info.use_raw_post = True
        
        # 检测混淆的 webshell
        if "${'_REQUEST'}" in content and "if (!empty(" in content:
            connection_info.obfuscated = True
            # 尝试提取参数名
            import re
            pattern = r"\$(\w+)\s*=\s*\$\{'_REQUEST'\}"
            match = re.search(pattern, content)
            if match:
                var_name = match.group(1)
                # 查找参数名
                param_pattern = rf"if \(!empty\(\${var_name}\['(\w+)'\]\)\)"
                param_match = re.search(param_pattern, content)
                if param_match:
                    connection_info.obfuscated_params = {
                        'func_name': param_match.group(1),
                        'decode_func': 'UpB_',
                        'param1': 'PWWk',
                        'param2': 'xfrwA',
                        'cmd_param': 'Epd'
                    }
        
        # 检测密码
        password_patterns = [
            r'if\s*\(\s*isset\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[\s*[\'"]([^\'"]+)[\'"]\s*\]\s*\)\s*\)',
            r'if\s*\(\s*!\s*empty\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[\s*[\'"]([^\'"]+)[\'"]\s*\]\s*\)\s*\)',
            r'if\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[\s*[\'"]([^\'"]+)[\'"]\s*\]\s*==\s*[\'"]([^\'"]+)[\'"]\s*\)'
        ]
        
        for pattern in password_patterns:
            match = re.search(pattern, content)
            if match:
                connection_info.password = match.group(1)
                break
        
        # 检测参数名
        param_patterns = [
            r'\$_(?:GET|POST|REQUEST)\s*\[\s*[\'"]([^\'"]+)[\'"]\s*\]',
            r'eval\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[\s*[\'"]([^\'"]+)[\'"]\s*\]\s*\)',
            r'system\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[\s*[\'"]([^\'"]+)[\'"]\s*\]\s*\)'
        ]
        
        for pattern in param_patterns:
            match = re.search(pattern, content)
            if match:
                connection_info.param_name = match.group(1)
                break
        
        # 检测编码
        if "base64_decode" in content:
            connection_info.encoding = "base64"
        
        # 检测 preg_replace
        if "preg_replace" in content and "/e" in content:
            connection_info.preg_replace = True
            connection_info.php_version = "5.4"  # preg_replace /e 在 PHP 5.5 中被废弃
        
        return connection_info

    def _analyze_features(self, content: str) -> Features:
        """Analyze webshell features"""
        features = Features()

        # check various features
        for feature, patterns in self.feature_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    setattr(features, feature, True)
                    break

        # check if obfuscated
        obfuscation_patterns = [
            r'base64_decode\s*\(',
            r'str_rot13\s*\(',
            r'gzinflate\s*\(',
            r'gzuncompress\s*\(',
            r'strrev\s*\(',
            r'\\x[0-9a-fA-F]{2}'
        ]
        
        for pattern in obfuscation_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                features.obfuscated = True
                break

        return features

class WebshellOrganizer:
    def __init__(self, source_dir: str, target_dir: str, test_connection: bool = True, skip_exist: bool = False):
        self.source_dir = source_dir
        self.target_dir = target_dir
        self.analyzer = WebshellAnalyzer()
        self.tester = WebshellTester() if test_connection else None
        self.skip_exist = skip_exist
        self.processed_files = []
        self.failed_files = []
        self.test_results = {
            'success': [],
            'failed': []
        }
        self.stats = {
            'start_time': datetime.datetime.now(),
            'end_time': None,
            'total_files': 0,
            'successful_files': 0,
            'failed_files': 0,
            'skipped_files': 0
        }

    def process_directory(self):
        """Process all files in the source directory"""
        logger.info(f"Starting to process directory: {self.source_dir}")
        
        # create target directory structure
        self._create_directory_structure()

        # get all file list
        all_files = []
        for root, _, files in os.walk(self.source_dir):
            for file in files:
                file_path = os.path.join(root, file)
                all_files.append(file_path)

        # 暂时只检测50个文件
        all_files = all_files[:50]
        self.stats['total_files'] = len(all_files)
        
        # use tqdm to show progress
        with tqdm(total=len(all_files), desc="Processing progress", ncols=100) as pbar:
            for file_path in all_files:
                self._process_file(file_path)
                pbar.update(1)

        # update stats
        self.stats['end_time'] = datetime.datetime.now()
        self.stats['successful_files'] = len(self.processed_files)
        self.stats['failed_files'] = len(self.failed_files)

        # output processing report
        self._generate_report()

    def _create_directory_structure(self):
        """Create target directory structure"""
        os.makedirs(os.path.join(self.target_dir, 'php'), exist_ok=True)
        os.makedirs(os.path.join(self.target_dir, 'jsp'), exist_ok=True)
        os.makedirs(os.path.join(self.target_dir, 'asp'), exist_ok=True)
        os.makedirs(os.path.join(self.target_dir, 'other'), exist_ok=True)

    def _process_file(self, file_path: str):
        """Process a single file"""
        logger.info(f"Processing file: {file_path}")

        try:
            # analyze file
            config = self.analyzer.analyze_file(file_path)
            if not config:
                self.failed_files.append(file_path)
                return

            # determine target path
            target_subdir = config.type if config.type else 'other'
            target_filename = f"{config.md5}.{config.type}"
            target_path = os.path.join(self.target_dir, target_subdir, target_filename)
            json_path = os.path.join(self.target_dir, target_subdir, f"{config.md5}.json")

            # check if file exists
            if self.skip_exist and os.path.exists(target_path) and os.path.exists(json_path):
                logger.info(f"File already exists, skipping: {file_path}")
                self.stats['skipped_files'] += 1
                return

            # test connection
            connection_success = False
            if self.tester and config.type in ['php', 'jsp']:
                logger.info(f"Testing connection: {file_path}")
                connection_success = self.tester.test_connection_sync(config)
                config.metadata.working_status = connection_success
                
                if connection_success:
                    self.test_results['success'].append(file_path)
                else:
                    self.test_results['failed'].append(file_path)
                    self.failed_files.append(file_path)
                    logger.warning(f"Connection test failed, skipping file: {file_path}")
                    return

            # only files that pass the test or don't need testing will be organized
            if not self.tester or connection_success:
                # copy file
                shutil.copy2(file_path, target_path)

                # save config file
                with open(json_path, 'w', encoding='utf-8') as f:
                    json.dump(asdict(config), f, indent=4, ensure_ascii=False)

                self.processed_files.append({
                    'source': file_path,
                    'target': target_path,
                    'config': json_path,
                    'working': config.metadata.working_status
                })
                logger.success(f"Successfully organized file: {file_path} -> {target_path}")

        except Exception as e:
            logger.error(f"Failed to process file: {file_path}: {str(e)}")
            self.failed_files.append(file_path)

    def _generate_report(self):
        """Generate processing report"""
        duration = (self.stats['end_time'] - self.stats['start_time']).total_seconds()

        logger.info("\n=== Processing report ===")
        logger.info(f"Total files: {self.stats['total_files']}")
        logger.info(f"Successful organized: {self.stats['successful_files']} files")
        logger.info(f"Failed/Unsuccessful: {self.stats['failed_files']} files")
        logger.info(f"Skipped existing: {self.stats['skipped_files']} files")
        logger.info(f"Processing time: {duration:.2f} seconds")

        if self.tester:
            logger.info("\n=== Connection test report ===")
            logger.info(f"Success: {len(self.test_results['success'])} files")
            logger.info(f"Failed: {len(self.test_results['failed'])} files")

        if self.failed_files:
            logger.info("\nFailed/Unsuccessful file list:")
            for file in self.failed_files:
                if file in self.test_results['failed']:
                    logger.info(f"- {file} (Connection test failed)")
                else:
                    logger.info(f"- {file} (Failed to process)")

        if self.processed_files:
            logger.info("\nSuccessfully organized file list:")
            for file in self.processed_files:
                logger.info(f"- {file['source']} -> {file['target']}")

        # save report to file
        report_path = os.path.join(self.target_dir, 'report.json')
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump({
                'stats': self.stats,
                'processed_files': self.processed_files,
                'failed_files': self.failed_files,
                'test_results': self.test_results
            }, f, indent=4, ensure_ascii=False, default=str)

def test_single_file(file_path: str, verbose: bool = False):
    """
    Test the analysis and connection of a single file
    Args:
        file_path: str, the path of the file to be tested
        verbose: bool, whether to show detailed information
    """
    if not os.path.exists(file_path):
        logger.error(f"File does not exist: {file_path}")
        return

    analyzer = WebshellAnalyzer()
    tester = WebshellTester()

    # analyze file
    # print analysis progress
    logger.info(f"Starting to analyze file: {file_path}")
    with tqdm(total=100, desc="Analysis progress", ncols=100) as pbar:
        config = analyzer.analyze_file(file_path)
        pbar.update(50)
        if not config:
            logger.error("File analysis failed")
            return

        # test connection
        success = tester.test_connection_sync(config)
        pbar.update(50)

    # print analysis results
    logger.info("\n=== Analysis results ===")
    logger.info(f"File type: {config.type}")
    logger.info(f"File size: {config.size} bytes")
    logger.info(f"MD5: {config.md5}")
    logger.info(f"Connection method: {config.connection.method}")
    
    if config.connection.special_auth:
        logger.info(f"Special authentication: {config.connection.special_auth['type']}")
        logger.info(f"Authentication value: {config.connection.special_auth['value']}")
    else:
        logger.info(f"Password parameter: {config.connection.password}")
        logger.info(f"Command parameter: {config.connection.param_name}")
    
    logger.info(f"Encoding: {config.connection.encoding}")

    # print connection test results
    logger.info("\n=== Connection test ===")
    if success:
        logger.success("Connection test successful")
    else:
        logger.error("Connection test failed")

    if verbose:
        # print features in detail
        logger.info("\n=== Detailed features ===")
        logger.info(f"File upload: {config.features.file_upload}")
        logger.info(f"Command execution: {config.features.command_exec}")
        logger.info(f"Database operations: {config.features.database_ops}")
        logger.info(f"Eval usage: {config.features.eval_usage}")
        logger.info(f"Obfuscated: {config.features.obfuscated}")

        # print original content
        logger.info("\n=== File content preview ===")
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            preview = content[:500] + "..." if len(content) > 500 else content
            logger.info(preview)

def main():
    setup_logger()
    logo()
    
    parser = argparse.ArgumentParser(description='WebShell Auto Organizer')
    parser.add_argument('source_dir', nargs='?', help='Source directory path')
    parser.add_argument('target_dir', nargs='?', help='Target directory path')
    parser.add_argument('--no-test', action='store_true', help='Not perform connection test')
    parser.add_argument('--skip-exist', action='store_true', help='Skip existing files')
    parser.add_argument('--test-file', help='Test a single file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show detailed information')
    
    args = parser.parse_args()

    if args.test_file:
        # test a single file
        test_single_file(args.test_file, args.verbose)
        return

    if not args.source_dir or not args.target_dir:
        parser.print_help()
        sys.exit(1)

    organizer = WebshellOrganizer(
        args.source_dir,
        args.target_dir,
        test_connection=not args.no_test,
        skip_exist=args.skip_exist
    )
    organizer.process_directory()

if __name__ == "__main__":
    main() 