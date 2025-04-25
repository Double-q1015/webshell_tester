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
from utils.output import save_results_as_html

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
            logger.debug("Starting to analyze file features...")
            features = self._analyze_features(text_content)
            logger.debug(f"Identified features: {features}")

            # 创建配置（移除错误的 features 赋值）
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
        connection_info.method = 'POST'  # 默认设置为POST
        
        # 检测是否使用eval
        if 'eval(' in content or 'assert(' in content:
            connection_info.eval_usage = True
        
        # 检测是否使用原始POST数据
        if 'php://input' in content:
            connection_info.use_raw_post = True
            return connection_info
            
        # 检测特殊认证
        if 'HTTP_USER_AGENT' in content:
            # 尝试多种匹配模式
            auth_patterns = [
                r"HTTP_USER_AGENT'\s*===?\s*'([^']+)'",
                r'HTTP_USER_AGENT\'\]==[\'"]([^\'"]+)[\'"]',
                r'\$_SERVER\s*\[\s*[\'"]HTTP_USER_AGENT[\'"]\s*\]\s*===?\s*[\'"]([^\'"]+)[\'"]'
            ]
            
            for pattern in auth_patterns:
                match = re.search(pattern, content)
                if match:
                    connection_info.special_auth = {
                        'type': 'user_agent',
                        'value': match.group(1)
                    }
                    break

        # 检测动态函数调用（如 key($_GET)）
        dynamic_func_pattern = r'\$?\w+\s*=\s*\(?key\s*\(\s*\$_GET\s*\)'
        if re.search(dynamic_func_pattern, content):
            connection_info.method = 'GET'
            connection_info.special_auth = {
                'type': 'dynamic_function',
                'value': 'key($_GET)'
            }
            # 检查POST参数
            post_param_match = re.search(r'\$_POST\s*\[\s*[\'"](\w+)[\'"]\s*\]', content)
            if post_param_match:
                connection_info.param_name = post_param_match.group(1)
            return connection_info

        # 检测base64编码
        if 'base64_decode' in content:
            connection_info.encoding = 'base64'
            # 提取base64编码的参数名
            base64_match = re.search(r'base64_decode\(\$_POST\[[\'"]([\w]+)[\'"]\]\)', content)
            if base64_match:
                connection_info.param_name = base64_match.group(1)
                return connection_info
        
        # 检测preg_replace
        if 'preg_replace' in content and '/e' in content:
            connection_info.preg_replace = True
            # 提取preg_replace参数名
            preg_match = re.search(r'preg_replace\([^,]+,\s*\$_POST\[[\'"]([\w]+)[\'"]\]\s*,', content)
            if preg_match:
                connection_info.param_name = preg_match.group(1)
                return connection_info
        
        # 提取参数名和密码
        # 首先检查是否有密码保护
        pwd_match = re.search(r'\$_(POST|GET)\[[\'"]([\w]+)[\'"]\]\s*===?\s*[\'"]([^\'"]+)[\'"]', content)
        if pwd_match:
            connection_info.password_param = pwd_match.group(2)
            connection_info.password = pwd_match.group(3)
            # 继续寻找命令参数
            cmd_match = re.search(r'eval\(\$_POST\[[\'"]([\w]+)[\'"]\]\)', content)
            if cmd_match and cmd_match.group(1) != connection_info.password_param:
                connection_info.param_name = cmd_match.group(1)
            return connection_info
        
        # 如果还没有找到参数名，尝试其他方式
        if not connection_info.param_name:
            # 检查简单的eval
            eval_match = re.search(r'@?eval\(\$_(POST|GET|REQUEST)\[[\'"]([\w]+)[\'"]\]\)', content)
            if eval_match:
                connection_info.param_name = eval_match.group(2)
                connection_info.method = eval_match.group(1)
            else:
                # 检查一般的参数
                param_match = re.search(r'\$_(POST|GET|REQUEST)\[[\'"]([\w]+)[\'"]\]', content)
                if param_match:
                    connection_info.param_name = param_match.group(2)
                    connection_info.method = param_match.group(1)
        
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
    def __init__(self, source_dir: str, target_dir: str, test_connection: bool = True, skip_exist: bool = False, output_format: str = 'json', verbose: bool = False):
        self.source_dir = source_dir
        self.target_dir = target_dir
        self.analyzer = WebshellAnalyzer()
        self.tester = WebshellTester() if test_connection else None
        self.skip_exist = skip_exist
        self.output_format = output_format
        self.verbose = verbose
        self.processed_files = []
        self.failed_files = []
        self.test_results = {
            'success': [],
            'failed': []
        }
        self.execution_details = []  # 存储详细的执行信息
        self.stats = {
            'start_time': datetime.datetime.now(),
            'end_time': None,
            'total_files': 0,
            'successful_files': 0,
            'failed_files': 0,
            'skipped_files': 0,
            'total_execution_time': 0,
            'average_execution_time': 0
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

        # 暂时只检测20个文件
        all_files = all_files[:20]
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
        """处理单个文件"""
        logger.info(f"处理文件: {file_path}")
        execution_detail = {
            'file': file_path,
            'steps': [],
            'start_time': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'end_time': None,
            'success': False,
            'error': None
        }

        try:
            # 分析文件
            step_start = datetime.datetime.now()
            config = self.analyzer.analyze_file(file_path)
            step_end = datetime.datetime.now()
            
            execution_detail['steps'].append({
                'step': '文件分析',
                'start_time': step_start.strftime("%Y-%m-%d %H:%M:%S"),
                'end_time': step_end.strftime("%Y-%m-%d %H:%M:%S"),
                'duration': (step_end - step_start).total_seconds(),
                'success': bool(config),
                'details': {
                    'file_type': config.type if config else None,
                    'size': config.size if config else None,
                    'md5': config.md5 if config else None,
                    'features': asdict(config.features) if config and config.features else None
                }
            })

            if not config:
                execution_detail['error'] = "文件分析失败"
                self.failed_files.append(file_path)
                execution_detail['end_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.execution_details.append(execution_detail)
                return

            # 确定目标路径
            target_subdir = config.type if config.type else 'other'
            target_filename = f"{config.md5}.{config.type}"
            target_path = os.path.join(self.target_dir, target_subdir, target_filename)
            json_path = os.path.join(self.target_dir, target_subdir, f"{config.md5}.json")

            # 检查文件是否存在
            if self.skip_exist and os.path.exists(target_path) and os.path.exists(json_path):
                execution_detail['steps'].append({
                    'step': '文件检查',
                    'success': True,
                    'details': {
                        'message': '文件已存在，跳过处理',
                        'target_path': target_path
                    }
                })
                logger.info(f"文件已存在，跳过: {file_path}")
                self.stats['skipped_files'] += 1
                execution_detail['success'] = True
                execution_detail['end_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.execution_details.append(execution_detail)
                return

            # 测试连接
            connection_success = False
            if self.tester and config.type in ['php', 'jsp']:
                logger.info(f"测试连接: {file_path}")
                step_start = datetime.datetime.now()
                test_result = self.tester.test_connection_sync(config)
                step_end = datetime.datetime.now()
                
                execution_detail['steps'].append({
                    'step': '连接测试',
                    'start_time': step_start.strftime("%Y-%m-%d %H:%M:%S"),
                    'end_time': step_end.strftime("%Y-%m-%d %H:%M:%S"),
                    'duration': (step_end - step_start).total_seconds(),
                    'success': test_result,
                    'details': {
                        'test_commands': self.tester.last_commands if hasattr(self.tester, 'last_commands') else [],
                        'test_responses': self.tester.last_responses if hasattr(self.tester, 'last_responses') else [],
                        'connection_info': asdict(config.connection)
                    }
                })
                
                connection_success = test_result
                config.metadata.working_status = connection_success
                
                if connection_success:
                    self.test_results['success'].append(file_path)
                else:
                    self.test_results['failed'].append(file_path)
                    self.failed_files.append(file_path)
                    execution_detail['error'] = "连接测试失败"
                    logger.warning(f"连接测试失败，跳过文件: {file_path}")
                    execution_detail['end_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    self.execution_details.append(execution_detail)
                    return

            # 只有通过测试或不需要测试的文件才会被整理
            if not self.tester or connection_success:
                # 复制文件
                step_start = datetime.datetime.now()
                shutil.copy2(file_path, target_path)
                step_end = datetime.datetime.now()
                
                execution_detail['steps'].append({
                    'step': '文件复制',
                    'start_time': step_start.strftime("%Y-%m-%d %H:%M:%S"),
                    'end_time': step_end.strftime("%Y-%m-%d %H:%M:%S"),
                    'duration': (step_end - step_start).total_seconds(),
                    'success': True,
                    'details': {
                        'source': file_path,
                        'target': target_path
                    }
                })

                # 保存配置文件
                step_start = datetime.datetime.now()
                with open(json_path, 'w', encoding='utf-8') as f:
                    json.dump(config.to_dict(), f, indent=4, ensure_ascii=False)
                step_end = datetime.datetime.now()
                
                execution_detail['steps'].append({
                    'step': '保存配置',
                    'start_time': step_start.strftime("%Y-%m-%d %H:%M:%S"),
                    'end_time': step_end.strftime("%Y-%m-%d %H:%M:%S"),
                    'duration': (step_end - step_start).total_seconds(),
                    'success': True,
                    'details': {
                        'config_path': json_path,
                        'config': config.to_dict() if self.verbose else None
                    }
                })

                self.processed_files.append({
                    'source': file_path,
                    'target': target_path,
                    'config': json_path,
                    'working': config.metadata.working_status
                })
                execution_detail['success'] = True
                logger.success(f"成功处理文件: {file_path} -> {target_path}")

        except Exception as e:
            logger.error(f"处理文件失败: {file_path}: {str(e)}")
            execution_detail['error'] = str(e)
            self.failed_files.append(file_path)
            
        execution_detail['end_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.execution_details.append(execution_detail)

    def _generate_report(self):
        """生成处理报告"""
        duration = (self.stats['end_time'] - self.stats['start_time']).total_seconds()
        self.stats['total_execution_time'] = duration
        self.stats['average_execution_time'] = duration / self.stats['total_files'] if self.stats['total_files'] > 0 else 0

        logger.info("\n=== 处理报告 ===")
        logger.info(f"总文件数: {self.stats['total_files']}")
        logger.info(f"成功处理: {self.stats['successful_files']} 个文件")
        logger.info(f"处理失败: {self.stats['failed_files']} 个文件")
        logger.info(f"跳过已存在: {self.stats['skipped_files']} 个文件")
        logger.info(f"处理总时间: {duration:.2f} 秒")

        if self.tester:
            logger.info("\n=== 连接测试报告 ===")
            logger.info(f"测试成功: {len(self.test_results['success'])} 个文件")
            logger.info(f"测试失败: {len(self.test_results['failed'])} 个文件")

        if self.failed_files:
            logger.info("\n失败文件列表:")
            for file in self.failed_files:
                if file in self.test_results['failed']:
                    logger.info(f"- {file} (连接测试失败)")
                else:
                    logger.info(f"- {file} (处理失败)")

        if self.processed_files:
            logger.info("\n成功处理的文件列表:")
            for file in self.processed_files:
                logger.info(f"- {file['source']} -> {file['target']}")

        # 准备报告数据
        report_data = {
            'stats': self.stats,
            'processed_files': self.processed_files,
            'failed_files': self.failed_files,
            'test_results': self.test_results,
            'total_commands': len(self.processed_files),
            'successful_commands': len(self.test_results['success']),
            'execution_details': self.execution_details if self.verbose else None,
            'results': []
        }

        # 添加成功处理的文件
        for file in self.processed_files:
            report_data['results'].append({
                'command': 'analyze_and_organize',
                'success': True,
                'output': f"已处理: {file['source']} -> {file['target']}",
                'error': None
            })
            
        # 添加失败的文件
        for file_path in self.failed_files:
            report_data['results'].append({
                'command': 'analyze_and_organize',
                'success': False,
                'output': None,
                'error': "连接测试失败" if file_path in self.test_results['failed'] else "处理失败",
                'file': file_path
            })

        # 保存报告
        if self.output_format == 'html':
            save_results_as_html(report_data, self.target_dir)
            logger.info(f"\nHTML报告已生成在: {self.target_dir}")
        else:
            # 保存JSON报告
            report_path = os.path.join(self.target_dir, 'report.json')
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=4, ensure_ascii=False, default=str)
            logger.info(f"\nJSON报告已生成在: {report_path}")

def test_single_file(file_path: str, verbose: bool = False, keep_container: bool = False):
    """
    Test the analysis and connection of a single file
    Args:
        file_path: str, the path of the file to be tested
        verbose: bool, whether to show detailed information
        keep_container: bool, whether to keep the container running after testing
    """
    if not os.path.exists(file_path):
        logger.error(f"File does not exist: {file_path}")
        return

    analyzer = WebshellAnalyzer()
    tester = WebshellTester(keep_container=keep_container)

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

    if keep_container:
        logger.info("容器将在测试后保持运行")
        logger.info("请在测试完成后手动停止和删除容器")

def main():
    setup_logger()
    logo()
    
    parser = argparse.ArgumentParser(description='WebShell自动整理工具')
    parser.add_argument('source_dir', nargs='?', help='源目录路径')
    parser.add_argument('target_dir', nargs='?', help='目标目录路径')
    parser.add_argument('--no-test', action='store_true', help='不执行连接测试')
    parser.add_argument('--skip-exist', action='store_true', help='跳过已存在的文件')
    parser.add_argument('--test-file', help='测试单个文件')
    parser.add_argument('--keep-container', action='store_true', help='测试完成后保持容器运行（仅在 --test-file 模式下有效）')
    parser.add_argument('--verbose', '-v', action='store_true', help='显示详细信息')
    parser.add_argument('--format', choices=['json', 'html'], default='json', help='报告输出格式 (json 或 html)')
    
    args = parser.parse_args()

    if args.test_file:
        # 测试单个文件
        if args.keep_container:
            logger.info("容器将在测试后保持运行")
            logger.info("请在测试完成后手动停止和删除容器")
        test_single_file(args.test_file, args.verbose, args.keep_container)
        return

    if not args.source_dir or not args.target_dir:
        parser.print_help()
        sys.exit(1)

    organizer = WebshellOrganizer(
        args.source_dir,
        args.target_dir,
        test_connection=not args.no_test,
        skip_exist=args.skip_exist,
        output_format=args.format,
        verbose=args.verbose
    )
    organizer.process_directory()

if __name__ == "__main__":
    main() 