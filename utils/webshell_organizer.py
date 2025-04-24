#!/usr/bin/env python3
import os
import sys
import json
import shutil
import hashlib
import datetime
from typing import Optional
from loguru import logger
import re
import magic
from dataclasses import asdict

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.mylogger import setup_logger
from utils.webshell_tester import WebshellTester
from utils.models import WebshellConfig, ConnectionInfo, Features, Detection, Metadata

class WebshellAnalyzer:
    def __init__(self):
        self.mime = magic.Magic(mime=True)
        # 常见的webshell特征
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
            ]
        }

    def analyze_file(self, file_path: str) -> Optional[WebshellConfig]:
        """分析webshell文件并生成配置"""
        try:
            if not os.path.exists(file_path):
                logger.error(f"文件不存在: {file_path}")
                return None

            # 基本文件信息
            file_size = os.path.getsize(file_path)
            logger.debug(f"文件大小: {file_size} 字节")

            # 检测文件类型
            file_type = self._detect_file_type(file_path)
            logger.debug(f"检测到的文件类型: {file_type}")
            if not file_type:
                logger.error(f"不支持的文件类型: {file_path}")
                return None

            # 读取文件内容
            with open(file_path, 'rb') as f:
                content = f.read()
                text_content = content.decode('utf-8', errors='ignore')
            logger.debug(f"文件内容长度: {len(text_content)} 字符")

            # 计算MD5
            md5 = hashlib.md5(content).hexdigest()
            logger.debug(f"文件MD5: {md5}")

            # 分析连接方法
            logger.debug("开始分析连接方法...")
            connection = self._analyze_connection(text_content)
            if not connection:
                logger.warning(f"无法识别连接方法: {file_path}")
                logger.debug("文件内容预览:")
                preview = text_content[:500] + "..." if len(text_content) > 500 else text_content
                logger.debug(preview)
                return None

            logger.debug(f"识别到的连接信息: {connection}")

            # 分析特征
            logger.debug("开始分析文件特征...")
            features = self._analyze_features(text_content)
            logger.debug(f"识别到的特征: {features}")

            # 创建配置
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

            logger.debug(f"生成的配置信息: {asdict(config)}")
            return config

        except Exception as e:
            logger.error(f"分析文件时出错 {file_path}: {str(e)}")
            import traceback
            logger.debug(f"错误堆栈:\n{traceback.format_exc()}")
            return None

    def _detect_file_type(self, file_path: str) -> Optional[str]:
        """检测文件类型"""
        try:
            mime_type = self.mime.from_file(file_path)
            logger.debug(f"MIME类型: {mime_type}")
            
            with open(file_path, 'rb') as f:
                content = f.read(1024).decode('utf-8', errors='ignore')
            logger.debug("文件头内容预览:")
            logger.debug(content[:200])

            if 'php' in mime_type.lower() or '<?php' in content.lower():
                return 'php'
            elif 'jsp' in mime_type.lower() or '<%' in content:
                return 'jsp'
            elif 'asp' in mime_type.lower():
                return 'asp'
            
            logger.debug(f"无法确定文件类型，MIME类型: {mime_type}")
            return None
            
        except Exception as e:
            logger.error(f"检测文件类型时出错: {str(e)}")
            return None

    def _analyze_connection(self, content: str) -> Optional[ConnectionInfo]:
        """分析webshell的连接方法"""
        # 常见的密码参数模式
        param_patterns = [
            # 标准POST/GET参数模式
            (r'\$_POST\[[\'"](.*?)[\'"]\]', 'POST'),
            (r'\$_GET\[[\'"](.*?)[\'"]\]', 'GET'),
            (r'\$_REQUEST\[[\'"](.*?)[\'"]\]', 'POST'),
            # 密码验证模式
            (r'\$password\s*=\s*[\'"](.+?)[\'"]', 'POST'),  # 硬编码密码
            (r'if\s*\(\s*\$_POST\[[\'"](\w+)[\'"]\]', 'POST'),  # if判断中的密码
            (r'if\s*\(\s*\$_GET\[[\'"](\w+)[\'"]\]', 'GET'),   # if判断中的密码
        ]

        # 命令执行参数模式
        cmd_patterns = [
            r'\$_POST\[[\'"](.*?)[\'"]\]',
            r'\$_GET\[[\'"](.*?)[\'"]\]',
            r'\$_REQUEST\[[\'"](.*?)[\'"]\]'
        ]

        logger.debug("开始匹配密码参数模式...")
        
        # 尝试识别密码参数
        password_param = None
        method = 'POST'  # 默认使用POST
        
        for pattern, req_method in param_patterns:
            logger.debug(f"尝试模式: {pattern}")
            matches = re.findall(pattern, content)
            if matches:
                for match in matches:
                    # 排除常见的命令参数名
                    if match.lower() not in ['cmd', 'command', 'exec', 'system', 'shell']:
                        password_param = match
                        method = req_method
                        logger.debug(f"找到可能的密码参数: {password_param}")
                        break
                if password_param:
                    break

        # 如果找不到密码参数，但发现了硬编码密码
        if not password_param:
            pwd_match = re.search(r'\$password\s*=\s*[\'"](.+?)[\'"]', content)
            if pwd_match:
                password_param = 'pwd'  # 使用默认参数名
                logger.debug(f"使用默认密码参数: {password_param}")

        # 如果仍然找不到密码参数，检查是否是简单的命令执行
        if not password_param:
            for pattern in cmd_patterns:
                matches = re.findall(pattern, content)
                if matches:
                    for match in matches:
                        if match.lower() in ['cmd', 'command', 'exec', 'system', 'shell']:
                            password_param = match
                            logger.debug(f"找到命令参数: {password_param}")
                            break
                    if password_param:
                        break

        if not password_param:
            return None

        # 检测编码方式
        encoding = 'raw'
        if 'base64_decode' in content or 'base64_encode' in content:
            encoding = 'base64'
            logger.debug("检测到base64编码")

        # 检测命令参数
        cmd_param = None
        for pattern in cmd_patterns:
            matches = re.findall(pattern, content)
            if matches:
                for match in matches:
                    if match.lower() in ['cmd', 'command', 'exec', 'system', 'shell']:
                        cmd_param = match
                        logger.debug(f"找到命令参数: {cmd_param}")
                        break
                if cmd_param:
                    break

        # 如果找到了密码参数但没有找到命令参数，使用默认值
        if not cmd_param:
            cmd_param = 'cmd'
            logger.debug("使用默认命令参数: cmd")

        connection_info = ConnectionInfo(
            method=method,
            password=password_param,
            param_name=cmd_param,  # 使用命令参数作为主要参数
            encoding=encoding,
            test_command="echo 'test';"
        )
        
        logger.debug(f"生成的连接信息: {connection_info}")
        return connection_info

    def _analyze_features(self, content: str) -> Features:
        """分析webshell的特征"""
        features = Features()

        # 检查各种特征
        for feature, patterns in self.feature_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    setattr(features, feature, True)
                    break

        # 检查是否混淆
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
    def __init__(self, source_dir: str, target_dir: str, test_connection: bool = True):
        self.source_dir = source_dir
        self.target_dir = target_dir
        self.analyzer = WebshellAnalyzer()
        self.tester = WebshellTester() if test_connection else None
        self.processed_files = []
        self.failed_files = []
        self.test_results = {
            'success': [],
            'failed': []
        }

    def process_directory(self):
        """处理源目录中的所有文件"""
        logger.info(f"开始处理目录: {self.source_dir}")
        
        # 创建目标目录结构
        self._create_directory_structure()

        # 遍历源目录
        for root, _, files in os.walk(self.source_dir):
            for file in files:
                file_path = os.path.join(root, file)
                self._process_file(file_path)

        # 输出处理报告
        self._generate_report()

    def _create_directory_structure(self):
        """创建目标目录结构"""
        os.makedirs(os.path.join(self.target_dir, 'php'), exist_ok=True)
        os.makedirs(os.path.join(self.target_dir, 'jsp'), exist_ok=True)
        os.makedirs(os.path.join(self.target_dir, 'asp'), exist_ok=True)
        os.makedirs(os.path.join(self.target_dir, 'other'), exist_ok=True)

    def _process_file(self, file_path: str):
        """处理单个文件"""
        logger.info(f"正在处理文件: {file_path}")

        try:
            # 分析文件
            config = self.analyzer.analyze_file(file_path)
            if not config:
                self.failed_files.append(file_path)
                return

            # 确定目标路径
            target_subdir = config.type if config.type else 'other'
            target_filename = f"{config.md5}.{config.type}"
            target_path = os.path.join(self.target_dir, target_subdir, target_filename)
            json_path = os.path.join(self.target_dir, target_subdir, f"{config.md5}.json")

            # 测试连接
            connection_success = False
            if self.tester and config.type in ['php', 'jsp']:
                logger.info(f"正在测试连接: {file_path}")
                connection_success = self.tester.test_connection_sync(config)
                config.metadata.working_status = connection_success
                
                if connection_success:
                    self.test_results['success'].append(file_path)
                else:
                    self.test_results['failed'].append(file_path)
                    self.failed_files.append(file_path)
                    logger.warning(f"连接测试失败，跳过文件整理: {file_path}")
                    return

            # 只有测试成功或不需要测试的文件才会被整理
            if not self.tester or connection_success:
                # 复制文件
                shutil.copy2(file_path, target_path)

                # 保存配置文件
                with open(json_path, 'w', encoding='utf-8') as f:
                    json.dump(asdict(config), f, indent=2, ensure_ascii=False)

                self.processed_files.append({
                    'source': file_path,
                    'target': target_path,
                    'config': json_path,
                    'working': config.metadata.working_status
                })
                logger.success(f"成功整理文件: {file_path} -> {target_path}")

        except Exception as e:
            logger.error(f"处理文件失败 {file_path}: {str(e)}")
            self.failed_files.append(file_path)

    def _generate_report(self):
        """生成处理报告"""
        logger.info("\n=== 处理报告 ===")
        logger.info(f"成功整理: {len(self.processed_files)} 个文件")
        logger.info(f"未通过/失败: {len(self.failed_files)} 个文件")

        if self.tester:
            logger.info("\n=== 连接测试报告 ===")
            logger.info(f"连接成功: {len(self.test_results['success'])} 个文件")
            logger.info(f"连接失败: {len(self.test_results['failed'])} 个文件")

        if self.failed_files:
            logger.info("\n未通过/失败文件列表:")
            for file in self.failed_files:
                if file in self.test_results['failed']:
                    logger.info(f"- {file} (连接测试失败)")
                else:
                    logger.info(f"- {file} (处理失败)")

        if self.processed_files:
            logger.info("\n成功整理的文件列表:")
            for file in self.processed_files:
                logger.info(f"- {file['source']} -> {file['target']}")

def main():
    setup_logger()
    if len(sys.argv) < 3:
        print("Usage: python webshell_organizer.py <source_dir> <target_dir> [--no-test]")
        sys.exit(1)

    source_dir = sys.argv[1]
    target_dir = sys.argv[2]
    test_connection = "--no-test" not in sys.argv

    organizer = WebshellOrganizer(source_dir, target_dir, test_connection)
    organizer.process_directory()

if __name__ == "__main__":
    main() 