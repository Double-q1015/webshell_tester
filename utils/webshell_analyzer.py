#!/usr/bin/env python3
import os
import sys
import hashlib
import datetime
from typing import Optional, Dict, List
from loguru import logger
import re
import magic
from dataclasses import asdict
from tqdm import tqdm

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


from utils.models import WebshellConfig, ConnectionInfo, Features, Detection, Metadata

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

            # basic file information
            file_size = os.path.getsize(file_path)
            logger.debug(f"File size: {file_size} bytes")

            # detect file type
            file_type = self._detect_file_type(file_path)
            logger.debug(f"Detected file type: {file_type}")
            if not file_type:
                logger.error(f"Unsupported file type: {file_path}")
                return None

            # read file content
            with open(file_path, 'rb') as f:
                content = f.read()
                text_content = content.decode('utf-8', errors='ignore')
            logger.debug(f"File content length: {len(text_content)} characters")

            # calculate MD5
            md5 = hashlib.md5(content).hexdigest()
            logger.debug(f"File MD5: {md5}")

            # analyze connection method
            logger.debug("Starting to analyze connection method...")
            connection = self._analyze_connection(text_content)
            if not connection:
                logger.warning(f"Unable to identify connection method: {file_path}")
                logger.debug("File content preview:")
                preview = text_content[:500] + "..." if len(text_content) > 500 else text_content
                logger.debug(preview)
                return None

            logger.debug(f"Identified connection info: {connection}")

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
        """Analyze WebShell connection method"""
        # initialize connection info
        connection_info = ConnectionInfo()
        
        # detect connection method
        if "$_GET" in content:
            connection_info.method = "GET"
        elif "$_POST" in content or "php://input" in content:
            connection_info.method = "POST"
            if "php://input" in content:
                connection_info.use_raw_post = True
        
        # detect obfuscated webshell
        if "${'_REQUEST'}" in content and "if (!empty(" in content:
            connection_info.obfuscated = True
            # try to extract parameter name
            pattern = r"\$(\w+)\s*=\s*\$\{'_REQUEST'\}"
            match = re.search(pattern, content)
            if match:
                var_name = match.group(1)
                # find parameter name
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
        
        # detect password
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
        
        # detect parameter name - 改进的参数名检测
        param_patterns = [
            r'\$_(?:GET|POST|REQUEST)\s*\[\s*[\'"]([^\'"]+)[\'"]\s*\]',  # 基本模式
            r'eval\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[\s*[\'"]([^\'"]+)[\'"]\s*\]\s*\)',  # eval模式
            r'system\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[\s*[\'"]([^\'"]+)[\'"]\s*\]\s*\)',  # system模式
            r'assert\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[\s*[\'"]([^\'"]+)[\'"]\s*\]\s*\)',  # assert模式
            r'preg_replace\s*\([^,]+/e,\s*\$_(?:GET|POST|REQUEST)\s*\[\s*[\'"]([^\'"]+)[\'"]\s*\]',  # preg_replace模式
            r'create_function\s*\(\s*[^,]+,\s*\$_(?:GET|POST|REQUEST)\s*\[\s*[\'"]([^\'"]+)[\'"]\s*\]\s*\)',  # create_function模式
            r'call_user_func\s*\(\s*[^,]+,\s*\$_(?:GET|POST|REQUEST)\s*\[\s*[\'"]([^\'"]+)[\'"]\s*\]\s*\)',  # call_user_func模式
            r'array_map\s*\(\s*[^,]+,\s*array\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[\s*[\'"]([^\'"]+)[\'"]\s*\]\s*\)\s*\)',  # array_map模式
            r'eval\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[\s*[\'"]([^\'"]+)[\'"]\s*\]\s*\)\s*;'  # eval模式（带分号）
        ]
        
        for pattern in param_patterns:
            match = re.search(pattern, content)
            if match:
                connection_info.param_name = match.group(1)
                break
        
        # detect encoding
        if "base64_decode" in content:
            connection_info.encoding = "base64"
        
        # detect preg_replace
        if "preg_replace" in content and "/e" in content:
            connection_info.preg_replace = True
            connection_info.php_version = "5.4"  # preg_replace /e in PHP 5.5 is deprecated
        
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