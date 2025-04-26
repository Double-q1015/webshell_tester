#!/usr/bin/env python3
from dataclasses import dataclass
from typing import List, Dict, Any

@dataclass
class ConnectionInfo:
    """WebShell connection information"""
    def __init__(
        self,
        method: str = "POST",
        password: str = None,
        param_name: str = None,
        encoding: str = None,
        preg_replace: bool = False,
        use_raw_post: bool = False,
        php_version: str = None,
        obfuscated: bool = False,
        obfuscated_params: Dict = None,
        test_command: str = "echo 'test';"
    ):
        self.method = method
        self.password = password
        self.param_name = param_name
        self.encoding = encoding
        self.preg_replace = preg_replace
        self.use_raw_post = use_raw_post
        self.php_version = php_version
        self.obfuscated = obfuscated
        self.obfuscated_params = obfuscated_params
        self.test_command = test_command

    def to_dict(self):
        return {
            'method': self.method,
            'password': self.password,
            'param_name': self.param_name,
            'encoding': self.encoding,
            'preg_replace': self.preg_replace,
            'use_raw_post': self.use_raw_post,
            'php_version': self.php_version,
            'obfuscated': self.obfuscated,
            'obfuscated_params': self.obfuscated_params,
            'test_command': self.test_command
        }

@dataclass
class Features:
    file_upload: bool = False
    command_exec: bool = False
    database_ops: bool = False
    eval_usage: bool = False
    obfuscated: bool = False

@dataclass
class Detection:
    antivirus_score: int = 0
    yara_rules: List[str] = None

    def __post_init__(self):
        if self.yara_rules is None:
            self.yara_rules = []

@dataclass
class Metadata:
    discovered_date: str
    last_tested: str
    working_status: bool = False
    original_filename: str = ""
    source_path: str = ""

@dataclass
class WebshellConfig:
    filename: str
    type: str
    size: int
    md5: str
    connection: ConnectionInfo
    features: Features
    detection: Detection
    metadata: Metadata