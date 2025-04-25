#!/usr/bin/env python3
from dataclasses import dataclass, asdict
from typing import List, Dict, Any

@dataclass
class Features:
    file_upload: bool = False
    command_exec: bool = False
    database_ops: bool = False
    eval_usage: bool = False
    obfuscated: bool = False

@dataclass
class ConnectionInfo:
    """WebShell连接信息"""
    method: str = "POST"  # 默认使用POST方法
    param_name: str = None  # 参数名
    password: str = None  # 密码值
    password_param: str = None  # 密码参数名
    eval_usage: bool = False  # 是否使用eval
    obfuscated: bool = False  # 是否混淆
    header: dict = None  # 请求头
    url_param: str = None  # 是否使用URL参数
    encoding: str = None  # 编码方式（如base64）
    use_raw_post: bool = False  # 是否使用原始POST数据
    preg_replace: bool = False  # 是否使用preg_replace
    special_auth: dict = None  # 特殊认证信息，格式为 {"type": "xxx", "value": "xxx"}
    php_version: str = None  # 可选的PHP版本
    features: Features = None

    def __post_init__(self):
        if self.features is None:
            self.features = Features()
        if self.special_auth is None:
            self.special_auth = {}
        if self.header is None:
            self.header = {}

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            'method': self.method,
            'param_name': self.param_name,
            'password': self.password,
            'password_param': self.password_param,
            'url_param': self.url_param,
            'header': self.header,
            'eval_usage': self.eval_usage,
            'obfuscated': self.obfuscated,
            'encoding': self.encoding,
            'use_raw_post': self.use_raw_post,
            'preg_replace': self.preg_replace,
            'special_auth': self.special_auth,
            'php_version': self.php_version,
            'features': asdict(self.features) if self.features else None
        }

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

    def to_dict(self) -> dict:
        """转换为字典"""
        return {
            'filename': self.filename,
            'type': self.type,
            'size': self.size,
            'md5': self.md5,
            'connection': self.connection.to_dict() if self.connection else {},
            'features': asdict(self.features) if self.features else {},
            'detection': asdict(self.detection) if self.detection else {},
            'metadata': asdict(self.metadata) if self.metadata else {}
        }