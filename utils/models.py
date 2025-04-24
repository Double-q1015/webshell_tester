#!/usr/bin/env python3
from dataclasses import dataclass
from typing import List

@dataclass
class ConnectionInfo:
    method: str
    password: str
    param_name: str
    encoding: str
    test_command: str = "echo 'test';"

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