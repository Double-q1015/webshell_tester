#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import os
import logging
import glob
from typing import List, Set
import argparse
import magic
import hashlib
from pathlib import Path

# 配置日志
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logger.addHandler(handler)

def get_file_info(file_path: str) -> dict:
    """获取文件基本信息"""
    file_path = Path(file_path)
    file_stat = file_path.stat()
    
    # 使用python-magic获取文件类型
    mime = magic.Magic(mime=True)
    file_type = mime.from_file(str(file_path))
    
    # 计算MD5
    md5 = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            md5.update(chunk)
            
    return {
        'name': file_path.name,
        'size': file_stat.st_size,
        'type': file_type,
        'md5': md5.hexdigest(),
        'created': file_stat.st_ctime,
        'modified': file_stat.st_mtime
    }

def read_file_content(file_path: str) -> str:
    """
    读取文件内容，支持多种编码
    """
    try:
        # 获取文件信息
        file_info = get_file_info(file_path)
        logger.info(f"\n文件信息:")
        logger.info(f"名称: {file_info['name']}")
        logger.info(f"大小: {file_info['size']} 字节")
        logger.info(f"类型: {file_info['type']}")
        logger.info(f"MD5: {file_info['md5']}")
        
        encodings = ['utf-8', 'gbk', 'gb2312', 'iso-8859-1', 'latin1']
        
        # 首先尝试二进制读取
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # 尝试不同的编码
        for encoding in encodings:
            try:
                return content.decode(encoding)
            except UnicodeDecodeError:
                continue
        
        # 如果所有编码都失败，使用二进制方式处理
        return content.decode('utf-8', errors='ignore')
        
    except Exception as e:
        logger.error(f"读取文件失败 {file_path}: {str(e)}")
        return None

def detect_dangerous_functions(content: str) -> Set[str]:
    """检测危险函数"""
    dangerous_funcs = {
        'system', 'exec', 'shell_exec', 'passthru', 'popen',
        'proc_open', 'pcntl_exec', 'eval', 'assert', 'create_function',
        'include', 'include_once', 'require', 'require_once'
    }
    found = set()
    for func in dangerous_funcs:
        if re.search(rf'\b{func}\s*\(', content):
            found.add(func)
    return found

def detect_obfuscation(content: str) -> Set[str]:
    """检测混淆技术"""
    techniques = set()
    patterns = {
        'base64': r'base64_decode\s*\(',
        'rot13': r'str_rot13\s*\(',
        'gzip': r'gzinflate\s*\(|gzuncompress\s*\(',
        'hex': r'hex2bin\s*\(|\\\x[0-9a-fA-F]{2}',
        'char_code': r'chr\s*\(\s*\d+\s*\)',
        'eval_concat': r'eval\s*\(\s*[\'"][^\'"]+[\'"]\s*\.\s*[\'"][^\'"]+[\'"]\s*\)'
    }
    for tech, pattern in patterns.items():
        if re.search(pattern, content):
            techniques.add(tech)
    return techniques

def detect_webshell_features(content: str) -> Set[str]:
    """检测WebShell特征"""
    features = set()
    patterns = {
        '命令执行': r'\$_(GET|POST|REQUEST)\[[\'"]cmd[\'"]\]',
        '文件上传': r'move_uploaded_file|copy\s*\(',
        '动态函数调用': r'\$\w+\s*\(\s*\$\w+\s*\)',
        '特殊认证': r'\$_SERVER\[\'HTTP_USER_AGENT\'\]',
        '一句话木马': r'eval\s*\(\s*\$_(POST|GET|REQUEST)',
        '加密通信': r'openssl_decrypt|mcrypt_decrypt'
    }
    for feat, pattern in patterns.items():
        if re.search(pattern, content):
            features.add(feat)
    return features

def detect_file_operations(content: str) -> Set[str]:
    """检测文件操作"""
    operations = set()
    patterns = {
        '文件读取': r'file_get_contents|fopen|readfile',
        '文件写入': r'file_put_contents|fwrite|fputs',
        '文件上传': r'move_uploaded_file',
        '文件删除': r'unlink|rmdir',
        '文件重命名': r'rename',
        '目录操作': r'scandir|opendir|readdir'
    }
    for op, pattern in patterns.items():
        if re.search(pattern, content):
            operations.add(op)
    return operations

def detect_network_operations(content: str) -> Set[str]:
    """检测网络操作"""
    operations = set()
    patterns = {
        'HTTP请求': r'curl_exec|file_get_contents\s*\(\s*[\'"]https?://',
        'Socket操作': r'fsockopen|socket_create',
        'DNS查询': r'gethostbyname|dns_get_record',
        '反弹Shell': r'bash\s+-i|nc\s+-e|python\s+-c\s+[\'"]*import\s+socket'
    }
    for op, pattern in patterns.items():
        if re.search(pattern, content):
            operations.add(op)
    return operations

def detect_system_commands(content: str) -> Set[str]:
    """检测系统命令执行"""
    commands = set()
    patterns = {
        '系统命令': r'system\s*\(|exec\s*\(|shell_exec\s*\(',
        '进程操作': r'proc_open|popen|pcntl_exec',
        '环境变量': r'putenv|getenv',
        '用户操作': r'posix_getpwuid|posix_getgrgid'
    }
    for cmd, pattern in patterns.items():
        if re.search(pattern, content):
            commands.add(cmd)
    return commands

def main():
    parser = argparse.ArgumentParser(description='PHP WebShell检测工具')
    parser.add_argument('path', help='要检测的文件或目录路径')
    parser.add_argument('-r', '--recursive', action='store_true', help='递归检测子目录')
    parser.add_argument('-v', '--verbose', action='store_true', help='显示详细信息')
    args = parser.parse_args()
    
    # 设置日志级别
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # 获取要检测的文件列表
    target_path = Path(args.path)
    if target_path.is_file():
        php_files = [target_path]
    else:
        pattern = '**/*.php' if args.recursive else '*.php'
        php_files = list(target_path.glob(pattern))
    
    if not php_files:
        logger.warning(f"未找到PHP文件: {args.path}")
        return
    
    logger.info(f"找到 {len(php_files)} 个PHP文件")
    
    # 检测结果统计
    stats = {
        'total': len(php_files),
        'suspicious': 0,
        'clean': 0,
        'error': 0
    }
    
    for file in php_files:
        try:
            logger.info(f"\n分析文件: {file}")
            
            # 读取文件内容
            content = read_file_content(str(file))
            if content is None:
                stats['error'] += 1
                continue
            
            # 初始化检测结果
            suspicious = False
                
            # 检测危险函数
            dangerous_functions = detect_dangerous_functions(content)
            if dangerous_functions:
                suspicious = True
                logger.warning("发现危险函数:")
                for func in dangerous_functions:
                    logger.warning(f"- {func}")
            
            # 检测混淆技术
            obfuscation = detect_obfuscation(content)
            if obfuscation:
                suspicious = True
                logger.warning("发现混淆技术:")
                for tech in obfuscation:
                    logger.warning(f"- {tech}")
            
            # 检测WebShell特征
            webshell_features = detect_webshell_features(content)
            if webshell_features:
                suspicious = True
                logger.warning("发现WebShell特征:")
                for feature in webshell_features:
                    logger.warning(f"- {feature}")
            
            # 检测文件操作
            file_operations = detect_file_operations(content)
            if file_operations:
                suspicious = True
                logger.warning("发现文件操作:")
                for op in file_operations:
                    logger.warning(f"- {op}")
            
            # 检测网络操作
            network_operations = detect_network_operations(content)
            if network_operations:
                suspicious = True
                logger.warning("发现网络操作:")
                for op in network_operations:
                    logger.warning(f"- {op}")
            
            # 检测系统命令执行
            system_commands = detect_system_commands(content)
            if system_commands:
                suspicious = True
                logger.warning("发现系统命令执行:")
                for cmd in system_commands:
                    logger.warning(f"- {cmd}")
            
            # 更新统计信息
            if suspicious:
                stats['suspicious'] += 1
            else:
                stats['clean'] += 1
                logger.info("未发现可疑特征")
                
        except Exception as e:
            logger.error(f"处理文件 {file} 时发生错误: {str(e)}")
            stats['error'] += 1
    
    # 输出统计信息
    logger.info("\n=== 检测统计 ===")
    logger.info(f"总文件数: {stats['total']}")
    logger.info(f"可疑文件: {stats['suspicious']}")
    logger.info(f"正常文件: {stats['clean']}")
    logger.info(f"错误文件: {stats['error']}")

if __name__ == '__main__':
    main()
