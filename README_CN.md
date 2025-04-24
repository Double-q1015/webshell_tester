# WebShell 测试工具

[English](README.md) | [中文](README_CN.md)

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-20.10%2B-blue.svg)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen.svg)]()

一个全面的 WebShell 自动化测试框架，用于分析和验证 WebShell。

## 项目概述

WebShell 测试工具是一个强大的测试框架，专为安全研究人员和开发人员设计，用于自动化测试和验证各种 Web 环境中的 WebShell。它提供了一种标准化的方法来测试 WebShell 的功能、可检测性和在不同 Web 服务器配置中的行为。

## 主要功能

### 环境管理
- 🐳 基于 Docker 的环境隔离
- 🔄 多种 Web 服务器配置
- ⚡ 快速环境部署和清理
- 🔒 安全的容器网络

### 测试能力
- 🎯 自动化 WebShell 部署
- 🔄 并发测试执行
- 📊 全面的结果分析
- 🛡️ 安全日志监控

### 支持的环境
- PHP 7.4 + Apache
- Tomcat 9
- Python Flask
- Node.js Express
- Spring Boot
- *更多环境即将支持*

## 快速开始

### 系统要求
- Python 3.10+
- Docker 20.10+
- pip

### 安装步骤
```bash
# 克隆仓库
git clone https://github.com/yourusername/webshell_tester.git
cd webshell_tester

# conda 创建环境
conda create --name webshell_tester python=3.10

# conda 切换环境
conda activate webshell_tester 

# 安装依赖
pip install -r requirements.txt
```

### 基本用法
```bash
# 列出可用环境
python tools/prebuild_images.py list

# 构建特定环境
python tools/prebuild_images.py build --env php7.4_apache

# 运行测试
python main.py --env php7.4_apache --shell test1.php
```

## 项目结构
```
webshell_tester/
├── docker_templates/    # Docker 环境模板
├── shells/             # WebShell 样本
├── core/               # 核心功能
├── tools/              # 工具脚本
├── utils/              # 工具函数
├── tests/              # 测试用例
└── main.py            # 主程序入口
```

## 高级功能

### 环境配置
* php环境1
```yaml
environment:
  name: php7.4_apache
  server: apache
  version: 2.4
  php_version: 7.4
  ports:
    - 8080:80
```

### 测试用例管理
```yaml
testcase:
  name: "PHP WebShell 测试"
  shell:
    type: "php"
    file: "test1.php"
  commands:
    - "whoami"
    - "pwd"
    - "ls -la"
```

## 检测技术

### 概述
本项目支持多种 WebShell 检测技术：

| 技术 | 描述 | 示例 |
|------|------|------|
| 沙箱 | 隔离环境中的动态分析 | 百度 Webdir |
| RASP | 运行时应用自我保护 | 百度 OpenRASP |
| 静态分析-正则 | 基于模式匹配的检测 | Shell-Detector |
| 静态分析-统计学 | 代码特征的统计分析 | 基于机器学习的检测器 |
| 静态分析-AST | 抽象语法树分析 | PHP-Parser |
| 机器学习 | 基于 AI 的检测 | 多种机器学习模型 |

### 相关项目
以下是 WebShell 检测领域的一些重要开源项目：

| 项目 | 描述 | 状态 |
|------|------|------|
| [CloudWalker](https://github.com/chaitin/cloudwalker) | 全面的检测解决方案 | 活跃 |
| [PHP-Malware-Finder](https://github.com/jvoisin/php-malware-finder) | PHP 恶意软件的 YARA 规则检测 | 活跃 |
| [MLCheckWebshell](https://github.com/hi-WenR0/MLCheckWebshell) | 基于朴素贝叶斯的检测 | 活跃 |
| [WebShell-Detect-By-ML](https://github.com/lcatro/WebShell-Detect-By-Machine-Learning) | 自定义贝叶斯算法实现 | 活跃 |
| [Shell-Detector](https://github.com/emposha/Shell-Detector) | 基于正则表达式的检测 | 活跃 |
| [PHP-Parser](https://github.com/nikic/PHP-Parser) | 基于 AST 的分析 | 活跃 |

### 理论资源
对于对 WebShell 检测理论感兴趣的读者：

- [基于 AST 的 WebShell 检测](https://xz.aliyun.com/t/5848)
- [PHP WebShell 攻击技术](https://mp.weixin.qq.com/s/FgzIm-IK02rjEf3JvxOxrw)
- [WebShell 检测能力进化笔记](https://zhuanlan.zhihu.com/p/135268144)
- [污点分析在 WebShell 检测中的应用](https://zhuanlan.zhihu.com/p/197553954)
- [云安全环境下恶意脚本检测的最佳实践](http://yundunpr.oss-cn-hangzhou.aliyuncs.com/2020/xcon2020.pdf)

## 贡献指南

欢迎贡献代码！请查看我们的[贡献指南](CONTRIBUTING.md)了解详情。

## 安全说明

- 所有容器在隔离的 Docker 网络中运行
- WebShell 执行限制在特定命令范围内
- 定期进行安全审计和更新

## 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件。

## 致谢

- Docker 社区
- Python 安全社区
- 开源贡献者

## 开发路线图

### 环境支持
- [ ] 高优先级：
  - PHP 7.4 + Apache/Nginx（最稳定且使用最广泛）
- [ ] 中优先级：
  - PHP 8.1 + Apache/Nginx（现代应用）
- [ ] 低优先级：
  - PHP 7.2/7.3 + Apache/Nginx（遗留系统）
  - PHP 5.6 + Apache（非常老的系统）

### 功能增强
- [ ] 增强报告系统
- [ ] Web 管理界面
- [ ] CI/CD 集成
- [ ] 性能优化

## 技术支持

如需技术支持，请在 GitHub 仓库中提交 issue 或联系维护者。

## 标签

#安全 #webshell #测试 #自动化 #docker #python #网络安全 #渗透测试 #devsecops 