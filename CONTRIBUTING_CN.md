# 贡献指南

[English](CONTRIBUTING.md) | [中文](CONTRIBUTING_CN.md)

感谢您对 WebShell 测试工具项目感兴趣！本文档提供了参与项目贡献的指南和说明。

## 目录

- [行为准则](#行为准则)
- [如何贡献](#如何贡献)
- [开发环境设置](#开发环境设置)
- [代码风格指南](#代码风格指南)
- [测试指南](#测试指南)
- [Pull Request 流程](#pull-request-流程)
- [文档要求](#文档要求)

## 行为准则

参与本项目即表示您同意遵守我们的[行为准则](CODE_OF_CONDUCT.md)。请尊重他人并保持礼貌。

## 如何贡献

### 问题报告

报告问题时，请包含以下信息：
- 清晰、描述性的标题
- 问题重现步骤
- 预期行为
- 实际行为
- 环境详情（操作系统、Python 版本、Docker 版本）
- 相关日志或错误信息

### 功能请求

提交功能请求时：
- 描述功能及其优势
- 提供使用场景
- 如有可能，建议实现方案

### Pull Requests

1. Fork 项目仓库
2. 为您的功能/修复创建新分支
3. 进行修改
4. 添加测试（如适用）
5. 更新文档
6. 提交 Pull Request

## 开发环境设置

### 系统要求

- Python 3.8+
- Docker 20.10+
- Git
- 虚拟环境（推荐）

### 设置步骤

```bash
# 克隆仓库
git clone https://github.com/yourusername/webshell_tester.git
cd webshell_tester

# 创建并激活虚拟环境
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 安装开发依赖
pip install -r requirements.txt
pip install -r requirements-dev.txt  # 开发工具
```

## 代码风格指南

### Python 代码

- 遵循 [PEP 8](https://www.python.org/dev/peps/pep-0008/) 风格指南
- 适当使用类型注解
- 为所有公共函数和类编写文档字符串
- 保持函数简洁专注
- 使用有意义的变量名

### Docker 配置

- 尽可能使用多阶段构建
- 最小化层数
- 使用特定版本标签
- 记录暴露的端口和卷

## 测试指南

### 单元测试

- 为新功能编写测试
- 保持测试覆盖率
- 使用 pytest 进行测试
- 模拟外部依赖

### 集成测试

- 测试 WebShell 功能
- 验证环境设置
- 测试容器交互

### 运行测试

```bash
# 运行所有测试
pytest

# 运行特定测试文件
pytest tests/test_environment.py

# 运行带覆盖率的测试
pytest --cov=core tests/
```

## Pull Request 流程

1. 确保代码通过所有测试
2. 必要时更新文档
3. 提供清晰的提交信息
4. 引用相关 issue
5. 等待审查并处理反馈

### 提交信息格式

```
<类型>(<范围>): <描述>

[可选正文]

[可选页脚]
```

类型：
- feat: 新功能
- fix: 错误修复
- docs: 文档更改
- style: 代码风格更改
- refactor: 代码重构
- test: 测试相关更改
- chore: 维护任务

## 文档要求

### 代码文档

- 使用 Google 风格的文档字符串
- 记录复杂算法
- 解释非显而易见的代码

### 用户文档

- 为新功能更新 README.md
- 添加使用示例
- 记录配置选项

## 获取帮助

- 查看现有 issue
- 加入社区讨论
- 联系维护者

## 许可证

通过贡献代码，您同意您的贡献将根据项目的 [MIT 许可证](LICENSE) 进行授权。 