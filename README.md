# WebShell Tester

[English](README.md) | [中文](README_CN.md)

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-20.10%2B-blue.svg)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen.svg)]()

A comprehensive automated testing framework for WebShell analysis and validation.

## Overview

WebShell Tester is a robust testing framework designed for security researchers and developers to automate the testing and validation of WebShells across various web environments. It provides a standardized approach to test WebShell functionality, detectability, and behavior in different web server configurations.

## Features

### Environment Management
- 🐳 Docker-based environment isolation
- 🔄 Multiple web server configurations
- ⚡ Quick environment deployment and teardown
- 🔒 Secure container networking

### Testing Capabilities
- 🎯 Automated WebShell deployment
- 🔄 Concurrent test execution
- 📊 Comprehensive result analysis
- 🛡️ Security log monitoring

### Supported Environments
- PHP 7.4 + Apache
- Tomcat 9
- Python Flask
- Node.js Express
- Spring Boot
- *More environments coming soon*

## Quick Start

### Prerequisites
- Python 3.10+
- Docker 20.10+
- pip

### Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/webshell_tester.git
cd webshell_tester

# create conda env
conda create --name webshell_tester python=3.10

# 
conda activate webshell_tester 

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage
```bash
# List available environments
python tools/prebuild_images.py list

# Build a specific environment
python tools/prebuild_images.py build --env php7.4_apache

# Run tests
python main.py --env php7.4_apache --shell test1.php
```

## Project Structure
```
webshell_tester/
├── docker_templates/    # Docker environment templates
├── shells/             # WebShell samples
├── core/               # Core functionality
├── tools/              # Utility scripts
├── utils/              # Helper functions
├── tests/              # Test cases
└── main.py            # Main entry point
```

## Advanced Features

### Environment Configuration
```yaml
environment:
  name: php7.4_apache
  server: apache
  version: 2.4
  php_version: 7.4
  ports:
    - 8080:80
```

### Test Case Management
```yaml
testcase:
  name: "PHP WebShell Test"
  shell:
    type: "php"
    file: "test1.php"
  commands:
    - "whoami"
    - "pwd"
    - "ls -la"
```

## Detection Techniques

### Overview
This project supports various WebShell detection techniques:

| Technique | Description | Example |
|-----------|-------------|---------|
| Sandbox | Dynamic analysis in isolated environment | Baidu Webdir |
| RASP | Runtime Application Self-Protection | Baidu OpenRASP |
| Static Analysis - Regex | Pattern matching based detection | Shell-Detector |
| Static Analysis - Statistical | Statistical analysis of code features | ML-based detectors |
| Static Analysis - AST | Abstract Syntax Tree analysis | PHP-Parser |
| Machine Learning | AI-based detection | Various ML models |

### Related Projects
Here are some notable open-source projects in the WebShell detection field:

| Project | Description | Status |
|---------|-------------|--------|
| [CloudWalker](https://github.com/chaitin/cloudwalker) | Comprehensive detection solution | Active |
| [PHP-Malware-Finder](https://github.com/jvoisin/php-malware-finder) | YARA rules for PHP malware detection | Active |
| [MLCheckWebshell](https://github.com/hi-WenR0/MLCheckWebshell) | Naive Bayes based detection | Active |
| [WebShell-Detect-By-ML](https://github.com/lcatro/WebShell-Detect-By-Machine-Learning) | Custom Bayesian algorithm implementation | Active |
| [Shell-Detector](https://github.com/emposha/Shell-Detector) | Regex-based detection | Active |
| [PHP-Parser](https://github.com/nikic/PHP-Parser) | AST-based analysis | Active |

### Theoretical Resources
For those interested in the theoretical aspects of WebShell detection:

- [AST-based Webshell Detection](https://xz.aliyun.com/t/5848)
- [PHP Webshell Attack Techniques](https://mp.weixin.qq.com/s/FgzIm-IK02rjEf3JvxOxrw)
- [Webshell Detection Evolution](https://zhuanlan.zhihu.com/p/135268144)
- [Taint Analysis in Webshell Detection](https://zhuanlan.zhihu.com/p/197553954)
- [Best Practices in Malicious Script Detection](http://yundunpr.oss-cn-hangzhou.aliyuncs.com/2020/xcon2020.pdf)

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

## Security

- All containers run in isolated Docker networks
- WebShell execution is restricted to specific commands
- Regular security audits and updates

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Docker Community
- Python Security Community
- Open Source Contributors

## Roadmap

### Environment Support
- [ ] High Priority:
  - PHP 7.4 + Apache/Nginx (Most stable and widely used)
- [ ] Medium Priority:
  - PHP 8.1 + Apache/Nginx (Modern applications)
- [ ] Lower Priority:
  - PHP 7.2/7.3 + Apache/Nginx (Legacy systems)
  - PHP 5.6 + Apache (Very old systems)

### Feature Enhancements
- [ ] Enhanced Reporting System
- [ ] Web Management Interface
- [ ] CI/CD Integration
- [ ] Performance Optimization

## Support

For support, please open an issue in the GitHub repository or contact the maintainers.

## Tags

#security #webshell #testing #automation #docker #python #cybersecurity #pentesting #devsecops 