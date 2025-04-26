# WebShell Tester

[English](README.md) | [中文](README_CN.md)

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-20.10%2B-blue.svg)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen.svg)]()

A comprehensive WebShell automation testing framework for analyzing and validating WebShells.

## Project Overview

WebShell Tester is a powerful testing framework designed for security researchers and developers to automate testing and validation of WebShells in various web environments. It provides a standardized approach to test WebShell functionality, detectability, and behavior across different web server configurations. It makes it easy to deploy webshells to specified environments for learning and testing purposes.

## Key Features

### Environment Management
- 🐳 Docker-based environment isolation
- 🔄 Multiple web server configurations
- ⚡ Quick environment deployment and cleanup
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

### System Requirements
- Python 3.10+
- Docker 20.10+
- pip

### Installation Steps
```bash
# Clone repository
git clone https://github.com/yourusername/webshell_tester.git
cd webshell_tester

# Create conda environment
conda create --name webshell_tester python=3.10

# Activate conda environment
conda activate webshell_tester 

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage
1 prebuild_images script usage
```bash
# List available environments
python tools/prebuild_images.py list

# Build specific environment
python tools/prebuild_images.py build --env php7.4_apache
```

2 Main program usage
```bash
# Prebuild environment
python main.py prebuild --env php7.4_apache

# Run tests
python main.py test --env php7.4_apache --shell test1.php

# Deploy WebShell
python main.py deploy --env php7.4_apache --shell test1.php

# View help
python main.py --help
```

3 Command line parameters
```bash
usage: main.py [-h] {prebuild,test,deploy} ...

WebShell automation test tool

positional arguments:
  {prebuild,test,deploy}
                        Main commands
    prebuild           Prebuild Docker environment
    test               Run WebShell tests
    deploy             Deploy WebShell to environment

options:
  -h, --help           Show help message

test command parameters:
  --env ENV            Specify test environment
  --shell SHELL        Specify WebShell file
```

## Project Structure
```
webshell_tester/
├── docker_templates/    # Docker environment templates and configurations
├── shells/             # WebShell sample collection and templates
├── core/               # Core functionality and business logic
├── tools/              # Utility scripts and helper tools
├── utils/              # Common utility functions and libraries
├── tests/              # Test cases and test data
└── main.py            # Main program entry point
```

### Directory Description
- `docker_templates/`: Contains Dockerfile templates and environment configurations for different web server setups
- `shells/`: Stores various WebShell samples categorized by language and type
- `core/`: Implements the main business logic including environment management and testing framework
- `tools/`: Contains utility scripts for environment setup, testing, and analysis
- `utils/`: Provides common utility functions used across the project
- `tests/`: Includes test cases, test data, and test configurations
- `main.py`: The entry point of the application, handling command-line interface and main workflow

## Detection Techniques

### Overview
Some WebShell detection techniques:

| Technique | Description | Example |
|-----------|-------------|---------|
| Sandbox | Dynamic analysis in isolated environment | Baidu Webdir |
| RASP | Runtime Application Self-Protection | Baidu OpenRASP |
| Static Analysis-Regex | Pattern matching based detection | Shell-Detector |
| Static Analysis-Statistics | Statistical analysis of code features | ML-based detectors |
| Static Analysis-AST | Abstract Syntax Tree analysis | PHP-Parser |
| Machine Learning | AI-based detection | Various ML models |

### Related Projects
Here are some important open-source projects in WebShell detection:

| Project | Description | Status |
|---------|-------------|--------|
| [CloudWalker](https://github.com/chaitin/cloudwalker) | Comprehensive detection solution | Active |
| [PHP-Malware-Finder](https://github.com/jvoisin/php-malware-finder) | YARA rules for PHP malware | Active |
| [MLCheckWebshell](https://github.com/hi-WenR0/MLCheckWebshell) | Naive Bayes based detection | Active |
| [WebShell-Detect-By-ML](https://github.com/lcatro/WebShell-Detect-By-Machine-Learning) | Custom Bayesian algorithm implementation | Active |
| [Shell-Detector](https://github.com/emposha/Shell-Detector) | Regex-based detection | Active |
| [PHP-Parser](https://github.com/nikic/PHP-Parser) | AST-based analysis | Active |

### Theoretical Resources
For readers interested in WebShell detection theory:

- [AST-based WebShell Detection](https://xz.aliyun.com/t/5848)
- [PHP WebShell Attack Techniques](https://mp.weixin.qq.com/s/FgzIm-IK02rjEf3JvxOxrw)
- [WebShell Detection Capability Evolution Notes](https://zhuanlan.zhihu.com/p/135268144)
- [Application of Taint Analysis in WebShell Detection](https://zhuanlan.zhihu.com/p/197553954)
- [Best Practices for Malicious Script Detection in Cloud Security](http://yundunpr.oss-cn-hangzhou.aliyuncs.com/2020/xcon2020.pdf)

## Contributing

Welcome to contribute! Please check our [Contributing Guide](CONTRIBUTING.md) for details.

## Security Notes

- All containers run in isolated Docker networks
- WebShell execution is limited to specific command ranges
- Regular security audits and updates

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Docker Community
- Python Security Community
- Open Source Contributors

## Development Roadmap

### Environment Support
- [ ] High Priority:
  - PHP 7.4 + Apache/Nginx (Most stable and widely used)
- [ ] Medium Priority:
  - PHP 8.1 + Apache/Nginx (Modern applications)
- [ ] Low Priority:
  - PHP 7.2/7.3 + Apache/Nginx (Legacy systems)
  - PHP 5.6 + Apache (Very old systems)

### Feature Enhancements
- [ ] Enhanced reporting system
- [ ] Web management interface
- [ ] CI/CD integration
- [ ] Performance optimization

## Technical Support

For technical support, please submit an issue in the GitHub repository or contact the maintainers.

## Tags

#security #webshell #testing #automation #docker #python #cybersecurity #pentesting #devsecops 