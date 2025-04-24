# core/analyzer.py
import re
import os
import json
from pathlib import Path
from typing import Optional, Dict
from loguru import logger

# 如果你使用 OpenAI 等 LLM，可以放在这里
from core.llm_client import analyze_with_llm


class WebShellAnalyzer:
    def __init__(self, cache_dir: str = "analyze_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True, parents=True)

    def analyze(self, file_path: str) -> Dict:
        """
        分析单个 WebShell 文件，返回结构如下：
        {
            "type": "password" / "eval" / "assert" / "custom",
            "param_name": "cmd" / "_" / ...,
            "password": "secret" / null,
            "recommended_commands": ["whoami", "id"]
        }
        """
        file = Path(file_path)
        cache_file = self.cache_dir / (file.stem + ".json")

        if cache_file.exists():
            logger.debug(f"从缓存加载分析结果: {cache_file.name}")
            return json.loads(cache_file.read_text())

        logger.info(f"开始分析WebShell: {file.name}")
        content = file.read_text()
        result = {
            "type": self.detect_shell_type(content),
            "param_name": self.extract_param_name(content),
            "password": self.extract_password(content),
            "recommended_commands": ["whoami", "id", "uname -a"]
        }

        # 使用LLM进一步推理
        try:
            llm_data = analyze_with_llm(content)
            result.update(llm_data)
        except Exception as e:
            logger.warning(f"LLM分析失败: {e}")

        # 保存缓存
        cache_file.write_text(json.dumps(result, indent=2, ensure_ascii=False))
        return result

    def detect_shell_type(self, content: str) -> str:
        if re.search(r'\$_(POST|GET)\[.*?\]', content):
            if 'assert' in content:
                return "assert"
            if 'eval' in content:
                return "eval"
            if 'system' in content or 'exec' in content:
                return "password"
        return "custom"

    def extract_param_name(self, content: str) -> Optional[str]:
        match = re.search(r'\$_(POST|GET)\["?(\w+)"?\]', content)
        if match:
            return match.group(2)
        return None

    def extract_password(self, content: str) -> Optional[str]:
        # 检测是否存在 $_POST['cmd'] == 'xxx'
        match = re.search(r'\$_(POST|GET)\["?(\w+)"?\]\s*==\s*\'?([\w\d]+)\'?', content)
        if match:
            return match.group(3)
        return None
