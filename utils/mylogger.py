from loguru import logger
from pathlib import Path

def setup_logger(log_dir: str = "logs", level: str = "DEBUG") -> None:
    """Setup logger"""
    Path(log_dir).mkdir(parents=True, exist_ok=True)

    logger.add(
        f"{log_dir}/webshell_test_{{time}}.log",
        rotation="500 MB",
        retention="10 days",
        encoding="utf-8",
        level=level,
        enqueue=True,
        backtrace=True,
        diagnose=True
    )

    logger.debug("Logger initialized")