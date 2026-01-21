# src/core/logging.py
from __future__ import annotations

import datetime as _dt
import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

LOG_DIR = Path("logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)

SYSTEM_LOG = LOG_DIR / "sbom-system.log"
UVICORN_LOG = LOG_DIR / "sbom-uvicorn.log"

# 生产建议：INFO；排障时临时改 DEBUG
LOG_LEVEL = logging.INFO


class CustomFileFormatter(logging.Formatter):
    """文件日志格式（无颜色，便于检索/采集）"""

    def format(self, record: logging.LogRecord) -> str:
        ts = _dt.datetime.fromtimestamp(record.created).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        level = record.levelname

        # 统一结构：时间 | level | logger | message
        msg = f"{ts} | {level:<8} | {record.name} | {record.getMessage().strip()}"

        if record.exc_info:
            msg = f"{msg}; {repr(record.exc_info[1])}"
        return msg


class CustomStdoutFormatter(logging.Formatter):
    """控制台日志格式（带颜色，便于人读）"""

    def format(self, record: logging.LogRecord) -> str:
        ts = _dt.datetime.fromtimestamp(record.created).strftime("%H:%M:%S.%f")[:-3]

        # 颜色
        if record.levelno >= logging.CRITICAL:
            tag = "\033[1;48;5;196;38;5;15mCRIT\033[0m"
            text = "\033[1;48;5;196;38;5;15m"
        elif record.levelno >= logging.ERROR:
            tag = "\033[38;5;196mERR \033[0m"
            text = "\033[38;5;196m"
        elif record.levelno >= logging.WARNING:
            tag = "\033[38;5;214mWARN\033[0m"
            text = "\033[4m"
        elif record.levelno >= logging.INFO:
            tag = "\033[38;5;39mINFO\033[0m"
            text = "\033[0m"
        else:
            tag = "\033[38;5;93mDBG \033[0m"
            text = "\033[3;38;5;240m"

        base = f"\033[38;5;240m[{ts}]\033[0m {tag} \033[38;5;245m{record.name}\033[0m {text}{record.getMessage().strip()}"
        if record.exc_info:
            base = f"{base}; {repr(record.exc_info[1])}\033[0m\n{self.formatException(record.exc_info)}"
        return base + "\033[0m"


def _build_stdout_handler(level: int) -> logging.Handler:
    h = logging.StreamHandler(sys.stdout)
    h.setLevel(level)
    h.setFormatter(CustomStdoutFormatter())
    return h


def _build_file_handler(filename: Path, level: int) -> logging.Handler:
    filename.parent.mkdir(parents=True, exist_ok=True)
    h = RotatingFileHandler(
        filename,
        encoding="utf-8",
        maxBytes=8 * 1024 * 1024,  # 8MiB
        backupCount=8,
    )
    h.setLevel(level)
    h.setFormatter(CustomFileFormatter())
    return h


def setup_logging() -> None:
    """
    全局 logging 初始化（生产级）：
    - root logger：stdout + system file
    - 分域 logger：sbom / exec / httpx / uvicorn.*
    - 避免重复 handler：每次初始化先清空 handlers
    """
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(LOG_LEVEL)

    root.addHandler(_build_stdout_handler(LOG_LEVEL))
    root.addHandler(_build_file_handler(SYSTEM_LOG, LOG_LEVEL))

    # 你自己的业务域
    for name in ("sbom", "exec"):
        lg = logging.getLogger(name)
        lg.handlers.clear()
        lg.setLevel(LOG_LEVEL)
        lg.propagate = True  # 交给 root 统一输出

    # 第三方库：一般只要 INFO
    httpx_logger = logging.getLogger("httpx")
    httpx_logger.setLevel(logging.INFO)
    httpx_logger.propagate = True

    # uvicorn 由 log_config 控制；这里只保证不要多余 handlers
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        lg = logging.getLogger(name)
        lg.handlers.clear()
        lg.propagate = True


def build_uvicorn_logging_config() -> dict[str, Any]:
    """
    给 uvicorn.run / uvicorn CLI 的 log_config 使用。
    注意：这里用标准 logging config dictConfig 规范。
    """
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "stdout": {"()": CustomStdoutFormatter},
            "file": {"()": CustomFileFormatter},
        },
        "handlers": {
            "stdout": {
                "class": "logging.StreamHandler",
                "formatter": "stdout",
                "stream": "ext://sys.stdout",
                "level": "INFO",
            },
            "file": {
                "class": "logging.handlers.RotatingFileHandler",
                "formatter": "file",
                "filename": str(UVICORN_LOG),
                "encoding": "utf-8",
                "maxBytes": 8 * 1024 * 1024,
                "backupCount": 8,
                "level": "INFO",
            },
        },
        "loggers": {
            # uvicorn 主日志
            "uvicorn": {"handlers": ["stdout", "file"], "level": "INFO", "propagate": False},
            "uvicorn.error": {"handlers": ["stdout", "file"], "level": "INFO", "propagate": False},
            "uvicorn.access": {"handlers": ["stdout", "file"], "level": "INFO", "propagate": False},
        },
    }
