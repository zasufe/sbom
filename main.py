from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from loguru import logger

from src.api.sbom import router as sbom_router
from src.service.utils import BusinessException


# =========================
# 日志配置（生产级）
# =========================

LOG_LEVEL = "INFO"
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

LOG_FILE = LOG_DIR / "sbom-service.log"


def setup_logging() -> None:
    """
    统一日志初始化。
    - 使用 loguru 作为核心日志引擎
    - 接管标准 logging（uvicorn / fastapi 内部日志）
    - 输出：控制台 + 文件（可轮转）
    - 结构化字段：timestamp / level / module / function / line
    """

    # 移除 loguru 默认 handler
    logger.remove()

    # 控制台输出（开发 / 容器 stdout）
    logger.add(
        sys.stdout,
        level=LOG_LEVEL,
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
            "<level>{level: <8}</level> | "
            "{name}:{function}:{line} - {message}"
        ),
        enqueue=True,
        backtrace=False,
        diagnose=False,
    )

    # 文件输出（生产持久化）
    logger.add(
        LOG_FILE,
        level=LOG_LEVEL,
        rotation="10 MB",          # 单文件 10MB 自动切分
        retention="7 days",        # 保留 7 天
        compression="zip",         # 压缩历史日志
        enqueue=True,
        backtrace=False,
        diagnose=False,
        format=(
            "{time:YYYY-MM-DD HH:mm:ss.SSS} | "
            "{level: <8} | "
            "{name}:{function}:{line} | "
            "{message}"
        ),
    )

    # 接管标准 logging（让 uvicorn / fastapi 的日志也走 loguru）
    class InterceptHandler(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            try:
                level = logger.level(record.levelname).name
            except ValueError:
                level = record.levelno

            frame, depth = logging.currentframe(), 2
            while frame and frame.f_code.co_filename == logging.__file__:
                frame = frame.f_back
                depth += 1

            logger.opt(depth=depth, exception=record.exc_info).log(
                level, record.getMessage()
            )

    logging.basicConfig(handlers=[InterceptHandler()], level=LOG_LEVEL, force=True)

    # 明确 uvicorn / fastapi 日志级别
    for _logger in ("uvicorn", "uvicorn.error", "uvicorn.access", "fastapi"):
        logging.getLogger(_logger).handlers = [InterceptHandler()]
        logging.getLogger(_logger).setLevel(LOG_LEVEL)


# =========================
# FastAPI 应用工厂
# =========================

def create_app() -> FastAPI:
    """
    FastAPI 应用工厂（官方推荐模式）
    """
    setup_logging()

    app = FastAPI(
        title="SBOM Service",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    # 路由注册
    app.include_router(sbom_router)

    # =========================
    # 生命周期事件（官方推荐）
    # =========================

    @app.on_event("startup")
    async def on_startup() -> None:
        logger.info("SBOM Service 启动完成")

    @app.on_event("shutdown")
    async def on_shutdown() -> None:
        logger.info("SBOM Service 已关闭")

    # =========================
    # 统一异常处理
    # =========================

    @app.exception_handler(BusinessException)
    async def handle_business_exception(
        request: Request,
        exc: BusinessException,
    ) -> JSONResponse:
        logger.warning(
            "业务异常",
            extra={
                "path": request.url.path,
                "method": request.method,
                "error_code": exc.code,
                "message": exc.message,
                "data": exc.data,
            },
        )

        payload: dict[str, Any] = {
            "error_code": exc.code,
            "message": exc.message,
        }
        if exc.data is not None:
            payload["data"] = exc.data

        return JSONResponse(status_code=200, content=payload)

    @app.exception_handler(Exception)
    async def handle_unexpected_exception(
        request: Request,
        exc: Exception,
    ) -> JSONResponse:
        logger.exception(
            "未捕获异常",
            extra={
                "path": request.url.path,
                "method": request.method,
                "error_type": type(exc).__name__,
            },
        )

        return JSONResponse(
            status_code=500,
            content={
                "error_code": "INTERNAL_SERVER_ERROR",
                "message": "服务内部错误，请联系管理员",
            },
        )

    return app


# =========================
# ASGI 入口
# =========================

app = create_app()
