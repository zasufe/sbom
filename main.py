# main.py
from __future__ import annotations

import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from typing import Final

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.middleware.base import BaseHTTPMiddleware

from src.api.sbom import router as sbom_router
from src.service.utils import BusinessException

# =========================
# 基础配置（可用环境变量覆盖）
# =========================

APP_NAME: Final[str] = os.getenv("APP_NAME", "SBOM Service")
APP_VERSION: Final[str] = os.getenv("APP_VERSION", "1.0.0")
ENV: Final[str] = os.getenv("ENV", "prod")  # dev / prod
LOG_LEVEL: Final[str] = os.getenv("LOG_LEVEL", "INFO").upper()


# =========================
# logging 初始化（标准库，生产稳定）
# =========================

def setup_logging() -> None:
    """
    生产级 logging 初始化：
    - stdout 输出（容器/系统采集友好）
    - 不混用 loguru，避免 uvicorn/fastapi 接管冲突
    """
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(LOG_LEVEL)

    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        fmt="%(asctime)s.%(msecs)03d | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    root.addHandler(handler)

    # 降低 uvicorn.access 噪声时可启用（需要时再打开）
    # logging.getLogger("uvicorn.access").setLevel(logging.INFO)


# =========================
# 中间件：Request-ID + 请求日志
# =========================

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    为每个请求生成 request_id，并记录：
    - 方法/路径/状态码/耗时
    - 异常时记录堆栈
    """
    def __init__(self, app: FastAPI):
        super().__init__(app)
        self.log = logging.getLogger("app.request")

    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        request.state.request_id = rid

        start = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            duration_ms = int((time.perf_counter() - start) * 1000)
            self.log.exception(
                "request_error request_id=%s method=%s path=%s duration_ms=%s",
                rid, request.method, request.url.path, duration_ms,
            )
            raise

        duration_ms = int((time.perf_counter() - start) * 1000)
        self.log.info(
            "request_done request_id=%s method=%s path=%s status=%s duration_ms=%s",
            rid, request.method, request.url.path, response.status_code, duration_ms,
        )

        # 回写 request-id，便于前端/调用方关联日志
        response.headers["X-Request-ID"] = rid
        return response


# =========================
# Lifespan（替代 on_event）
# =========================

@asynccontextmanager
async def lifespan(app: FastAPI):
    log = logging.getLogger("app.lifespan")

    # ✅ 启动阶段（初始化资源、预热、检查依赖）
    log.info("startup env=%s version=%s", ENV, APP_VERSION)

    # 例：你可以在这里做 DB 连接探测 / DX 服务探测
    # await check_db()
    # await check_dx()

    yield

    # ✅ 关闭阶段（释放资源）
    log.info("shutdown complete")


# =========================
# App 工厂
# =========================

def create_app() -> FastAPI:
    setup_logging()
    log = logging.getLogger("app")

    # FastAPI 初始化：生产建议关闭 docs（可按需开启）
    docs_url = "/docs" if ENV != "prod" else None
    redoc_url = "/redoc" if ENV != "prod" else None
    openapi_url = "/openapi.json" if ENV != "prod" else None

    app = FastAPI(
        title=APP_NAME,
        version=APP_VERSION,
        lifespan=lifespan,
        docs_url=docs_url,
        redoc_url=redoc_url,
        openapi_url=openapi_url,
    )

    # 中间件：请求日志 + request_id
    app.add_middleware(RequestLoggingMiddleware)

    # 路由
    app.include_router(sbom_router)

    # =========================
    # 健康检查（k8s/systemd）
    # =========================

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> PlainTextResponse:
        return PlainTextResponse("ok")

    @app.get("/readyz", include_in_schema=False)
    async def readyz() -> PlainTextResponse:
        # 可以扩展为：检查 DB/DX/磁盘空间等
        return PlainTextResponse("ready")

    # =========================
    # 异常处理
    # =========================

    @app.exception_handler(BusinessException)
    async def handle_business_exception(request: Request, exc: BusinessException) -> JSONResponse:
        rid = getattr(request.state, "request_id", "-")
        log.warning(
            "business_error request_id=%s code=%s msg=%s path=%s",
            rid, exc.code, exc.message, request.url.path,
        )

        payload = {"error_code": exc.code, "message": exc.message}
        if exc.data is not None:
            payload["data"] = exc.data
        return JSONResponse(status_code=200, content=payload)

    @app.exception_handler(Exception)
    async def handle_unexpected_exception(request: Request, exc: Exception) -> JSONResponse:
        rid = getattr(request.state, "request_id", "-")
        log.exception(
            "unhandled_error request_id=%s type=%s path=%s",
            rid, type(exc).__name__, request.url.path,
        )
        return JSONResponse(
            status_code=500,
            content={"error_code": "INTERNAL_SERVER_ERROR", "message": "服务内部错误"},
        )

    return app


# uvicorn 入口：兼容 `uvicorn main:app`
app = create_app()


# =========================
# 允许 `python main.py` 直接启动（生产仍推荐 uvicorn CLI）
# =========================

if __name__ == "__main__":
    import uvicorn

    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "5544"))
    workers = int(os.getenv("WORKERS", "1"))

    # ✅ 生产推荐：通过 CLI 启动并交给进程管理器（systemd/docker/k8s）
    # uvicorn main:app --host 0.0.0.0 --port 5544 --workers 2 --proxy-headers --forwarded-allow-ips="*"
    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        workers=workers,
        # 开发调试用
        reload=(ENV == "dev"),
        log_level=LOG_LEVEL.lower(),
        proxy_headers=True,
        forwarded_allow_ips="*",
    )
