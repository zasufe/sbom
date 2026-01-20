from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from src.api.sbom import router as sbom_router
from src.service.utils import BusinessException


def create_app() -> FastAPI:
    app = FastAPI(title='SBOM Service', version='1.0.0')

    app.include_router(sbom_router)

    @app.exception_handler(BusinessException)
    async def handle_business_exception(request: Request, exc: BusinessException):
        payload = {'error_code': exc.code, 'message': exc.message}
        if exc.data is not None:
            payload['data'] = exc.data
        return JSONResponse(status_code=200, content=payload)

    return app


app = create_app()
