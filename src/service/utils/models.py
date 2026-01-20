"""
 * Copyright (c) 2022 FengTaiSEC Corporation.
 * @brief      请求、响应模型 (FastAPI compatibility version)
"""

from __future__ import annotations

import math
import traceback
from typing import Type, Any, TypeVar, Generic

import jsonref
from pydantic import BaseModel, Field
from starlette.responses import JSONResponse, Response


def mk_resp(message: str = 'success', data: Any = None, error_code: int = 0) -> Response:
    """Generate a JSON response compatible with the existing protocol.

    Protocol:
      - success:  {"code": 0, "message": "...", "data": ...}
      - failed:   {"code": nonzero, "message": "...", "data": ...}

    We keep HTTP status_code=200 to match the Flask behavior.
    """
    result = {'error_code': error_code, 'message': message}
    if data is not None:
        result.update({'data': data})
    return JSONResponse(status_code=200, content=result)


def model_json_schema_flat(model: Type[BaseModel]) -> dict:
    return jsonref.replace_refs(model.model_json_schema())


class PaginationReq(BaseModel):
    """分页请求体"""
    page: int = Field(1, title='页码', ge=1, le=2 ** 32, examples=[1, 2])
    page_size: int = Field(10, title='每页数量', ge=1, le=50, examples=[10, 15, 50])


class PaginationRes(BaseModel):
    """分页响应体"""
    page: int = Field(title='页码')
    page_size: int = Field(title='每页数量')
    total: int = Field(title='总条数')
    total_page: int = Field(title='总页数')

    class Config:
        json_schema_extra = {
            'example': {
                'page': 1,
                'page_size': 10,
                'total': 500,
                'total_page': 50,
            }
        }

    @classmethod
    def from_req(cls, pagination_req: PaginationReq, total: int) -> 'PaginationRes':
        total_page = math.ceil(total / pagination_req.page_size) if pagination_req.page_size else 0
        return cls(page=pagination_req.page, page_size=pagination_req.page_size, total=total, total_page=total_page)


DataT = TypeVar('DataT')


class BaseResponseModel(BaseModel, Generic[DataT]):
    """基本响应模型"""
    error_code: int = Field(title='状态码', description='0为成功，其他为失败')
    message: str = Field(title='消息', description='成功或失败的消息')
    data: DataT = Field(title='数据')

    @classmethod
    def success(cls, message: str = '成功', data: DataT = None) -> 'BaseResponseModel[DataT]':
        return cls(error_code=0, message=message, data=data)

    @classmethod
    def failed(cls, message: str = '失败', data: DataT = None, error_code: int = -1) -> 'BaseResponseModel[DataT]':
        return cls(error_code=error_code, message=message, data=data)

    def resp(self) -> Response:
        return JSONResponse(status_code=200, content=self.model_dump(mode='json'))

    @classmethod
    def model_json_schema_flat(cls) -> dict:
        return model_json_schema_flat(cls)


class BaseResponseWithPaginationModel(BaseModel, Generic[DataT]):
    """分页响应模型"""
    error_code: int = Field(title='状态码', description='0为成功，其他为失败')
    message: str = Field(title='消息', description='成功或失败的消息')
    data: list[DataT] = Field(title='数据')
    pagination: PaginationRes = Field(title='分页信息')

    @classmethod
    def success(
        cls, message: str = '成功', data: list[DataT] = None, pagination: PaginationRes = None
    ) -> 'BaseResponseWithPaginationModel':
                return cls(error_code=0, message=message, data=data, pagination=pagination)

    @classmethod
    def failed(
        cls, message: str = '失败', data: list[DataT] = None, pagination: PaginationRes = None, error_code: int = -1
    ) -> 'BaseResponseWithPaginationModel':
        if data is None:
            data = []
        if pagination is None:
            pagination = PaginationRes(page=1, page_size=10, total=0, total_page=0)
        return cls(error_code=error_code, message=message, data=data, pagination=pagination)

    def resp(self) -> Response:
        return JSONResponse(status_code=200, content=self.model_dump(mode='json'))

    @classmethod
    def model_json_schema_flat(cls) -> dict:
        return model_json_schema_flat(cls)


class BaseResponseNoDataModel(BaseModel):
    """无数据响应模型"""
    error_code: int = Field(title='状态码', description='0为成功，其他为失败')
    message: str = Field(title='消息', description='成功或失败的消息')

    @classmethod
    def success(cls, message: str = '成功') -> 'BaseResponseNoDataModel':
        return cls(error_code=0, message=message)

    @classmethod
    def failed(cls, message: str = '失败', error_code: int = -1) -> 'BaseResponseNoDataModel':
        return cls(error_code=error_code, message=message)

    def resp(self) -> Response:
        return JSONResponse(status_code=200, content=self.model_dump(mode='json'))


class BarChatData(BaseModel):
    """柱状图数据"""
    name: str = Field(title='数据列')
    value: list[int | float] = Field(title='值')


class BarChat(BaseModel):
    """柱状图数据"""
    x_data: list[str] = Field(title='x轴数据')
    data: list[BarChatData] = Field(title='数据')

    @classmethod
    def from_data(cls, data: dict[str, int | float], x_title: str = '数值') -> "BarChat":
        x_data = list(data.keys())
        series = [BarChatData(name=x_title, value=[v]) for v in data.values()]
        return cls(x_data=x_data, data=series)

    @classmethod
    def from_datas(cls, data: dict[str, list[int | float]], x_titles: list[str] = None) -> "BarChat":
        x_data = list(data.keys())
        try:
            series = [BarChatData(name=x_titles[i], value=v) for i, v in enumerate(data.values())]
        except IndexError as e:
            raise ValueError('x_titles长度与数据列数不匹配') from e
        return cls(x_data=x_data, data=series)


class BusinessException(Exception):
    """业务层异常"""

    def __init__(self, message: str, error_code: int = -1, data=None):
        self.error_code = error_code
        self.message = message
        self.data = data
        self.tb: list[traceback.FrameSummary] = traceback.extract_stack()[:-1]

    def __str__(self) -> str:
        return self.message

    def __repr__(self) -> str:
        lt = self.tb[-1]
        if self.data is None:
            return f'<HttpError code={self.code} message="{self.message}" file="{lt.filename}" line={lt.lineno} {lt.name}>'
        return f'<HttpError code={self.code} message="{self.message}" data={repr(self.data)} file="{lt.filename}" line={lt.lineno} {lt.name}>'

    def resp(self) -> Response:
        return mk_resp(message=self.message, error_code=self.error_code, data=self.data)

    @classmethod
    def not_login(cls) -> "BusinessException":
        traceback.print_exc()
        return cls('未登录', error_code=2000)

    @classmethod
    def no_permission(cls) -> "BusinessException":
        return cls('无权限', error_code=2001)
