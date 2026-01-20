# -*- coding: utf-8 -*-
"""SBOM request/response schemas."""

from __future__ import annotations

from typing import Callable, Any, Optional, Type

from pydantic import BaseModel, Field

from src.service.utils import PaginationReq, PaginationRes

from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import Row, select, func


class AddSbomProjectArgs(BaseModel):
    project_name: str = Field(title='项目名称')
    project_desc: str = Field(title='项目描述')
    code_language: str = Field(title='代码语言')


class AddSbomProjectReturn(BaseModel):
    project_id: int = Field(title='项目id')
    dx_uuid: str = Field(title='dx uuid')


class DeleteSbomProjectArgs(BaseModel):
    project_id: int = Field(title='项目id')


class UpdateSbomProjectArgs(BaseModel):
    project_name: str = Field(title='项目名称')
    project_desc: str = Field(title='项目描述')
    project_id: int = Field(title='项目id')


class GetComponentsArgs(PaginationReq):
    dx_uuid: str = Field(title='dx uuid')
    search_text: str | None = Field(default=None, title='组件名称')


class GetVulnerabilitiesArgs(BaseModel):
    dx_uuid: str = Field(title='dx uuid')
    search_text: str | None = Field(default=None, title='漏洞名称')


class GetCountArgs(BaseModel):
    dx_uuid: str = Field(title='dx uuid')


class ProjectInfo(BaseModel):
    project_name: str = Field(title='项目名称')
    project_desc: str = Field(title='项目描述')
    code_language: str = Field(title='代码语言')
    status: int = Field(title='项目状态')


class GetChildGraph(BaseModel):
    graph_uuid: str = Field(title='组件uuid')


class GetVulnerabilitiesDetails(BaseModel):
    vuln_id: str = Field(title='漏洞id')


class SelectSbomProjectArgs(PaginationReq):
    project_name: str | None = Field(default=None, title='项目名称')
    code_language: str | None = Field(default=None, title='语言')


class SelectSbomProjectReturn(PaginationRes):
    """继承并重写分页响应体 ..."""

    tabledata: Optional[list[Any]] = Field(title='表格数据', default=[])

    class Config:
        json_schema_extra = {
            'example': {
                'page': 1,
                'page_size': 10,
                'total': 500,
                'total_page': 50,
                'tabledata': []
            }
        }

    @classmethod
    async def build_res_with_sql_query(
            cls,
            pagination_req: PaginationReq,
            query: Any,
            sess: AsyncSession,
            handle: dict[str, Callable[[Any], Any]] = None,
    ) -> "PaginationRes":
        total_stmt = select(func.count()).select_from(query.subquery())
        total = (await sess.execute(total_stmt)).scalar_one()
        base_result = super().from_req(pagination_req, total)

        if total == 0:
            data = []
        else:
            data = (
                await sess.execute(
                    query.limit(pagination_req.page_size).offset((pagination_req.page - 1) * pagination_req.page_size)
                )
            ).all()

        base_result.tabledata = query_results_format(data, handle=handle)
        return cls(**base_result.model_dump())


def query_results_format(
    objs: list[Row | Type[DeclarativeBase]],
    keys: list[str] = None,
    key_alias: dict = None,
    handle: dict[str, Callable[[Any], Any]] = None,
) -> list[dict[str, Any]]:
    return [query_result_format(obj, keys, key_alias, handle) for obj in objs]


def query_result_format(
    obj: Row | Type[DeclarativeBase],
    keys: list[str] = None,
    key_alias: dict = None,
    handle: dict[str, Callable] = None,
) -> dict[str, Any]:
    if isinstance(obj, Row):
        data = dict(obj._mapping)
    else:
        data = obj.__dict__
        data.pop('_sa_instance_state', None)
    if keys is not None:
        data = {k: data[k] for k in keys}
    if handle is not None:
        for k, v in handle.items():
            if k in data:
                data[k] = v(data[k])
    if key_alias is not None:
        data = {key_alias.get(k, k): v for k, v in data.items()}
    return data
