# src/api/sbom.py
from __future__ import annotations

import asyncio
import os
from pathlib import Path
from uuid import uuid4

import aiofiles
from fastapi import APIRouter, Depends, File, Form, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_db
from src.config import get_settings
from src.service.sbom import dx_ctl, sbom_db
from src.service.sbom.sbom_args import (
    AddSbomProjectArgs,
    AddSbomProjectReturn,
    DeleteSbomProjectArgs,
    GetChildGraph,
    GetComponentsArgs,
    GetCountArgs,
    GetVulnerabilitiesArgs,
    GetVulnerabilitiesDetails,
    SelectSbomProjectArgs,
    SelectSbomProjectReturn,
    UpdateSbomProjectArgs,
)
from src.service.sbom.sbom_src import main as sbom_main_async
from src.service.utils import BaseResponseModel, BaseResponseNoDataModel

router = APIRouter(tags=["开源组件分析工具"])
DEFAULT_USER_ID = 0

_ALONE_LANGUAGE = {"python", "golang", "php", "javascript", "rust", "java", "c/c++"}
_ALLOWED_ARCHIVE_SUFFIX = {"zip", "tar"}


def _safe_filename(name: str) -> str:
    """
    最小化的文件名清洗：避免 ../ 路径穿越
    """
    return os.path.basename(name).replace("\\", "_").replace("/", "_")


def _spawn(coro: asyncio.Future) -> None:
    """
    在当前事件循环丢后台协程任务，并记录异常（避免 silent fail）
    """
    task = asyncio.create_task(coro)

    def _done_callback(t: asyncio.Task) -> None:
        try:
            t.result()
        except Exception as e:  # noqa: BLE001
            # 这里建议你换成项目日志 logger
            print(f"[sbom background task error] {e!r}")

    task.add_done_callback(_done_callback)


@router.post(
    "/sbom/create_sbom_project",
    response_model=BaseResponseModel[AddSbomProjectReturn],
)
async def create_sbom_project(
    project_name: str = Form(...),
    project_desc: str = Form(...),
    code_language: str = Form(...),
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
):
    """
    创建分析任务（异步版）
    - 保存上传包（aiofiles）
    - 写库（AsyncSession）
    - 启动后台协程做解压/生成bom/上传DX/更新状态
    """
    args = AddSbomProjectArgs.model_validate(
        {"project_name": project_name, "project_desc": project_desc, "code_language": code_language}
    )
    if args.code_language not in _ALONE_LANGUAGE:
        return BaseResponseModel.failed("暂不支持该语言").resp()

    raw_filename = file.filename or ""
    filename = _safe_filename(raw_filename)
    if "." not in filename:
        return BaseResponseModel.failed("文件格式错误，只支持zip和tar格式").resp()

    file_suffix = filename.rsplit(".", 1)[-1].lower()
    file_name = filename.rsplit(".", 1)[0]
    if file_suffix not in _ALLOWED_ARCHIVE_SUFFIX:
        return BaseResponseModel.failed("文件格式错误，只支持zip和tar格式").resp()

    settings = get_settings()
    sbom_root: Path = settings.paths.sbom
    sbom_root.mkdir(parents=True, exist_ok=True)

    # 1) 创建 DX 项目（异步 HTTP）
    dx_project_name = uuid4().hex
    dx_uuid = await dx_ctl.create_project(dx_project_name)

    # 2) 保存上传文件（异步写）
    file_path = sbom_root / filename
    try:
        async with aiofiles.open(file_path, "wb") as f:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                await f.write(chunk)
    finally:
        # 释放上传文件句柄
        await file.close()

    # 3) 目标目录（解压目录）
    file_dir = sbom_root / dx_project_name

    # 4) 写 DB（AsyncSession + SQLAlchemy 2.0）
    data = await sbom_db.create_sbom_project(db, args, DEFAULT_USER_ID, str(file_dir), dx_uuid)

    # 5) 启动后台任务（不要传 db/session，后台内部自己开会话/或只做无DB逻辑+通过 sbom_db 自建会话）
    _spawn(
        sbom_main_async(
            archive_path=str(file_path),
            extract_dir=str(file_dir),
            dx_uuid=dx_uuid,
            file_name=file_name,
            code_language=args.code_language,
            project_id=data.project_id,
        )
    )

    return BaseResponseModel.success("新建分析任务成功", data=data).resp()


@router.get("/sbom/get_language_down")
async def get_language_down():
    ret_data = [
        {"label": "python", "value": "python"},
        {"label": "golang", "value": "golang"},
        {"label": "php", "value": "php"},
        {"label": "javascript", "value": "javascript"},
        {"label": "rust", "value": "rust"},
        {"label": "java", "value": "java"},
        {"label": "c/c++", "value": "c/c++"},
    ]
    return BaseResponseModel.success("获取语言下拉成功", data=ret_data).resp()


@router.post("/sbom/update_sbom_project", response_model=BaseResponseNoDataModel)
async def update_sbom_project(args: UpdateSbomProjectArgs, db: AsyncSession = Depends(get_db)):
    await sbom_db.update_project(db, args, DEFAULT_USER_ID)
    return BaseResponseNoDataModel.success("修改项目信息成功").resp()


@router.post("/sbom/get_project_list", response_model=BaseResponseModel[SelectSbomProjectReturn])
async def get_project_list(args: SelectSbomProjectArgs, db: AsyncSession = Depends(get_db)):
    data = await sbom_db.select_project(db, args, DEFAULT_USER_ID)
    return BaseResponseModel.success(data=data).resp()


@router.post("/sbom/delete_sbom_project", response_model=BaseResponseNoDataModel)
async def delete_sbom_project(args: DeleteSbomProjectArgs, db: AsyncSession = Depends(get_db)):
    await sbom_db.delete_project(db, args, DEFAULT_USER_ID)
    return BaseResponseNoDataModel.success().resp()


@router.post("/sbom/get_component_list")
async def get_component_list(args: GetComponentsArgs):
    data = await dx_ctl.get_bom_result(
        project_uuid=args.dx_uuid,
        page_number=args.page,
        page_size=args.page_size,
        search_text=args.search_text or "",
    )
    return BaseResponseModel.success(data=data or []).resp()


@router.post("/sbom/get_count")
async def get_project_count(args: GetCountArgs):
    data = await dx_ctl.get_count(project_uuid=args.dx_uuid)
    return BaseResponseModel.success(data=data or {}).resp()


@router.post("/sbom/get_vulnerabilities")
async def get_vulnerabilities(args: GetVulnerabilitiesArgs):
    data = await dx_ctl.get_project_vulnerabilities(project_uuid=args.dx_uuid, search_text=args.search_text or "")
    return BaseResponseModel.success(data=data or []).resp()


@router.post("/sbom/get_project_graph")
async def get_graph(args: GetCountArgs):
    data = await dx_ctl.get_project_graph(project_uuid=args.dx_uuid)
    return BaseResponseModel.success(data=data or {}).resp()


@router.post("/sbom/get_project_child_graph")
async def get_child_graph(args: GetChildGraph):
    data = await dx_ctl.get_project_child_graph(graph_uuid=args.graph_uuid)
    return BaseResponseModel.success(data=data or {}).resp()


@router.post("/sbom/get_vulnerabilities_details")
async def get_vuln_details(args: GetVulnerabilitiesDetails):
    data = await dx_ctl.get_vulnerabilities_details(vuln_id=args.vuln_id)
    return BaseResponseModel.success(data=data or {}).resp()


@router.post("/sbom/get_project_base_info")
async def get_project_base_info(args: GetCountArgs, db: AsyncSession = Depends(get_db)):
    data = await sbom_db.get_project_base_info(db, args)
    return BaseResponseModel.success(data=data).resp()
