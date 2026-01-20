# src/service/sbom/sbom_db.py
from __future__ import annotations

import datetime
import os
import shutil

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models.sbom_models import SbomProject
from src.service.sbom.sbom_args import (
    AddSbomProjectArgs,
    AddSbomProjectReturn,
    UpdateSbomProjectArgs,
    SelectSbomProjectArgs,
    SelectSbomProjectReturn,
    DeleteSbomProjectArgs,
    GetCountArgs,
    ProjectInfo,
)
from src.service.utils import BusinessException


async def create_sbom_project(
    session: AsyncSession,
    args: AddSbomProjectArgs,
    user_id: int,
    file_path: str,
    dx_uuid: str,
) -> AddSbomProjectReturn:
    stmt = select(SbomProject.project_name).where(SbomProject.project_name == args.project_name)
    exists = (await session.execute(stmt)).first()
    if exists:
        raise BusinessException("项目名称重复，请重新输入")

    new_obj = SbomProject(
        project_name=args.project_name,
        project_desc=args.project_desc,
        code_language=args.code_language,
        create_user_id=user_id,
        code_path=file_path,
        dx_uuid=dx_uuid,
    )
    session.add(new_obj)
    await session.flush()
    project_id = new_obj.id
    await session.commit()
    return AddSbomProjectReturn(project_id=project_id, dx_uuid=dx_uuid)


async def update_project_status(
    session: AsyncSession,
    project_id: int,
    status: int,
    error_message: str | None = None,
) -> bool:
    stmt = (
        update(SbomProject)
        .where(SbomProject.id == project_id)
        .values(status=status, error_message=error_message, update_time=datetime.datetime.now())
    )
    await session.execute(stmt)
    await session.commit()
    return True


async def project_authentication(session: AsyncSession, project_id: int, user_id: int) -> bool:
    stmt = select(SbomProject.create_user_id).where(SbomProject.id == project_id)
    row = (await session.execute(stmt)).first()
    if not row:
        raise BusinessException("未知项目")
    if row.create_user_id != user_id:
        raise BusinessException("暂无修改权限")
    return True


async def update_project(session: AsyncSession, args: UpdateSbomProjectArgs, user_id: int) -> None:
    await project_authentication(session, args.project_id, user_id)
    stmt = (
        update(SbomProject)
        .where(SbomProject.id == args.project_id)
        .values(project_name=args.project_name, project_desc=args.project_desc, update_time=datetime.datetime.now())
    )
    await session.execute(stmt)
    await session.commit()


async def select_project(session: AsyncSession, args: SelectSbomProjectArgs, user_id: int) -> SelectSbomProjectReturn:
    filters = [SbomProject.create_user_id == user_id]
    if args.project_name:
        filters.append(SbomProject.project_name.like(f"%{args.project_name}%"))
    if args.code_language:
        filters.append(SbomProject.code_language == args.code_language)

    query = (
        select(
            SbomProject.id,
            SbomProject.project_name,
            SbomProject.code_language,
            SbomProject.project_desc,
            SbomProject.status,
            SbomProject.create_time,
            SbomProject.update_time,
            SbomProject.dx_uuid,
        )
        .where(*filters)
        .order_by(SbomProject.create_time.desc())
    )

    time_handle = {
        "create_time": lambda x: x.strftime("%Y-%m-%d %H:%M") if x else "",
        "update_time": lambda x: x.strftime("%Y-%m-%d %H:%M") if x else "",
    }
    # 注意：这里需要 sbom_args.SelectSbomProjectReturn.build_res_with_sql_query 也改成 async
    return await SelectSbomProjectReturn.build_res_with_sql_query(
        pagination_req=args,
        query=query,
        handle=time_handle,
        sess=session,
    )


async def delete_project(session: AsyncSession, args: DeleteSbomProjectArgs, user_id: int) -> bool:
    await project_authentication(session, args.project_id, user_id)

    stmt_path = select(SbomProject.code_path).where(SbomProject.id == args.project_id)
    row = (await session.execute(stmt_path)).first()
    code_path = row.code_path if row else None

    if code_path and os.path.exists(code_path):
        shutil.rmtree(code_path)

    stmt = delete(SbomProject).where(SbomProject.id == args.project_id)
    await session.execute(stmt)
    await session.commit()
    return True


async def get_project_base_info(session: AsyncSession, args: GetCountArgs) -> ProjectInfo:
    stmt = select(
        SbomProject.project_name, SbomProject.code_language, SbomProject.project_desc, SbomProject.status
    ).where(SbomProject.dx_uuid == args.dx_uuid)
    row = (await session.execute(stmt)).first()
    if not row:
        raise BusinessException("未知项目")
    return ProjectInfo(
        project_name=row.project_name,
        code_language=row.code_language,
        project_desc=row.project_desc,
        status=row.status,
    )
