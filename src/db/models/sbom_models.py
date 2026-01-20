# -*- coding: utf-8 -*-
"""
 * Copyright (c) 2024 FengTaiSEC Corporation.
"""
from datetime import datetime

from sqlalchemy import VARCHAR, TEXT
from sqlalchemy.orm import Mapped, mapped_column

from .base_model import DbModel


class SbomProject(DbModel):
    """软件清单扫描项目表"""

    __tablename__ = "sbom_project"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True, index=True)
    project_name: Mapped[str] = mapped_column(VARCHAR(64), index=True, unique=True, comment="项目名称")
    project_desc: Mapped[str] = mapped_column(TEXT, comment="项目描述")
    code_language: Mapped[str] = mapped_column(VARCHAR(64), comment="代码语言")
    code_path: Mapped[str] = mapped_column(VARCHAR(255), comment="代码路径")
    create_time: Mapped[datetime] = mapped_column(index=True, default=datetime.now, comment="创建时间")
    update_time: Mapped[datetime] = mapped_column(index=True, default=datetime.now, onupdate=datetime.now, comment="更新时间")
    create_user_id: Mapped[int] = mapped_column(index=True, comment="创建人id")
    status: Mapped[int] = mapped_column(index=True, default=0, comment="任务状态0：未开始，1：解压中，2：生成bom中，3：分析完成，-1：失败")
    dx_uuid: Mapped[str] = mapped_column(VARCHAR(64), comment="DX project uuid", nullable=True)
    error_message: Mapped[str] = mapped_column(TEXT, comment="失败原因", nullable=True)
