# src/db/session.py
from __future__ import annotations

from functools import lru_cache

from sqlalchemy import URL
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from src.config import get_settings


def build_url() -> URL:
    s = get_settings()
    db = s.db
    return URL.create(
        drivername=f"mysql+{db.driver}",  # mysql+asyncmy
        username=db.user,
        password=db.password,
        host=db.host,
        port=db.port,
        database=db.database,
        query={"charset": db.charset},
    )


@lru_cache(maxsize=1)
def get_engine() -> AsyncEngine:
    s = get_settings()
    return create_async_engine(
        build_url(),
        pool_pre_ping=s.db.pool_pre_ping,
        pool_size=s.db.pool_size,
        max_overflow=s.db.max_overflow,
    )


@lru_cache(maxsize=1)
def get_session_maker() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(
        bind=get_engine(),
        expire_on_commit=False,
        autoflush=False,
        class_=AsyncSession,
    )
