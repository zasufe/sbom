# src/config.py
from __future__ import annotations

import os
import sys
from functools import lru_cache
from pathlib import Path

from pydantic import Field, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict

# 你明确说 .env 在 src/.env
ENV_FILE = Path(__file__).resolve().parent / ".env"


class DxSettings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    api_host: str = Field(default="http://127.0.0.1:8081", validation_alias="DX_API_HOST")
    api_key: str = Field(default="", validation_alias="DX_API_KEY")


class DbSettings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    driver: str = Field(default="asyncmy", validation_alias="DB_DRIVER")
    host: str = Field(default="127.0.0.1", validation_alias="DB_HOST")
    port: int = Field(default=3306, validation_alias="DB_PORT")
    user: str = Field(default="root", validation_alias="DB_USER")
    password: str = Field(default="", validation_alias="DB_PASSWORD")
    database: str = Field(default="sbom", validation_alias="DB_NAME")
    charset: str = Field(default="utf8mb4", validation_alias="DB_CHARSET")

    pool_size: int = Field(default=10, validation_alias="DB_POOL_SIZE")
    max_overflow: int = Field(default=20, validation_alias="DB_MAX_OVERFLOW")
    pool_pre_ping: bool = Field(default=True, validation_alias="DB_POOL_PRE_PING")


class PathSettings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    base: Path = Field(default_factory=lambda: Path(__file__).resolve().parents[1])
    sbom_storage_dir: str | None = Field(default=None, validation_alias="SBOM_STORAGE_DIR")

    @computed_field
    @property
    def sbom(self) -> Path:
        return Path(self.sbom_storage_dir) if self.sbom_storage_dir else (self.base / "data" / "sbom")


class AppSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
    )

    dx: DxSettings = Field(default_factory=DxSettings)
    db: DbSettings = Field(default_factory=DbSettings)
    paths: PathSettings = Field(default_factory=PathSettings)


@lru_cache(maxsize=1)
def get_settings() -> AppSettings:
    return AppSettings()


def debug_dump() -> None:
    """一键确认：env_file 是否被读取、关键变量是什么。"""
    s = get_settings()
    print("ENV_FILE:", ENV_FILE, "exists=", ENV_FILE.exists())
    print("CWD:", Path.cwd())
    print("os.getenv('DX_API_KEY'):", os.getenv("DX_API_KEY"))
    print("settings.dx.api_host:", s.dx.api_host)
    print("settings.dx.api_key:", repr(s.dx.api_key))
    print("settings.paths.sbom:", s.paths.sbom)
    print("settings.db.host:", s.db.host)
    print("settings.db.password:", repr(s.db.password))


if __name__ == "__main__":
    # 强制打印（避免 stdout 缓冲导致你误以为没输出）
    debug_dump()
    sys.stdout.flush()
