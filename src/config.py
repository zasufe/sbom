# src/config.py
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, Field, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict

ENV_FILE = Path(__file__).resolve().parent / ".env"


class DxSettings(BaseSettings):
    """
    .env:
      DX_API_HOST=...
      DX_API_KEY=...
    """
    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        env_prefix="DX_",
        extra="ignore",
    )

    api_host: str = Field(default="http://127.0.0.1:8081")
    api_key: str = Field(default="")


class DbSettings(BaseSettings):

    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        env_prefix="DB_",
        extra="ignore",
    )

    driver: str = Field(default="asyncmy")
    host: str = Field(default="127.0.0.1")
    port: int = Field(default=3306)
    user: str = Field(default="root")
    password: str = Field(default="")
    database: str = Field(default="sbom")
    charset: str = Field(default="utf8mb4")

    pool_size: int = Field(default=10)
    max_overflow: int = Field(default=20)
    pool_pre_ping: bool = Field(default=True)


class PathSettings(BaseSettings):
    """
    .env:
      SBOM_STORAGE_DIR=/opt/sbom/data/sbom
    """
    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
    )

    base: Path = Field(default_factory=lambda: Path(__file__).resolve().parents[1])
    sbom_storage_dir: str | None = Field(default=None)

    @computed_field
    @property
    def sbom(self) -> Path:
        return Path(self.sbom_storage_dir) if self.sbom_storage_dir else (self.base / "data" / "sbom")


class AppSettings(BaseModel):
    """
    聚合配置（不再负责从 env_file 解析）
    """
    dx: DxSettings = Field(default_factory=DxSettings)
    db: DbSettings = Field(default_factory=DbSettings)
    paths: PathSettings = Field(default_factory=PathSettings)


@lru_cache(maxsize=1)
def get_settings() -> AppSettings:
    return AppSettings()


if __name__ == "__main__":
    s = get_settings()
    print("ENV_FILE:", ENV_FILE, "exists=", ENV_FILE.exists())
    print("DX host:", s.dx.api_host)
    print("DX key :", repr(s.dx.api_key))
    print("DB host:", s.db.host)
    print("DB pwd :", repr(s.db.password))
    print("SBOM dir:", s.paths.sbom)
