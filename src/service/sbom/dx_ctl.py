# src/service/sbom/dx_ctl.py
from __future__ import annotations

import json
from typing import Any

import httpx

from src.config import get_settings
from src.service.utils import BusinessException


# =========================
# 基础工具
# =========================

def _base_url() -> str:
    # 统一处理末尾 /
    host = get_settings().dx.api_host.rstrip("/")
    return host


def _headers_json() -> dict[str, str]:
    s = get_settings().dx
    if not s.api_key:
        raise BusinessException("DX_API_KEY 未配置")
    return {
        "X-Api-Key": s.api_key,
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def _headers_any(content_type: str) -> dict[str, str]:
    s = get_settings().dx
    if not s.api_key:
        raise BusinessException("DX_API_KEY 未配置")
    return {
        "X-Api-Key": s.api_key,
        "Accept": "application/json",
        "Content-Type": content_type,
    }


async def _client() -> httpx.AsyncClient:
    # 保持最小改动：每次创建 client；如果要更高性能，建议在 FastAPI lifespan 中维护单例 client。
    # timeout 生产建议分 connect/read/write/pool；这里先给稳妥值。
    timeout = httpx.Timeout(connect=5.0, read=30.0, write=30.0, pool=5.0)
    return httpx.AsyncClient(timeout=timeout)


async def _sleep_1s() -> None:
    import asyncio
    await asyncio.sleep(1)


def _err_of(resp: httpx.Response) -> str:
    # 统一把错误内容截断，避免日志/DB 爆炸
    text = resp.text or ""
    text = text[:2000]
    return f"{resp.status_code}: {text}"


# =========================
# API 封装
# =========================

async def get_bom_result(project_uuid: str, page_size: int = 10, page_number: int = 1, search_text: str = "") -> Any:
    url = f"{_base_url()}/api/v1/component/project/{project_uuid}"
    params = {"searchText": search_text, "pageSize": page_size, "pageNumber": page_number}
    async with (await _client()) as c:
        r = await c.get(url, headers=_headers_json(), params=params)
    if r.status_code == 200:
        return r.json()
    return None


async def create_project(project_name: str) -> str:
    """
    curl 验证：PUT /api/v1/project -> 201 Created
    """
    url = f"{_base_url()}/api/v1/project"
    payload = {
        "active": True,
        "name": project_name,
        "classifier": "LIBRARY",
        "parent": None,
        "tags": [],
        "version": "1.0",
    }

    last_err: str | None = None
    for _ in range(3):
        async with (await _client()) as c:
            r = await c.put(url, headers=_headers_json(), content=json.dumps(payload))
        if r.status_code == 201:
            uuid = r.json().get("uuid")
            if not uuid:
                raise BusinessException("DX 返回 201 但 uuid 为空")
            return uuid
        last_err = _err_of(r)
        await _sleep_1s()

    raise BusinessException(f"DX_CREATE_PROJECT_FAILED: {last_err or 'unknown'}")


async def delete_project(project_uuid: str) -> bool:
    """
    删除 Dependency-Track 项目

    你抓包里是：
      DELETE /api/v1/project/{uuid}

    生产兼容：
      - 204 No Content：常见成功
      - 200 OK / 202 Accepted：有些版本/反向代理会返回
      - 404 Not Found：项目已不存在，也视为成功（幂等）
    """
    url = f"{_base_url()}/api/v1/project/{project_uuid}"

    last_err: str | None = None
    for _ in range(3):
        async with (await _client()) as c:
            r = await c.delete(url, headers=_headers_json())

        if r.status_code in (200, 202, 204, 404):
            return True

        last_err = _err_of(r)
        await _sleep_1s()

    raise BusinessException(f"DX_DELETE_PROJECT_FAILED: {last_err or 'unknown'}")


async def update_project_bom(project_uuid: str, file_path: str) -> bool:
    """
    POST /api/v1/bom  (multipart)
    fields:
      - project: <uuid>
      - bom: <file>
    """
    url = f"{_base_url()}/api/v1/bom"

    try:
        with open(file_path, "rb") as f:
            files = {
                "project": (None, project_uuid),
                "bom": (f"{project_uuid}.json", f, "application/json"),
            }
            # multipart 时不要强塞 Content-Type: application/json
            headers = {"X-Api-Key": get_settings().dx.api_key, "Accept": "application/json"}
            async with (await _client()) as c:
                r = await c.post(url, headers=headers, files=files)
    except FileNotFoundError:
        return False

    # 200 OK：常见成功；有些版本可能 201
    return r.status_code in (200, 201)


async def get_count(project_uuid: str) -> Any:
    url = f"{_base_url()}/api/v1/metrics/project/{project_uuid}/current"
    async with (await _client()) as c:
        r = await c.get(url, headers=_headers_json())
    if r.status_code == 200:
        try:
            return r.json()
        except Exception:
            return None
    return None


async def get_project_graph(project_uuid: str) -> Any:
    url = f"{_base_url()}/api/v1/project/{project_uuid}"
    async with (await _client()) as c:
        r = await c.get(url, headers=_headers_json())
    if r.status_code == 200:
        return r.json()
    return None


async def get_project_child_graph(graph_uuid: str) -> Any:
    url = f"{_base_url()}/api/v1/component/{graph_uuid}"
    params = {"includeRepositoryMetaData": "true"}
    async with (await _client()) as c:
        r = await c.get(url, headers=_headers_json(), params=params)
    if r.status_code == 200:
        return r.json()
    return None


async def get_project_vulnerabilities(project_uuid: str, search_text: str) -> Any:
    url = f"{_base_url()}/api/v1/finding/project/{project_uuid}"
    params = {"source": "NVD", "suppressed": "false", "searchText": search_text}
    async with (await _client()) as c:
        r = await c.get(url, headers=_headers_json(), params=params)
    if r.status_code == 200:
        return r.json()
    return None


async def get_vulnerabilities_details(vuln_id: str) -> Any:
    url = f"{_base_url()}/api/v1/vulnerability/source/NVD/vuln/{vuln_id}"
    async with (await _client()) as c:
        r = await c.get(url, headers=_headers_json())
    if r.status_code == 200:
        return r.json()
    return None
