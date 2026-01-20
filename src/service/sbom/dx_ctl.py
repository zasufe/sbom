# src/service/sbom/dx_ctl.py
from __future__ import annotations

import json
from typing import Any

import httpx

from src.config import get_settings
from src.service.utils import BusinessException


def _base_url() -> str:
    # 统一处理末尾 /
    host = get_settings().dx.api_host.rstrip("/")
    return host


def _headers_json() -> dict[str, str]:
    s = get_settings().dx
    if not s.api_key:
        raise BusinessException("DX_API_KEY 未配置")
    # Dependency-Track header 通常是 X-Api-Key（大小写不敏感，但建议规范）
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
    # 每次创建 client 成本不大，但生产更推荐用单例 client（可在 lifespan 中实现）。
    # 这里先保持最小改动、可运行。
    return httpx.AsyncClient(timeout=httpx.Timeout(30.0))


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

    # 轻量重试（网络抖动）
    last_err: str | None = None
    for _ in range(3):
        async with (await _client()) as c:
            r = await c.put(url, headers=_headers_json(), content=json.dumps(payload))
        if r.status_code == 201:
            return r.json().get("uuid")
        last_err = f"{r.status_code}: {r.text}"
        await _sleep_1s()

    raise BusinessException(f"NETWORK_ERROR: {last_err or 'unknown'}")


async def delete_project(project_uuid: str) -> bool:
    url = f"{_base_url()}/api/v1/project/{project_uuid}"
    async with (await _client()) as c:
        r = await c.delete(url, headers=_headers_json())
    return r.status_code == 204


async def update_project_bom(project_uuid: str, file_path: str) -> bool:
    """
    POST /api/v1/bom  (multipart)
    fields:
      - project: <uuid>
      - bom: <file>
    """
    url = f"{_base_url()}/api/v1/bom"

    # 用 httpx files= 直接 multipart（无需 requests_toolbelt）
    try:
        with open(file_path, "rb") as f:
            files = {
                "project": (None, project_uuid),
                "bom": (f"{project_uuid}.json", f, "application/json"),
            }
            async with (await _client()) as c:
                r = await c.post(url, headers={"X-Api-Key": get_settings().dx.api_key, "Accept": "application/json"}, files=files)
    except FileNotFoundError:
        return False

    return r.status_code == 200


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


async def _sleep_1s() -> None:
    import asyncio
    await asyncio.sleep(1)
