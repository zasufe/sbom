# src/service/sbom/sbom_src.py
from __future__ import annotations

"""
SBOM background workflow (async).

Steps:
1) Extract uploaded zip/tar archive to a project directory
2) Generate CycloneDX BOM JSON via language-specific CLI
3) Upload BOM to Dependency-Track (DX)
4) Update project status in DB
"""

import asyncio
import tarfile
import zipfile
from pathlib import Path

from src.db.session import get_session_maker
from src.service.sbom import sbom_db


async def _update_status(project_id: int, status: int, error_message: str | None = None) -> None:
    SessionLocal = get_session_maker()
    async with SessionLocal() as db:
        await sbom_db.update_project_status(
            db,
            project_id=project_id,
            status=status,
            error_message=error_message,
        )


async def extract_archive(archive_path: str, extract_dir: str, project_id: int) -> bool:
    await _update_status(project_id=project_id, status=1)

    archive_p = Path(archive_path)
    extract_p = Path(extract_dir)

    def _do_extract() -> tuple[bool, str | None]:
        try:
            if tarfile.is_tarfile(archive_p):
                extract_p.mkdir(parents=True, exist_ok=True)
                with tarfile.open(archive_p, "r") as tar:
                    tar.extractall(extract_p)
            elif zipfile.is_zipfile(archive_p):
                extract_p.mkdir(parents=True, exist_ok=True)
                with zipfile.ZipFile(archive_p, "r") as zf:
                    zf.extractall(extract_p)
            else:
                return False, "不支持的文件类型"
            return True, None
        except Exception as e:  # noqa: BLE001
            return False, f"解压失败: {e!r}"
        finally:
            try:
                archive_p.unlink(missing_ok=True)
            except Exception:
                pass

    ok, err = await asyncio.to_thread(_do_extract)
    if not ok:
        await _update_status(project_id=project_id, status=-1, error_message=err)
    return ok


def _build_bom_command(code_language: str, dx_uuid: str) -> str | None:
    if code_language == "python":
        return f"cyclonedx-py requirements requirements.txt -o {dx_uuid}.json"
    if code_language == "golang":
        return f"cyclonedx-gomod mod -json -output {dx_uuid}.json"
    if code_language == "php":
        return f"composer update && composer CycloneDX:make-sbom --output-format=JSON --output-file={dx_uuid}.json"
    if code_language == "javascript":
        return f"cyclonedx-npm package.json --output-format=JSON --output-file={dx_uuid}.json"
    if code_language == "rust":
        return f"cargo cyclonedx -f=json --override-filename={dx_uuid}"
    if code_language == "java":
        return f"cdxgen -t java -o {dx_uuid}.json --spec-version 1.6"
    if code_language == "c/c++":
        return f"cdxgen -t c -o {dx_uuid}.json --spec-version 1.6"
    return None


async def make_dx_bom(
    extract_dir: str,
    code_language: str,
    file_name: str,
    dx_uuid: str,
    project_id: int,
) -> str | None:
    await _update_status(project_id=project_id, status=2)

    target_dir = Path(extract_dir) / file_name
    cmd = _build_bom_command(code_language, dx_uuid)
    if not cmd:
        await _update_status(project_id=project_id, status=-1, error_message="不支持的语言类型")
        return None

    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            cwd=str(target_dir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await proc.communicate()
    except Exception as e:  # noqa: BLE001
        await _update_status(project_id=project_id, status=-1, error_message=f"生成bom异常: {e!r}")
        return None

    if proc.returncode != 0:
        err_msg = (err.decode("utf-8", "ignore") if err else "")[:2000]
        await _update_status(project_id=project_id, status=-1, error_message=f"生成bom失败: {err_msg}")
        return None

    return f"{dx_uuid}.json"


async def main(
    archive_path: str,
    extract_dir: str,
    dx_uuid: str,
    file_name: str,
    code_language: str,
    project_id: int,
) -> bool:
    ok = await extract_archive(archive_path=archive_path, extract_dir=extract_dir, project_id=project_id)
    if not ok:
        return False

    bom_json_name = await make_dx_bom(
        extract_dir=extract_dir,
        code_language=code_language,
        file_name=file_name,
        dx_uuid=dx_uuid,
        project_id=project_id,
    )
    if not bom_json_name:
        return False

    bom_path = str(Path(extract_dir) / file_name / bom_json_name)

    # ✅ 断开循环依赖：函数内导入
    from src.service.sbom import dx_ctl

    flag = await dx_ctl.update_project_bom(project_uuid=dx_uuid, file_path=bom_path)
    if flag:
        await _update_status(project_id=project_id, status=3)
        return True

    await _update_status(project_id=project_id, status=-1, error_message="DX error")
    return False
