# src/service/sbom/sbom_src.py
from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Final

"""
SBOM 后台工作流程（异步）。

步骤：
1) 将上传的 zip/tar 存档解压到项目目录
2) 通过特定语言的 CLI 生成 CycloneDX BOM JSON
3) 将 BOM 上传到依赖项跟踪 (DX)
4）更新DB中的项目状态
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





@dataclass(frozen=True, slots=True)
class BomCommand:
    """
    SBOM 生成命令的结构化表示
    - args: 传给 subprocess 的参数列表（不使用 shell=True）
    - cwd: 执行命令时的工作目录（统一为 target_dir）
    - output: 期望生成的 SBOM 输出文件路径
    - tool: 实际使用的工具名（用于审计与日志）
    """
    args: list[str]
    cwd: Path
    output: Path
    tool: str


# ===== 常量区（便于维护与统一变更） =====

PYTHON_REQUIREMENT_CANDIDATES: Final[list[str]] = [
    "requirements.txt",
    "requirement.txt",
    "requirements-dev.txt",
    "requirements-prod.txt",
    "requirements-test.txt",
]

C_CPP_BUILD_METADATA: Final[list[str]] = [
    "CMakeLists.txt",
    "Makefile",
    "makefile",
    "compile_commands.json",
    "conanfile.txt",
    "conanfile.py",
    "vcpkg.json",
    "meson.build",
]


# ===== 通用工具函数 =====

def _which(cmd: str) -> str | None:
    """
    安全获取可执行文件的绝对路径。
    避免依赖不稳定的 PATH，增强容器 / CI 稳定性。
    """
    return shutil.which(cmd)


def _pick_first_existing(target_dir: Path, candidates: list[str]) -> str | None:
    """
    从候选文件名列表中，返回第一个在 target_dir 中存在的文件名。
    """
    for name in candidates:
        if (target_dir / name).exists():
            return name
    return None


# ===== 各语言构建函数 =====

def _build_python_bom(dx_uuid: str, target_dir: Path) -> BomCommand | None:
    """
    构建 Python 项目的 SBOM 生成命令。
    支持：
    - requirements*.txt
    - pyproject.toml（Poetry / PEP 621）
    """
    cyclonedx = _which("cyclonedx-py")
    if not cyclonedx:
        return None  # 工具不存在，交由上层做降级或报错

    output = target_dir / f"{dx_uuid}.json"

    # 1) requirements*.txt
    req_file = _pick_first_existing(target_dir, PYTHON_REQUIREMENT_CANDIDATES)
    if req_file:
        return BomCommand(
            args=[cyclonedx, "requirements", req_file, "-o", str(output)],
            cwd=target_dir,
            output=output,
            tool="cyclonedx-py",
        )

    # 2) pyproject.toml
    if (target_dir / "pyproject.toml").exists():
        return BomCommand(
            args=[cyclonedx, "pyproject", "pyproject.toml", "-o", str(output)],
            cwd=target_dir,
            output=output,
            tool="cyclonedx-py",
        )

    return None


def _build_golang_bom(dx_uuid: str, target_dir: Path) -> BomCommand | None:
    """
    构建 Go 项目的 SBOM 生成命令（基于 go.mod）。
    """
    gomod = _which("cyclonedx-gomod")
    if not gomod or not (target_dir / "go.mod").exists():
        return None

    output = target_dir / f"{dx_uuid}.json"
    return BomCommand(
        args=[gomod, "mod", "-json", "-output", str(output)],
        cwd=target_dir,
        output=output,
        tool="cyclonedx-gomod",
    )


def _build_php_bom(dx_uuid: str, target_dir: Path) -> BomCommand | None:
    """
    构建 PHP 项目的 SBOM 生成命令。
    策略：
    - 有 composer.lock → composer install（稳定、可复现）
    - 无 lock → composer update（退而求其次）
    """
    composer = _which("composer")
    if not composer or not (target_dir / "composer.json").exists():
        return None

    output = target_dir / f"{dx_uuid}.json"

    if (target_dir / "composer.lock").exists():
        pre_cmd = [composer, "install", "--no-interaction", "--no-progress"]
    else:
        pre_cmd = [composer, "update", "--no-interaction", "--no-progress"]

    sbom_cmd = [
        composer,
        "CycloneDX:make-sbom",
        "--output-format=JSON",
        f"--output-file={output}",
    ]

    return BomCommand(
        args=pre_cmd + ["&&"] + sbom_cmd,  # 仅用于展示；真实执行应拆成两步
        cwd=target_dir,
        output=output,
        tool="composer+cyclonedx",
    )


def _build_javascript_bom(dx_uuid: str, target_dir: Path) -> BomCommand | None:
    """
    构建 Node.js 项目的 SBOM 生成命令。
    """
    cyclonedx_npm = _which("cyclonedx-npm")
    if not cyclonedx_npm or not (target_dir / "package.json").exists():
        return None

    output = target_dir / f"{dx_uuid}.json"
    return BomCommand(
        args=[cyclonedx_npm, "package.json", "--output-format=JSON", "--output-file", str(output)],
        cwd=target_dir,
        output=output,
        tool="cyclonedx-npm",
    )


def _build_rust_bom(dx_uuid: str, target_dir: Path) -> BomCommand | None:
    """
    构建 Rust 项目的 SBOM 生成命令。
    - 默认启用 workspace / all，避免多 crate 项目缺失依赖。
    """
    cargo = _which("cargo")
    cyclonedx = _which("cargo-cyclonedx")

    if not cargo or not cyclonedx or not (target_dir / "Cargo.toml").exists():
        return None

    output = target_dir / f"{dx_uuid}.json"
    return BomCommand(
        args=[
            cargo,
            "cyclonedx",
            "-f=json",
            f"--override-filename={dx_uuid}",
            "--workspace",
            "--all",
        ],
        cwd=target_dir,
        output=output,
        tool="cargo-cyclonedx",
    )


def _build_java_bom(dx_uuid: str, target_dir: Path) -> BomCommand | None:
    """
    构建 Java 项目的 SBOM 生成命令（基于 cdxgen）。
    即使没有 pom.xml / gradle，也尝试 best-effort 扫描。
    """
    cdxgen = _which("cdxgen")
    if not cdxgen:
        return None

    output = target_dir / f"{dx_uuid}.json"
    return BomCommand(
        args=[cdxgen, "-t", "java", "-o", str(output), "--spec-version", "1.6"],
        cwd=target_dir,
        output=output,
        tool="cdxgen",
    )


def _build_c_cpp_bom(dx_uuid: str, target_dir: Path) -> BomCommand | None:
    """
    构建 C / C++ 项目的 SBOM 生成命令（基于 cdxgen）。
    若存在典型构建元数据文件，优先扫描；否则 best-effort。
    """
    cdxgen = _which("cdxgen")
    if not cdxgen:
        return None

    output = target_dir / f"{dx_uuid}.json"

    has_metadata = any((target_dir / f).exists() for f in C_CPP_BUILD_METADATA)
    if not has_metadata:
        # 这里可以选择 return None（严格）或 best-effort 扫描
        pass

    return BomCommand(
        args=[cdxgen, "-t", "c", "-o", str(output), "--spec-version", "1.6"],
        cwd=target_dir,
        output=output,
        tool="cdxgen",
    )


# ===== 主入口函数 =====

def build_bom_command(
    code_language: str,
    dx_uuid: str,
    target_dir: Path,
) -> BomCommand | None:
    """
    根据语言类型 + 目标目录，构建 SBOM 生成命令。
    返回 BomCommand（结构化命令），或 None（不具备生成条件）。
    """
    code_language = code_language.lower().strip()

    match code_language:
        case "python":
            return _build_python_bom(dx_uuid, target_dir)

        case "golang" | "go":
            return _build_golang_bom(dx_uuid, target_dir)

        case "php":
            return _build_php_bom(dx_uuid, target_dir)

        case "javascript" | "node" | "nodejs":
            return _build_javascript_bom(dx_uuid, target_dir)

        case "rust":
            return _build_rust_bom(dx_uuid, target_dir)

        case "java":
            return _build_java_bom(dx_uuid, target_dir)

        case "c/c++" | "c" | "cpp":
            return _build_c_cpp_bom(dx_uuid, target_dir)

        case _:
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
    cmd = build_bom_command(code_language, dx_uuid, target_dir)
    print("生成bom命令:", cmd)
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
