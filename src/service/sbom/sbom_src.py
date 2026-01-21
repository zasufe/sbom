# src/service/sbom/sbom_src.py
from __future__ import annotations

import asyncio
import logging
import os
import shutil
import sys
import tarfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

from src.db.session import get_session_maker
from src.service.sbom import sbom_db

"""
SBOM 后台工作流程（异步、生产级）。

步骤：
1) 将上传的 zip/tar 存档安全解压到项目目录
2) 自动定位项目根目录（兼容：压缩包带顶层目录 / 不带顶层目录）
3) 探测项目语言关键清单文件，并构建 SBOM 命令
4) 执行命令（区分并打印：命令行为日志、stdout/stderr 流式日志）
5) 将生成的 BOM 上传到依赖项跟踪 (DX)
6) 更新 DB 项目状态

设计目标：
- 可观测：必打执行命令/目录/环境、stdout/stderr 实时输出、rc/耗时/摘要
- 高可用：超时、并发限流、输出校验、异常分类、DB 写入截断保护
- 安全：不使用 shell=True；安全解压防路径穿越/链接攻击/zip bomb
- 易维护：结构化命令、统一执行器、集中常量配置
"""

# =========================
# 日志域（业务 vs 命令执行）
# =========================

LOG = logging.getLogger("sbom")   # 业务流程日志
EXEC = logging.getLogger("exec")  # 命令执行日志（过程/输出）

# =========================
# 生产参数（可按需调整）
# =========================

SBOM_CONCURRENCY: Final[int] = int(os.getenv("SBOM_CONCURRENCY", "2"))
_SBOM_SEM = asyncio.Semaphore(SBOM_CONCURRENCY)

CMD_TIMEOUT_SEC: Final[int] = int(os.getenv("SBOM_CMD_TIMEOUT_SEC", "1800"))  # 30min
MAX_CAPTURE_CHARS: Final[int] = int(os.getenv("SBOM_MAX_CAPTURE_CHARS", "8000"))  # 建议比 2000 大一点

# 解压安全参数
MAX_EXTRACT_FILES: Final[int] = int(os.getenv("SBOM_MAX_EXTRACT_FILES", "20000"))
MAX_EXTRACT_SIZE_BYTES: Final[int] = int(os.getenv("SBOM_MAX_EXTRACT_SIZE_BYTES", str(2 * 1024**3)))  # 2GB

# 项目根目录探测：最多向下探测多少层
MAX_ROOT_DETECT_DEPTH: Final[int] = int(os.getenv("SBOM_ROOT_DETECT_DEPTH", "4"))

# =========================
# DB 状态更新
# =========================

async def _update_status(project_id: int, status: int, error_message: str | None = None) -> None:
    SessionLocal = get_session_maker()
    async with SessionLocal() as db:
        await sbom_db.update_project_status(
            db,
            project_id=project_id,
            status=status,
            error_message=error_message,
        )

# =========================
# 安全解压（防 Zip Slip / Tar 路径穿越 / 链接攻击）
# =========================

def _is_within_directory(base: Path, target: Path) -> bool:
    """判断 target 是否在 base 目录内（防路径穿越）。"""
    try:
        base_resolved = base.resolve(strict=False)
        target_resolved = target.resolve(strict=False)
        return os.path.commonpath([str(base_resolved), str(target_resolved)]) == str(base_resolved)
    except Exception:
        return False

def _safe_extract_zip(zip_path: Path, extract_dir: Path) -> tuple[bool, str | None]:
    """安全解压 zip：限制文件数量/总大小，拒绝路径穿越/绝对路径。"""
    total_size = 0

    with zipfile.ZipFile(zip_path, "r") as zf:
        infos = zf.infolist()
        total_files = len(infos)
        if total_files > MAX_EXTRACT_FILES:
            return False, f"Zip 文件过大：文件数 {total_files} 超过限制 {MAX_EXTRACT_FILES}"

        for info in infos:
            total_size += int(info.file_size or 0)
            if total_size > MAX_EXTRACT_SIZE_BYTES:
                return False, f"Zip 文件过大：总解压体积超过限制 {MAX_EXTRACT_SIZE_BYTES} bytes"

            name = info.filename

            # 拒绝绝对路径/盘符
            if name.startswith(("/", "\\")) or ":" in name:
                return False, f"Zip 包含可疑绝对路径：{name}"

            out_path = extract_dir / name
            if not _is_within_directory(extract_dir, out_path):
                return False, f"Zip 路径穿越风险：{name}"

        zf.extractall(extract_dir)

    return True, None

def _safe_extract_tar(tar_path: Path, extract_dir: Path) -> tuple[bool, str | None]:
    """安全解压 tar：限制成员数量/总大小，拒绝路径穿越/绝对路径/链接成员。"""
    total_size = 0

    with tarfile.open(tar_path, "r:*") as tar:
        members = tar.getmembers()
        total_files = len(members)
        if total_files > MAX_EXTRACT_FILES:
            return False, f"Tar 文件过大：成员数 {total_files} 超过限制 {MAX_EXTRACT_FILES}"

        for m in members:
            name = m.name

            if name.startswith(("/", "\\")) or ":" in name:
                return False, f"Tar 包含可疑绝对路径：{name}"

            # 禁止链接类
            if m.issym() or m.islnk():
                return False, f"Tar 包含链接类型成员，存在风险：{name}"

            total_size += max(0, int(getattr(m, "size", 0) or 0))
            if total_size > MAX_EXTRACT_SIZE_BYTES:
                return False, f"Tar 文件过大：总解压体积超过限制 {MAX_EXTRACT_SIZE_BYTES} bytes"

            out_path = extract_dir / name
            if not _is_within_directory(extract_dir, out_path):
                return False, f"Tar 路径穿越风险：{name}"

        tar.extractall(extract_dir)

    return True, None

async def extract_archive(archive_path: str, extract_dir: str, project_id: int) -> bool:
    """解压归档文件到 extract_dir。"""
    await _update_status(project_id=project_id, status=1)

    archive_p = Path(archive_path)
    extract_p = Path(extract_dir)

    def _do_extract() -> tuple[bool, str | None]:
        try:
            extract_p.mkdir(parents=True, exist_ok=True)

            if tarfile.is_tarfile(archive_p):
                return _safe_extract_tar(archive_p, extract_p)

            if zipfile.is_zipfile(archive_p):
                return _safe_extract_zip(archive_p, extract_p)

            return False, "不支持的文件类型（仅支持 tar/tar.gz/zip）"
        except Exception as e:  # noqa: BLE001
            return False, f"解压失败: {e!r}"
        finally:
            try:
                archive_p.unlink(missing_ok=True)
            except Exception:
                pass

    ok, err = await asyncio.to_thread(_do_extract)

    if not ok:
        LOG.warning("解压失败 project_id=%s archive=%s err=%s", project_id, archive_path, err)
        await _update_status(project_id=project_id, status=-1, error_message=err)
        return False

    LOG.info("解压成功 project_id=%s extract_dir=%s", project_id, extract_dir)
    return True

# =========================
# 项目根目录定位（统一解压目录/分析目录）
# =========================

# 用于“快速识别根目录”的典型文件（按语言/生态覆盖）
ROOT_HINT_FILES: Final[set[str]] = {
    # Python
    "requirements.txt", "requirement.txt", "pyproject.toml", "setup.py", "setup.cfg", "Pipfile",
    # Node
    "package.json", "pnpm-lock.yaml", "yarn.lock", "package-lock.json",
    # Go
    "go.mod",
    # Rust
    "Cargo.toml",
    # Java
    "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
    # PHP
    "composer.json",
    # C/C++
    "CMakeLists.txt", "Makefile", "makefile", "meson.build", "vcpkg.json", "conanfile.py", "conanfile.txt",
}

def _list_top_entries(p: Path, limit: int = 32) -> list[str]:
    if not p.exists() or not p.is_dir():
        return []
    items = []
    try:
        for i, c in enumerate(sorted(p.iterdir(), key=lambda x: x.name)):
            if i >= limit:
                items.append("...")  # marker
                break
            items.append(c.name + ("/" if c.is_dir() else ""))
    except Exception:
        return []
    return items

def _score_root_candidate(dirpath: Path) -> int:
    """目录命中 ROOT_HINT_FILES 越多，越像根目录。"""
    if not dirpath.is_dir():
        return -1
    score = 0
    for name in ROOT_HINT_FILES:
        if (dirpath / name).exists():
            score += 2
    # 额外启发：如果存在 src/ 或 app/，加分
    if (dirpath / "src").is_dir():
        score += 1
    if (dirpath / "app").is_dir():
        score += 1
    return score

def _detect_project_root(extract_dir: Path, *, hint: str | None, lang: str) -> Path:
    """
    在 extract_dir 下定位项目根目录。
    兼容：
    - 压缩包带顶层目录（extract_dir/xxx/...）
    - 压缩包不带顶层目录（extract_dir 直接就是项目根）
    - API 传入 hint(file_name) 但实际解压后目录名不一致
    """
    extract_dir = extract_dir.resolve(strict=False)

    # 0) 首先尝试：extract_dir/hint
    if hint:
        p = (extract_dir / hint)
        if p.exists() and p.is_dir():
            return p

    # 1) 如果 extract_dir 本身就像根目录
    best = extract_dir
    best_score = _score_root_candidate(extract_dir)

    # 2) BFS/有限深度扫描候选子目录
    #    注意：只扫描目录，不递归无限
    frontier: list[tuple[Path, int]] = [(extract_dir, 0)]
    seen: set[Path] = set()

    while frontier:
        cur, depth = frontier.pop(0)
        if cur in seen:
            continue
        seen.add(cur)

        if depth > MAX_ROOT_DETECT_DEPTH:
            continue

        score = _score_root_candidate(cur)
        if score > best_score:
            best_score = score
            best = cur

        try:
            for child in cur.iterdir():
                if child.is_dir():
                    # 跳过常见巨大目录
                    if child.name in {".git", ".svn", "node_modules", ".venv", "venv", "__pycache__", "target", "dist", "build"}:
                        continue
                    frontier.append((child, depth + 1))
        except Exception:
            continue

    # 3) 最终返回 best（即使 score=0，也至少返回 extract_dir）
    return best

# =========================
# 命令结构与构建
# =========================

@dataclass(frozen=True, slots=True)
class BomCommand:
    """
    SBOM 生成命令的结构化表示：
    - pre_args: 前置命令（可选，例如 composer install/update）
    - args: 主命令
    - cwd: 执行工作目录
    - output: 期望输出文件（完整路径）
    - tool: 工具名（用于审计与日志）
    """
    args: list[str]
    cwd: Path
    output: Path
    tool: str
    pre_args: list[str] | None = None


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

def _venv_bin() -> str | None:
    """
    从 sys.executable 推断 venv/bin：
    /root/.virtualenvs/sbom/bin/python -> /root/.virtualenvs/sbom/bin
    """
    exe = Path(sys.executable)
    if exe.parent.name == "bin" and exe.name.startswith("python"):
        return str(exe.parent)
    return None

def _build_subproc_env() -> dict[str, str]:
    """
    构造子进程 env：关键是兜底 PATH，把当前解释器所在 venv/bin 放最前。
    解决：uvicorn/systemd/IDE 环境 PATH 与交互 shell 不一致导致 which 找不到工具。
    """
    env = os.environ.copy()

    prefix: list[str] = []
    vbin = _venv_bin()
    if vbin:
        prefix.append(vbin)  # ✅ 必须有：保证 cyclonedx-py 等 venv 内 CLI 可见

    prefix += [
        "/root/.cargo/bin",
        "/root/.local/bin",
        "/usr/local/sbin",
        "/usr/local/bin",
        "/usr/sbin",
        "/usr/bin",
        "/sbin",
        "/bin",
    ]

    current = env.get("PATH", "")
    merged = ":".join(prefix + [current])

    seen: set[str] = set()
    parts: list[str] = []
    for p in merged.split(":"):
        if p and p not in seen:
            seen.add(p)
            parts.append(p)

    env["PATH"] = ":".join(parts)
    return env

def _which(cmd: str) -> str | None:
    """使用“子进程同款 PATH”来 which，避免 uvicorn 环境 PATH 不一致。"""
    env = _build_subproc_env()
    return shutil.which(cmd, path=env.get("PATH"))

def _pick_first_existing(target_dir: Path, candidates: list[str]) -> str | None:
    for name in candidates:
        if (target_dir / name).exists():
            return name
    return None

def _build_python_bom(dx_uuid: str, project_root: Path) -> BomCommand | None:
    """
    ✅ Python：强制使用 sys.executable -m cyclonedx_py（不依赖 PATH）
    """
    output = project_root / f"{dx_uuid}.json"
    py = sys.executable

    req = _pick_first_existing(project_root, PYTHON_REQUIREMENT_CANDIDATES)
    if req:
        return BomCommand(
            args=[py, "-m", "cyclonedx_py", "requirements", req, "-o", str(output)],
            cwd=project_root,
            output=output,
            tool="cyclonedx-py",
        )

    if (project_root / "pyproject.toml").exists():
        return BomCommand(
            args=[py, "-m", "cyclonedx_py", "pyproject", "pyproject.toml", "-o", str(output)],
            cwd=project_root,
            output=output,
            tool="cyclonedx-py",
        )

    return None

def _build_golang_bom(dx_uuid: str, project_root: Path) -> BomCommand | None:
    gomod = _which("cyclonedx-gomod")
    if not gomod or not (project_root / "go.mod").exists():
        return None
    output = project_root / f"{dx_uuid}.json"
    return BomCommand(
        args=[gomod, "mod", "-json", "-output", str(output)],
        cwd=project_root,
        output=output,
        tool="cyclonedx-gomod",
    )

def _build_php_bom(dx_uuid: str, project_root: Path) -> BomCommand | None:
    composer = _which("composer")
    if not composer or not (project_root / "composer.json").exists():
        return None

    output = project_root / f"{dx_uuid}.json"

    pre_args = (
        [composer, "install", "--no-interaction", "--no-progress"]
        if (project_root / "composer.lock").exists()
        else [composer, "update", "--no-interaction", "--no-progress"]
    )

    args = [
        composer,
        "CycloneDX:make-sbom",
        "--output-format=JSON",
        f"--output-file={output}",
    ]

    return BomCommand(pre_args=pre_args, args=args, cwd=project_root, output=output, tool="composer+cyclonedx")

def _build_javascript_bom(dx_uuid: str, project_root: Path) -> BomCommand | None:
    cyclonedx_npm = _which("cyclonedx-npm")
    if not cyclonedx_npm or not (project_root / "package.json").exists():
        return None
    output = project_root / f"{dx_uuid}.json"
    return BomCommand(
        args=[cyclonedx_npm, "package.json", "--output-format=JSON", "--output-file", str(output)],
        cwd=project_root,
        output=output,
        tool="cyclonedx-npm",
    )

def _build_rust_bom(dx_uuid: str, project_root: Path) -> BomCommand | None:
    cargo = _which("cargo")
    cargo_cyclonedx = _which("cargo-cyclonedx")  # 有些环境是 cargo 子命令安装到 ~/.cargo/bin
    if not cargo or not cargo_cyclonedx or not (project_root / "Cargo.toml").exists():
        return None
    output = project_root / f"{dx_uuid}.json"
    return BomCommand(
        args=[cargo, "cyclonedx", "-f=json", f"--override-filename={dx_uuid}", "--workspace", "--all"],
        cwd=project_root,
        output=output,
        tool="cargo-cyclonedx",
    )

def _build_java_bom(dx_uuid: str, project_root: Path) -> BomCommand | None:
    cdxgen = _which("cdxgen")
    if not cdxgen:
        return None
    output = project_root / f"{dx_uuid}.json"
    return BomCommand(
        args=[cdxgen, "-t", "java", "-o", str(output), "--spec-version", "1.6"],
        cwd=project_root,
        output=output,
        tool="cdxgen",
    )

def _build_c_cpp_bom(dx_uuid: str, project_root: Path) -> BomCommand | None:
    cdxgen = _which("cdxgen")
    if not cdxgen:
        return None

    # best-effort：即使没有构建元数据也可跑，但你可以在日志里提醒
    has_metadata = any((project_root / f).exists() for f in C_CPP_BUILD_METADATA)
    if not has_metadata:
        LOG.info("C/C++ 未发现典型构建元数据，cdxgen 将 best-effort 扫描 project_root=%s", str(project_root))

    output = project_root / f"{dx_uuid}.json"
    return BomCommand(
        args=[cdxgen, "-t", "c", "-o", str(output), "--spec-version", "1.6"],
        cwd=project_root,
        output=output,
        tool="cdxgen",
    )

def build_bom_command(code_language: str, dx_uuid: str, project_root: Path) -> tuple[BomCommand | None, dict[str, str | None]]:
    """
    返回：(BomCommand|None, which_map)
    which_map 用于“无法构建命令”时输出诊断信息。
    """
    lang = code_language.lower().strip()

    which_map = {
        "python": str(Path(sys.executable)),
        "cyclonedx-py": _which("cyclonedx-py"),
        "cyclonedx-gomod": _which("cyclonedx-gomod"),
        "composer": _which("composer"),
        "cyclonedx-npm": _which("cyclonedx-npm"),
        "cargo": _which("cargo"),
        "cargo-cyclonedx": _which("cargo-cyclonedx"),
        "cdxgen": _which("cdxgen"),
    }

    match lang:
        case "python":
            return _build_python_bom(dx_uuid, project_root), which_map
        case "golang" | "go":
            return _build_golang_bom(dx_uuid, project_root), which_map
        case "php":
            return _build_php_bom(dx_uuid, project_root), which_map
        case "javascript" | "node" | "nodejs":
            return _build_javascript_bom(dx_uuid, project_root), which_map
        case "rust":
            return _build_rust_bom(dx_uuid, project_root), which_map
        case "java":
            return _build_java_bom(dx_uuid, project_root), which_map
        case "c/c++" | "c" | "cpp":
            return _build_c_cpp_bom(dx_uuid, project_root), which_map
        case _:
            return None, which_map

# =========================
# 命令执行器（确保看到过程/报错）
# =========================

@dataclass(frozen=True, slots=True)
class CmdResult:
    returncode: int
    stdout: str
    stderr: str
    duration_ms: int

def _format_cmd(args: list[str]) -> str:
    """仅用于日志展示（可复制粘贴），不用于执行。"""
    def q(s: str) -> str:
        if s == "":
            return '""'
        if any(c in s for c in (" ", "\t", "\n", '"', "'")):
            return '"' + s.replace('"', '\\"') + '"'
        return s
    return " ".join(q(a) for a in args)

async def _stream_reader(
    stream: asyncio.StreamReader,
    *,
    stream_name: Literal["stdout", "stderr"],
    exec_id: str,
    max_capture_chars: int,
) -> str:
    """
    流式读取子进程输出（按块读取，兼容无换行/进度条）：
    - 实时打印到 EXEC 日志（区分 stdout/stderr）
    - 同时截断捕获（用于失败时写 DB）
    """
    captured = 0
    buf: list[str] = []

    while True:
        chunk = await stream.read(4096)
        if not chunk:
            break

        text = chunk.decode("utf-8", "ignore")

        # 实时打印：将 \r 当换行，避免进度条“看不到”
        for line in text.replace("\r", "\n").splitlines():
            if line.strip():
                EXEC.info("[exec:%s][%s] %s", exec_id, stream_name, line)

        # 截断捕获：保留原始 chunk（含换行）
        if captured < max_capture_chars:
            remain = max_capture_chars - captured
            piece = text[:remain]
            buf.append(piece)
            captured += len(piece)

    return "".join(buf)

async def run_command_logged(
    *,
    args: list[str],
    cwd: Path,
    exec_id: str,
    tool: str,
    timeout_sec: int = CMD_TIMEOUT_SEC,
    max_capture_chars: int = MAX_CAPTURE_CHARS,
) -> CmdResult:
    """
    生产级命令执行（保证可观测）：
    - 不使用 shell=True（安全）
    - 必打：START（cmd/cwd/timeout/python/PATH）/ END（rc/耗时/摘要）
    - stdout/stderr：实时流式输出
    - 超时：kill 并记录 TIMEOUT
    """
    start = time.perf_counter()
    env = _build_subproc_env()
    cmd_str = _format_cmd(args)

    EXEC.info(
        "[exec:%s] START tool=%s cwd=%s timeout_sec=%s cmd=%s",
        exec_id, tool, str(cwd), timeout_sec, cmd_str,
    )
    EXEC.info(
        "[exec:%s] ENV python=%s VIRTUAL_ENV=%s PATH=%s",
        exec_id, sys.executable, env.get("VIRTUAL_ENV", ""), env.get("PATH", ""),
    )

    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            cwd=str(cwd),
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        assert proc.stdout is not None
        assert proc.stderr is not None

        stdout_task = asyncio.create_task(_stream_reader(proc.stdout, stream_name="stdout", exec_id=exec_id, max_capture_chars=max_capture_chars))
        stderr_task = asyncio.create_task(_stream_reader(proc.stderr, stream_name="stderr", exec_id=exec_id, max_capture_chars=max_capture_chars))

        try:
            await asyncio.wait_for(proc.wait(), timeout=timeout_sec)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            raise

        stdout_text = await stdout_task
        stderr_text = await stderr_task

        duration_ms = int((time.perf_counter() - start) * 1000)
        rc = int(proc.returncode or 0)

        stdout_head = (stdout_text or "")[:240].replace("\n", "\\n")
        stderr_head = (stderr_text or "")[:240].replace("\n", "\\n")
        EXEC.info(
            "[exec:%s] END tool=%s rc=%s duration_ms=%s stdout_head=%s stderr_head=%s",
            exec_id, tool, rc, duration_ms, stdout_head, stderr_head,
        )

        return CmdResult(returncode=rc, stdout=stdout_text, stderr=stderr_text, duration_ms=duration_ms)

    except TimeoutError:
        duration_ms = int((time.perf_counter() - start) * 1000)
        EXEC.error("[exec:%s] TIMEOUT tool=%s duration_ms=%s", exec_id, tool, duration_ms)
        return CmdResult(returncode=124, stdout="", stderr="TIMEOUT", duration_ms=duration_ms)

    except FileNotFoundError as e:
        duration_ms = int((time.perf_counter() - start) * 1000)
        EXEC.error("[exec:%s] NOT_FOUND tool=%s duration_ms=%s err=%r cmd=%s", exec_id, tool, duration_ms, e, cmd_str)
        return CmdResult(returncode=127, stdout="", stderr=f"NOT_FOUND: {e!r}", duration_ms=duration_ms)

    except Exception as e:  # noqa: BLE001
        duration_ms = int((time.perf_counter() - start) * 1000)
        EXEC.exception("[exec:%s] ERROR tool=%s duration_ms=%s err=%r", exec_id, tool, duration_ms, e)
        return CmdResult(returncode=1, stdout="", stderr=repr(e), duration_ms=duration_ms)

# =========================
# 生成 SBOM（业务层）
# =========================

async def make_dx_bom(
    *,
    extract_dir: str,
    code_language: str,
    file_name_hint: str,
    dx_uuid: str,
    project_id: int,
) -> str | None:
    await _update_status(project_id=project_id, status=2)

    extract_p = Path(extract_dir)
    project_root = _detect_project_root(extract_p, hint=file_name_hint, lang=code_language)

    LOG.info(
        "定位项目根目录 project_id=%s extract_dir=%s hint=%s lang=%s project_root=%s top=%s",
        project_id,
        str(extract_p),
        file_name_hint,
        code_language,
        str(project_root),
        _list_top_entries(project_root),
    )

    if not project_root.exists():
        LOG.error("项目根目录不存在 project_id=%s project_root=%s", project_id, str(project_root))
        await _update_status(project_id=project_id, status=-1, error_message="项目根目录不存在")
        return None

    LOG.info(
        "开始生成 SBOM project_id=%s dx_uuid=%s lang=%s project_root=%s",
        project_id, dx_uuid, code_language, str(project_root),
    )

    bom_cmd, which_map = build_bom_command(code_language, dx_uuid, project_root)

    # 诊断信息：命中哪些 requirements、是否有 pyproject
    req_hits = [n for n in PYTHON_REQUIREMENT_CANDIDATES if (project_root / n).exists()]
    has_pyproject = (project_root / "pyproject.toml").exists()

    if not bom_cmd:
        LOG.warning(
            "无法构建 SBOM 命令 project_id=%s dx_uuid=%s lang=%s project_root=%s "
            "reason=missing_manifest_or_tool which=%s req_hits=%s has_pyproject=%s top=%s PATH=%s python=%s",
            project_id,
            dx_uuid,
            code_language,
            str(project_root),
            which_map,
            req_hits,
            has_pyproject,
            _list_top_entries(project_root),
            _build_subproc_env().get("PATH", ""),
            sys.executable,
        )
        await _update_status(
            project_id=project_id,
            status=-1,
            error_message="无法构建SBOM命令：缺少清单文件/工具未安装或不在PATH",
        )
        return None

    # 无论执行与否，先把命令完整打印出来（关键！）
    LOG.info(
        "将执行 SBOM 命令 project_id=%s tool=%s cwd=%s pre=%s cmd=%s output=%s",
        project_id,
        bom_cmd.tool,
        str(bom_cmd.cwd),
        _format_cmd(bom_cmd.pre_args) if bom_cmd.pre_args else "-",
        _format_cmd(bom_cmd.args),
        str(bom_cmd.output),
    )

    exec_base = f"{project_id}-{dx_uuid}-{bom_cmd.tool}"

    async with _SBOM_SEM:
        # 1) 前置命令
        if bom_cmd.pre_args:
            pre_res = await run_command_logged(
                args=bom_cmd.pre_args,
                cwd=bom_cmd.cwd,
                exec_id=exec_base + ":pre",
                tool=bom_cmd.tool,
            )
            if pre_res.returncode != 0:
                LOG.error(
                    "前置命令失败 project_id=%s rc=%s stderr=%s",
                    project_id, pre_res.returncode, (pre_res.stderr or "")[:MAX_CAPTURE_CHARS],
                )
                await _update_status(
                    project_id=project_id,
                    status=-1,
                    error_message=f"前置命令失败(rc={pre_res.returncode}): {(pre_res.stderr or '')[:MAX_CAPTURE_CHARS]}",
                )
                return None

        # 2) 主命令
        res = await run_command_logged(
            args=bom_cmd.args,
            cwd=bom_cmd.cwd,
            exec_id=exec_base,
            tool=bom_cmd.tool,
        )

    if res.returncode != 0:
        LOG.error(
            "生成 SBOM 失败 project_id=%s tool=%s rc=%s duration_ms=%s stderr=%s",
            project_id, bom_cmd.tool, res.returncode, res.duration_ms, (res.stderr or "")[:MAX_CAPTURE_CHARS],
        )
        await _update_status(
            project_id=project_id,
            status=-1,
            error_message=f"生成bom失败(rc={res.returncode}): {(res.stderr or '')[:MAX_CAPTURE_CHARS]}",
        )
        return None

    if not bom_cmd.output.exists():
        LOG.error("命令 rc=0 但未产出文件 project_id=%s output=%s", project_id, str(bom_cmd.output))
        await _update_status(project_id=project_id, status=-1, error_message="生成bom失败：命令执行成功但未发现输出文件")
        return None

    LOG.info(
        "SBOM 生成成功 project_id=%s dx_uuid=%s tool=%s output=%s duration_ms=%s",
        project_id, dx_uuid, bom_cmd.tool, str(bom_cmd.output), res.duration_ms,
    )

    return bom_cmd.output.name

# =========================
# 总入口：解压 → 生成 → 上传 DX → 更新状态
# =========================

async def main(
    *,
    archive_path: str,
    extract_dir: str,
    dx_uuid: str,
    file_name: str,
    code_language: str,
    project_id: int,
) -> bool:
    """
    主流程入口（供 API 层后台任务调用）。
    """
    ok = await extract_archive(archive_path=archive_path, extract_dir=extract_dir, project_id=project_id)
    if not ok:
        return False

    bom_json_name = await make_dx_bom(
        extract_dir=extract_dir,
        code_language=code_language,
        file_name_hint=file_name,  # 注意：这里是“hint”，不再硬拼路径
        dx_uuid=dx_uuid,
        project_id=project_id,
    )
    if not bom_json_name:
        return False

    # bom_path 使用“定位到的 project_root”后生成的输出文件名
    # 这里我们重新定位一次 root（幂等），确保路径一致
    project_root = _detect_project_root(Path(extract_dir), hint=file_name, lang=code_language)
    bom_path = str(project_root / bom_json_name)

    from src.service.sbom import dx_ctl  # 断开循环依赖

    flag = await dx_ctl.update_project_bom(project_uuid=dx_uuid, file_path=bom_path)
    if flag:
        await _update_status(project_id=project_id, status=3)
        LOG.info("DX 上传成功 project_id=%s dx_uuid=%s bom_path=%s", project_id, dx_uuid, bom_path)
        return True

    await _update_status(project_id=project_id, status=-1, error_message="DX error")
    LOG.error("DX 上传失败 project_id=%s dx_uuid=%s bom_path=%s", project_id, dx_uuid, bom_path)
    return False
