"""SBOM：认语言，不认"打包机自己"。

原实现跑 `cyclonedx-py environment`，生成的是**当前解释器环境**的清单。
一个纯 npm 项目会拿到 143 条 Python 依赖，还标着 "SBOM Tool: cyclonedx"。
那不是项目的 SBOM，是构建机的体检报告。

这里的规矩：先认项目类型，再挑对应的扫描器；显式要了却拿不到就报错。
用户明确要的东西没产出、退出码还是 0，是审计里最容易被抓的那种洞。

唯一例外是 Python 项目缺扫描器（或扫描器不认这个形态）：`requirements.txt`
与 `pyproject.toml` 的 PEP 621 依赖表本身就是依赖声明，从它们生成最小 CycloneDX
比让整条流水线失败更有用，也比空 SBOM 诚实。
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

from . import __version__
from .errors import ToolFailure, UsageError
from .fsutil import stable_json_bytes

SUPPORTED = ("auto", "none", "python", "node")


def detect_kind(repo_root: Path) -> str | None:
    if any((repo_root / f).exists() for f in ("pyproject.toml", "setup.py", "requirements.txt", "poetry.lock")):
        return "python"
    if (repo_root / "package.json").exists():
        return "node"
    return None


def _run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
    except OSError as exc:
        raise ToolFailure(f"无法执行 {cmd[0]}：{exc}") from exc


def _requirements_text(repo_root: Path) -> str | None:
    """扫描器缺席时的退路：requirements.txt 本身就是一份依赖声明。

    直接从它生成最小 CycloneDX —— 不猜、不联网、不摸构建机的环境。
    poetry.lock 的解析交给 cyclonedx-py，这里不去猜 TOML 的锁文件语义。
    """
    req = repo_root / "requirements.txt"
    if not req.is_file():
        return None
    try:
        return req.read_text(encoding="utf-8")
    except OSError:
        return None


def _pyproject_requirements(repo_root: Path) -> list[str] | None:
    """从 pyproject.toml 的 PEP 621 依赖表里取出依赖声明。

    为什么需要这条：cyclonedx-py 只认 requirements / poetry / pipenv / venv，
    **没有**从 pyproject.toml 读依赖的子命令。而 pyproject.toml 恰恰是现代
    Python 项目的常态 —— 不补这条，`sbom: auto` 对这些项目必然判 3。

    读不到（没有 tomllib、TOML 坏了、没写 dependencies）一律返回 None，
    让上层维持原来的「要而不得就 3」的判定，绝不静默出空 SBOM。
    """
    pyproject = repo_root / "pyproject.toml"
    if not pyproject.is_file():
        return None
    # Python 3.11+ 有标准库 tomllib；3.10 需要 tomli。两者都没有就只能放弃，
    # 让上层维持「要而不得则 3」，绝不假装扫过一遍。
    try:
        import tomllib
    except ModuleNotFoundError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ModuleNotFoundError:
            return None
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None

    specs: list[str] = []
    project = data.get("project")
    if isinstance(project, dict):
        for key in ("dependencies",):
            raw = project.get(key)
            if isinstance(raw, list):
                specs.extend(str(x) for x in raw)
        # optional-dependencies 也算项目的依赖面，只是不总是装。
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for group in sorted(optional):
                deps = optional[group]
                if isinstance(deps, list):
                    specs.extend(str(x) for x in deps)
    return specs or None


def _python_cmd(repo_root: Path) -> list[str]:
    py = shutil.which("cyclonedx-py")
    if not py:
        raise ToolFailure(
            "需要 cyclonedx-py 生成 Python SBOM（pip install cyclonedx-bom）；"
            "或者提供 requirements.txt 让内置兜底解析。"
        )
    if (repo_root / "poetry.lock").exists():
        return [py, "poetry", "--output-format", "json"]
    if (repo_root / "requirements.txt").exists():
        return [py, "requirements", "--output-format", "json"]
    raise ToolFailure("Python 项目既无 poetry.lock 也无 requirements.txt，无法确定要扫描的依赖清单。")


def _node_cmd(repo_root: Path) -> list[str]:
    npm = shutil.which("cyclonedx-npm")
    if not npm:
        raise ToolFailure("需要 cyclonedx-npm 生成 Node SBOM（npm i -g @cyclonedx/cyclonedx-npm）。")
    return [npm, "--output-format", "JSON"]


_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*(\[[^\]]*\])?\s*(.*)$")


def _parse_requirements(text: str) -> list[dict]:
    """解析 requirements.txt 成 CycloneDX components。

    只认「名字 + 可选版本约束」，`-r` / `-e` / `--hash` / 注释 / 空行一律跳过：
    这些行要么指向别处，要么是构建参数，猜测它们只会造出假数据。
    """
    components: list[dict] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-r", "-e", "-c", "--")):
            continue
        m = _REQ_LINE.match(line)
        if not m:
            continue
        name = m.group(1)
        if not name or name.lower() in seen:
            continue
        seen.add(name.lower())
        constraint = m.group(3).strip().split(";", 1)[0].strip()
        component: dict = {"type": "library", "name": name}
        if constraint.startswith(("==", ">=", "<=", "~=", "!=")):
            component["version"] = constraint.lstrip("=<>!~ ").strip() or "unspecified"
        else:
            component["version"] = "unspecified"
        components.append(component)
    return sorted(components, key=lambda c: (c["name"], c["version"]))


def _requirements_sbom(text: str, *, source: str = "requirements.txt") -> dict:
    """最小 CycloneDX。

    `source` 要如实写清是从哪个文件推出来的 —— 审计时「这个 SBOM 从哪儿来的」
    和「里面有什么」同样重要，写成固定值等于伪造出处。
    """
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {"type": "application", "name": source},
            "tools": [{"name": "evidence-pack/dependency-fallback", "version": __version__}],
        },
        "components": _parse_requirements(text),
    }


def _normalize(parsed: dict, epoch: int | None) -> dict:
    """抹掉扫描器自带的两个不确定性来源。

    这是真实踩过的坑：cyclonedx-py 每次都写新的 `metadata.timestamp`（当下时间）
    和 `serialNumber`（随机 UUID）。同一个 commit 打两次包，tar.gz 的哈希就不同，
    而「可复现」正是这个工具存在的理由。

    处理方式：
      - `timestamp` → SOURCE_DATE_EPOCH（没有就整个删掉，宁缺勿假）
      - `serialNumber` → 由内容派生的确定性 UUID，同一份清单永远同一个序列号

    只动这两个字段；其余内容（含键序）交给 stable_json_bytes 负责。
    """
    import datetime as _dt
    import hashlib as _hl
    import uuid as _uuid

    parsed.pop("serialNumber", None)
    meta = parsed.get("metadata")
    if isinstance(meta, dict):
        meta.pop("timestamp", None)
        if epoch is not None:
            meta["timestamp"] = (
                _dt.datetime.fromtimestamp(epoch, _dt.timezone.utc)
                .strftime("%Y-%m-%dT%H:%M:%SZ")
            )

    # 序列号按内容派生：内容变则号变，内容不变则号不变。
    fingerprint = _hl.sha256(stable_json_bytes(parsed)).hexdigest()
    parsed["serialNumber"] = f"urn:uuid:{_uuid.UUID(fingerprint[:32])}"
    return parsed


def _write(out_path: Path, parsed: dict, epoch: int | None = None) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # 重新序列化而非透传：不同扫描器输出的键序不同，直接落盘会毁掉可复现性。
    out_path.write_bytes(stable_json_bytes(_normalize(parsed, epoch)))


def generate(repo_root: Path, choice: str, out_path: Path, *, epoch: int | None = None) -> str:
    """返回实际使用的扫描方式；"none" 表示没产。

    `epoch` 是打包使用的 SOURCE_DATE_EPOCH，用来把扫描器自带的时间戳
    钉死；不给则删掉时间戳字段（见 _normalize）。
    """
    if choice not in SUPPORTED:
        raise UsageError(f"--sbom 只接受 {'/'.join(SUPPORTED)}，收到 {choice!r}。")

    if choice == "none":
        return "none"

    kind = detect_kind(repo_root)
    if choice == "auto":
        if kind is None:
            return "none"
        choice = kind
    else:
        # 只挡掉「认出了另一种语言」的明确冲突；认不出来时交给下面的扫描器兜底。
        if kind is not None and kind != choice:
            raise UsageError(f"--sbom {choice} 与项目类型不符：{repo_root} 认出来的是 {kind} 项目。")

    if choice == "python":
        try:
            cmd = _python_cmd(repo_root)
        except ToolFailure:
            # 扫描器缺席或它不认这个项目形态时的兜底，顺序是：
            # requirements.txt（最贴近真实安装）→ pyproject.toml（PEP 621）。
            text = _requirements_text(repo_root)
            if text is not None:
                _write(out_path, _requirements_sbom(text, source="requirements.txt"), epoch)
                return "python"
            specs = _pyproject_requirements(repo_root)
            if specs is not None:
                _write(out_path, _requirements_sbom("\n".join(specs), source="pyproject.toml"), epoch)
                return "python"
            # 明确要了却拿不到：退出码 3，绝不静默出个空 SBOM。
            raise
    else:
        cmd = _node_cmd(repo_root)
    proc = _run(cmd, repo_root)
    if proc.returncode != 0:
        first = (proc.stderr.strip().splitlines() or ["未知错误"])[0]
        raise ToolFailure(f"SBOM 生成失败（{choice}）：{first}")

    raw = proc.stdout.strip()
    if not raw:
        raise ToolFailure(f"SBOM 生成器 {cmd[0]} 没有输出内容。")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ToolFailure(f"SBOM 输出不是合法 JSON：{exc}") from exc
    if not isinstance(parsed, dict) or not isinstance(parsed.get("components"), list):
        raise ToolFailure("SBOM 输出缺少 components 字段，不是 CycloneDX。")

    _write(out_path, parsed, epoch)
    return choice
