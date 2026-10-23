"""SBOM：认语言，不认"打包机自己"。

原实现跑 `cyclonedx-py environment`，生成的是**当前解释器环境**的清单。
一个纯 npm 项目会拿到 143 条 Python 依赖，还标着 "SBOM Tool: cyclonedx"。
那不是项目的 SBOM，是构建机的体检报告。

这里的规矩：先认项目类型，再挑对应的扫描器；显式要了却拿不到就报错。
用户明确要的东西没产出、退出码还是 0，是审计里最容易被抓的那种洞。

唯一例外是 Python 项目缺 cyclonedx-py：`requirements.txt` 本身就是依赖声明，
从它生成最小 CycloneDX 比让整条流水线失败更有用，也比空 SBOM 诚实。
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
    只有 requirements.txt 可用；poetry.lock 的解析交给 cyclonedx-py，
    这里不去猜 TOML 的锁文件语义。
    """
    req = repo_root / "requirements.txt"
    if not req.is_file():
        return None
    try:
        text = req.read_text(encoding="utf-8")
    except OSError:
        return None
    return text


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


def _requirements_sbom(text: str) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {"type": "application", "name": "requirements.txt"},
            "tools": [{"name": "evidence-pack/requirements-fallback", "version": __version__}],
        },
        "components": _parse_requirements(text),
    }


def _write(out_path: Path, parsed: dict) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # 重新序列化而非透传：不同扫描器输出的键序不同，直接落盘会毁掉可复现性。
    out_path.write_bytes(stable_json_bytes(parsed))


def generate(repo_root: Path, choice: str, out_path: Path) -> str:
    """返回实际使用的扫描方式；"none" 表示没产。"""
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
        except ToolFailure as exc:
            text = _requirements_text(repo_root)
            if text is None:
                # 明确要了却拿不到：退出码 3，绝不静默出个空 SBOM。
                raise
            _write(out_path, _requirements_sbom(text))
            return "python"
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

    _write(out_path, parsed)
    return choice
