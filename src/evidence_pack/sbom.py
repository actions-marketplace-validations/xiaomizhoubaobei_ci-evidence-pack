"""SBOM：认语言，不认"打包机自己"。

原实现跑 `cyclonedx-py environment`，生成的是**当前解释器环境**的清单。
一个纯 npm 项目会拿到 143 条 Python 依赖，还标着 "SBOM Tool: cyclonedx"。
那不是项目的 SBOM，是构建机的体检报告。

这里的规矩：先认项目类型，再挑对应的扫描器；显式要了却拿不到就报错。
用户明确要的东西没产出、退出码还是 0，是审计里最容易被抓的那种洞。
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

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


def _python_cmd(repo_root: Path) -> list[str]:
    py = shutil.which("cyclonedx-py")
    if not py:
        raise ToolFailure("需要 cyclonedx-py 生成 Python SBOM（pip install cyclonedx-bom）。")
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
    elif kind is None:
        raise UsageError(f"--sbom {choice} 与项目类型不符：没在 {repo_root} 认出该语言的依赖清单。")

    cmd = _python_cmd(repo_root) if choice == "python" else _node_cmd(repo_root)
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

    out_path.parent.mkdir(parents=True, exist_ok=True)
    # 重新序列化而非透传：不同扫描器输出的键序不同，直接落盘会毁掉可复现性。
    out_path.write_bytes(stable_json_bytes(parsed))
    return choice
