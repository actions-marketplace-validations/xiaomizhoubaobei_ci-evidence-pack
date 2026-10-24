"""SBOM：要得到就必须有，但不该因为少装一个扫描器就让整条流水线红掉。"""

import json
from pathlib import Path

import pytest

from evidence_pack import sbom
from evidence_pack.errors import ToolFailure, UsageError


def _repo(tmp_path: Path, requirements: str | None = None) -> Path:
    (tmp_path / "src").mkdir()
    if requirements is not None:
        (tmp_path / "requirements.txt").write_text(requirements)
    return tmp_path


def test_none_produces_nothing(tmp_path):
    out = tmp_path / "sbom" / "sbom.cdx.json"
    assert sbom.generate(_repo(tmp_path), "none", out) == "none"
    assert not out.exists()


def test_unknown_choice_is_usage_error(tmp_path):
    with pytest.raises(UsageError):
        sbom.generate(_repo(tmp_path), "syft", tmp_path / "x.json")


def test_requirements_fallback_when_scanner_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(sbom.shutil, "which", lambda _name: None)
    out = tmp_path / "sbom" / "sbom.cdx.json"
    repo = _repo(
        tmp_path, "typer>=0.12,<1.0\npytest==8.3.0  # 测试用\n-r other.txt\n-e .\n"
    )
    assert sbom.generate(repo, "auto", out) == "python"
    data = json.loads(out.read_text(encoding="utf-8"))
    names = [c["name"] for c in data["components"]]
    assert names == ["pytest", "typer"]
    assert {c["name"]: c["version"] for c in data["components"]}["pytest"] == "8.3.0"


def test_python_project_without_scanner_or_requirements_is_exit_3(
    tmp_path, monkeypatch
):
    """pyproject.toml 认得出是 Python 项目，但既没扫描器也没 requirements.txt → 3。"""
    monkeypatch.setattr(sbom.shutil, "which", lambda _name: None)
    repo = _repo(tmp_path)
    (repo / "pyproject.toml").write_text("[project]\nname = 'x'\n")
    with pytest.raises(ToolFailure):
        sbom.generate(repo, "auto", tmp_path / "x.json")


def test_explicit_choice_must_match_project_kind(tmp_path):
    """Python 仓库上显式要 node SBOM：认不出依赖清单就是用法错，不是 3。"""
    with pytest.raises(UsageError, match="与项目类型不符"):
        sbom.generate(_repo(tmp_path, "typer\n"), "node", tmp_path / "x.json")


def test_fallback_output_is_byte_stable(tmp_path, monkeypatch):
    monkeypatch.setattr(sbom.shutil, "which", lambda _name: None)
    repo = _repo(tmp_path, "b-pkg\nabc\nA-pkg==1.0\nb-pkg\n")
    first = tmp_path / "a.json"
    second = tmp_path / "b.json"
    sbom.generate(repo, "python", first)
    sbom.generate(repo, "python", second)
    assert first.read_bytes() == second.read_bytes()


# ---------------------------------------------------------------------------
# pyproject.toml 兜底：cyclonedx-py 没有「从 PEP 621 依赖表生成」的子命令，
# 而只有 pyproject.toml 的现代 Python 项目到处都是。不补这条，
# `sbom: auto` 对它们必然判 3 —— 开箱即用就断在这儿。
# ---------------------------------------------------------------------------

pytest_tomli = pytest.mark.skipif(
    __import__("importlib").util.find_spec("tomli") is None
    and __import__("sys").version_info < (3, 11),
    reason="需要 tomllib(3.11+) 或 tomli",
)


def _pyproject_repo(tmp_path: Path, body: str) -> Path:
    repo = tmp_path / "proj"
    repo.mkdir(parents=True, exist_ok=True)
    (repo / "pyproject.toml").write_text(body, encoding="utf-8")
    return repo


@pytest_tomli
def test_pyproject_dependencies_are_used_when_scanner_missing(tmp_path, monkeypatch):
    """只有 pyproject.toml 也要能出 SBOM，而不是判 3。"""
    monkeypatch.setattr(sbom.shutil, "which", lambda _name: None)
    repo = _pyproject_repo(
        tmp_path,
        """[project]
name = "demo"
dependencies = ["typer>=0.12", "httpx==0.27.0"]
""",
    )
    out = tmp_path / "x.json"
    assert sbom.generate(repo, "auto", out) == "python"
    data = json.loads(out.read_text(encoding="utf-8"))
    names = [c["name"] for c in data["components"]]
    assert names == ["httpx", "typer"]
    # 出处要如实写：这不是 requirements.txt 里来的。
    assert data["metadata"]["component"]["name"] == "pyproject.toml"


@pytest_tomli
def test_pyproject_optional_dependencies_are_included(tmp_path, monkeypatch):
    monkeypatch.setattr(sbom.shutil, "which", lambda _name: None)
    repo = _pyproject_repo(
        tmp_path,
        """[project]
name = "demo"
dependencies = ["typer"]

[project.optional-dependencies]
dev = ["pytest>=8"]
""",
    )
    out = tmp_path / "x.json"
    sbom.generate(repo, "auto", out)
    names = [
        c["name"] for c in json.loads(out.read_text(encoding="utf-8"))["components"]
    ]
    assert names == ["pytest", "typer"]


@pytest_tomli
def test_requirements_wins_over_pyproject(tmp_path, monkeypatch):
    """两者都在时以 requirements.txt 为准：它更贴近实际安装的清单。"""
    monkeypatch.setattr(sbom.shutil, "which", lambda _name: None)
    repo = _pyproject_repo(tmp_path, '[project]\nname="d"\ndependencies=["fromtoml"]\n')
    (repo / "requirements.txt").write_text("fromreqs==1.0\n")
    out = tmp_path / "x.json"
    sbom.generate(repo, "auto", out)
    data = json.loads(out.read_text(encoding="utf-8"))
    assert [c["name"] for c in data["components"]] == ["fromreqs"]
    assert data["metadata"]["component"]["name"] == "requirements.txt"


@pytest_tomli
def test_pyproject_without_dependencies_still_exit_3(tmp_path, monkeypatch):
    """读得到 pyproject 但没有依赖表 —— 仍然是「要而不得」，不许出空 SBOM。"""
    monkeypatch.setattr(sbom.shutil, "which", lambda _name: None)
    repo = _pyproject_repo(tmp_path, '[project]\nname = "demo"\n')
    with pytest.raises(ToolFailure):
        sbom.generate(repo, "auto", tmp_path / "x.json")


def test_broken_pyproject_does_not_crash(tmp_path, monkeypatch):
    """TOML 写坏了也不能抛 tomllib 的 DecodeError 出去，只能维持 3。"""
    monkeypatch.setattr(sbom.shutil, "which", lambda _name: None)
    repo = _pyproject_repo(tmp_path, "[project\nname = broken")
    with pytest.raises(ToolFailure):
        sbom.generate(repo, "auto", tmp_path / "x.json")


# ---------------------------------------------------------------------------
# 确定性：扫描器自带的不确定字段必须被抹掉。
# 这不是洁癖 —— 同一个 commit 打两次包哈希不同，「可复现」就是句空话。
# ---------------------------------------------------------------------------


def test_scanner_timestamp_and_serial_are_normalized(tmp_path):
    repo = _repo(tmp_path, "typer==0.12\n")
    out = tmp_path / "x.json"
    # 模拟扫描器每次都给新时间戳和随机序列号（cyclonedx-py 真实行为）
    sbom.generate(repo, "python", out, epoch=1700000000)
    first = out.read_text(encoding="utf-8")
    sbom.generate(repo, "python", out, epoch=1700000000)
    assert out.read_text(encoding="utf-8") == first

    data = json.loads(first)
    assert data["metadata"]["timestamp"] == "2023-11-14T22:13:20Z"
    assert data["serialNumber"].startswith("urn:uuid:")


def test_serial_number_changes_when_content_changes(tmp_path):
    """序列号按内容派生：内容一变就得变，否则等于给两份不同的清单发同一个号。"""
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    repo_a = _repo(tmp_path / "a", "typer\n")
    repo_b = _repo(tmp_path / "b", "httpx\n")
    out_a, out_b = tmp_path / "a.json", tmp_path / "b.json"
    sbom.generate(repo_a, "python", out_a, epoch=1700000000)
    sbom.generate(repo_b, "python", out_b, epoch=1700000000)
    assert (
        json.loads(out_a.read_text())["serialNumber"]
        != json.loads(out_b.read_text())["serialNumber"]
    )
