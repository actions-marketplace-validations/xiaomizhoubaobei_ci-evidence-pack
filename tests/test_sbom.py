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
    repo = _repo(tmp_path, "typer>=0.12,<1.0\npytest==8.3.0  # 测试用\n-r other.txt\n-e .\n")
    assert sbom.generate(repo, "auto", out) == "python"
    data = json.loads(out.read_text(encoding="utf-8"))
    names = [c["name"] for c in data["components"]]
    assert names == ["pytest", "typer"]
    assert {c["name"]: c["version"] for c in data["components"]}["pytest"] == "8.3.0"


def test_python_project_without_scanner_or_requirements_is_exit_3(tmp_path, monkeypatch):
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
