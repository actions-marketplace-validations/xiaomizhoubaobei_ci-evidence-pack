from pathlib import Path

import pytest

from evidence_pack.collect import Collector
from evidence_pack.errors import UsageError


def _repo(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("a")
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "old.tar.gz").write_text("old bundle")
    return tmp_path


def test_relative_include_lands_at_same_relative_path(tmp_path):
    repo = _repo(tmp_path)
    stage = tmp_path / "stage"
    stage.mkdir()
    result = Collector(repo, repo / "dist").collect(["src"], stage)
    assert result.rel_paths == ["src/a.py"]
    assert (stage / "src" / "a.py").is_file()


def test_include_outside_repo_is_an_error_not_silently_dropped(tmp_path):
    repo = _repo(tmp_path)
    outside = tmp_path.parent / "outside-secret"
    outside.mkdir(exist_ok=True)
    (outside / "secret.txt").write_text("s")
    stage = tmp_path / "stage"
    stage.mkdir()
    with pytest.raises(UsageError, match="越界"):
        Collector(repo, repo / "dist").collect(["../outside-secret"], stage)


def test_include_dot_is_rejected(tmp_path):
    repo = _repo(tmp_path)
    stage = tmp_path / "stage"
    stage.mkdir()
    with pytest.raises(UsageError, match=r"--include \."):
        Collector(repo, repo / "dist").collect(["."], stage)


def test_output_dir_itself_cannot_be_included(tmp_path):
    repo = _repo(tmp_path)
    stage = tmp_path / "stage"
    stage.mkdir()
    with pytest.raises(UsageError, match="输出目录自身"):
        Collector(repo, repo / "dist").collect(["dist"], stage)


def test_missing_include_is_an_error(tmp_path):
    repo = _repo(tmp_path)
    stage = tmp_path / "stage"
    stage.mkdir()
    with pytest.raises(UsageError, match="不存在"):
        Collector(repo, repo / "dist").collect(["nope"], stage)


def test_default_excludes_skip_git_and_node_modules(tmp_path):
    repo = _repo(tmp_path)
    (repo / ".git").mkdir()
    (repo / ".git" / "config").write_text("x")
    (repo / "node_modules").mkdir()
    (repo / "node_modules" / "x.js").write_text("x")
    stage = tmp_path / "stage"
    stage.mkdir()
    result = Collector(repo, repo / "dist").collect(["src"], stage)
    assert all(not p.startswith((".git", "node_modules")) for p in result.rel_paths)


def test_explicit_include_wins_over_default_excludes(tmp_path):
    """`--include dist` 是最常见的用法，默认排除名单不该把它挡死。"""
    repo = _repo(tmp_path)
    stage = tmp_path / "stage"
    stage.mkdir()
    result = Collector(repo, tmp_path / "out").collect(["dist"], stage)
    assert result.rel_paths == ["dist/old.tar.gz"]


def test_nested_excluded_dir_inside_included_root_is_still_skipped(tmp_path):
    repo = _repo(tmp_path)
    (repo / "src" / "node_modules").mkdir()
    (repo / "src" / "node_modules" / "x.js").write_text("x")
    stage = tmp_path / "stage"
    stage.mkdir()
    result = Collector(repo, tmp_path / "out").collect(["src"], stage)
    assert result.rel_paths == ["src/a.py"]


def test_git_dir_is_never_collected_even_if_named(tmp_path):
    repo = _repo(tmp_path)
    (repo / ".git").mkdir()
    (repo / ".git" / "config").write_text("x")
    stage = tmp_path / "stage"
    stage.mkdir()
    with pytest.raises(UsageError, match="不可收范围"):
        Collector(repo, tmp_path / "out").collect([".git"], stage)
