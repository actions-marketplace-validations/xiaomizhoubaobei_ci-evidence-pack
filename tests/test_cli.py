"""CLI 层的契约：退出码与输出模式。

这里刻意不用 CliRunner.isolated_filesystem —— 它在新版 typer 里已不存在，
原项目 4/8 测试就是这么红的。用 pytest 的 tmp_path 更稳。
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from evidence_pack.errors import (
    EXIT_EVIDENCE_INVALID,
    EXIT_OK,
    EXIT_TOOL_FAILURE,
    EXIT_USAGE,
)


def run(*args, cwd=None, env=None, expect=None):
    full_env = dict(os.environ, **(env or {}))
    proc = subprocess.run(
        [sys.executable, "-m", "evidence_pack.cli", *args],
        capture_output=True, text=True, cwd=cwd, env=full_env,
    )
    if expect is not None:
        assert proc.returncode == expect, f"{proc.returncode=} {proc.stdout=} {proc.stderr=}"
    return proc


def repo(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.txt").write_text("hello")
    return tmp_path


def test_pack_json_and_quiet(tmp_path):
    r = repo(tmp_path)
    quiet = run("pack", "--repo", str(r), "--out", "dist", "--include", "src",
                "--sbom", "none", "--quiet", cwd=r, env={"SOURCE_DATE_EPOCH": "1700000000"},
                expect=EXIT_OK)
    path = quiet.stdout.strip()
    assert path.endswith(".tar.gz") and Path(path).is_file()

    js = run("pack", "--repo", str(r), "--out", "dist", "--include", "src",
             "--sbom", "none", "--json", cwd=r, env={"SOURCE_DATE_EPOCH": "1700000000"},
             expect=EXIT_OK)
    payload = json.loads(js.stdout)
    assert payload["ok"] and payload["file_count"] >= 1


def test_usage_error_exit_code_is_1(tmp_path):
    r = repo(tmp_path)
    run("pack", "--repo", str(r), "--out", "dist", "--include", "../escape",
        "--sbom", "none", cwd=r, expect=EXIT_USAGE)


def test_manifest_only_verify_is_exit_2(tmp_path):
    r = repo(tmp_path)
    out = run("pack", "--repo", str(r), "--out", "dist", "--include", "src",
              "--sbom", "none", "--quiet", cwd=r, env={"SOURCE_DATE_EPOCH": "1700000000"},
              expect=EXIT_OK).stdout.strip()
    run("verify", out, "--json", expect=EXIT_EVIDENCE_INVALID)


def test_verify_with_anchor_is_exit_0(tmp_path):
    import hashlib

    r = repo(tmp_path)
    out = run("pack", "--repo", str(r), "--out", "dist", "--include", "src",
              "--sbom", "none", "--quiet", cwd=r, env={"SOURCE_DATE_EPOCH": "1700000000"},
              expect=EXIT_OK).stdout.strip()
    sha = hashlib.sha256(Path(out).read_bytes()).hexdigest()
    js = run("verify", out, "--expect-sha256", sha, "--json", expect=EXIT_OK)
    assert json.loads(js.stdout)["anchored"] is True


def test_missing_cosign_is_exit_3(tmp_path):
    r = repo(tmp_path)
    out = run("pack", "--repo", str(r), "--out", "dist", "--include", "src",
              "--sbom", "none", "--quiet", cwd=r, env={"SOURCE_DATE_EPOCH": "1700000000"},
              expect=EXIT_OK).stdout.strip()
    # 只要一个 key 参数就会触发签名路径；PATH 里没有 cosign
    js = run("pack", "--repo", str(r), "--out", "dist2", "--include", "src",
             "--sbom", "none", "--key", "nonexistent.key", "--json",
             cwd=r, env={"PATH": "/nonexistent", "SOURCE_DATE_EPOCH": "1700000000"},
             expect=EXIT_TOOL_FAILURE)
    assert "cosign" in json.loads(js.stdout)["error"]


def test_verify_usage_error_when_bundle_missing(tmp_path):
    run("verify", str(tmp_path / "nope.tar.gz"), "--json", expect=EXIT_USAGE)
