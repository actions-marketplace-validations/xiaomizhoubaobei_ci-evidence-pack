"""CLI 层的契约：退出码与输出模式。

这里刻意不用 CliRunner.isolated_filesystem —— 它在新版 typer 里已不存在，
原项目 4/8 测试就是这么红的。用 pytest 的 tmp_path 更稳。
"""

import base64
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


SRC = str(Path(__file__).resolve().parents[1] / "src")


def run(*args, cwd=None, env=None, expect=None):
    # 测试不该依赖「有没有 pip install -e .」：直接把 src 塞进 PYTHONPATH。
    full_env = dict(os.environ, PYTHONPATH=SRC, **(env or {}))
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
                "--sbom", "none", "--no-sign", "--quiet", cwd=r,
                env={"SOURCE_DATE_EPOCH": "1700000000"}, expect=EXIT_OK)
    path = quiet.stdout.strip()
    assert path.endswith(".tar.gz") and Path(path).is_file()

    js = run("pack", "--repo", str(r), "--out", "dist", "--include", "src",
             "--sbom", "none", "--no-sign", "--json", cwd=r,
             env={"SOURCE_DATE_EPOCH": "1700000000"}, expect=EXIT_OK)
    payload = json.loads(js.stdout)
    assert payload["ok"] and payload["file_count"] >= 1


def test_usage_error_exit_code_is_1(tmp_path):
    r = repo(tmp_path)
    run("pack", "--repo", str(r), "--out", "dist", "--include", "../escape",
        "--sbom", "none", cwd=r, expect=EXIT_USAGE)


def test_manifest_only_verify_is_exit_2(tmp_path):
    r = repo(tmp_path)
    out = run("pack", "--repo", str(r), "--out", "dist", "--include", "src",
              "--sbom", "none", "--no-sign", "--quiet", cwd=r,
              env={"SOURCE_DATE_EPOCH": "1700000000"}, expect=EXIT_OK).stdout.strip()
    run("verify", out, "--json", expect=EXIT_EVIDENCE_INVALID)


def test_verify_with_anchor_is_exit_0(tmp_path):
    import hashlib

    r = repo(tmp_path)
    out = run("pack", "--repo", str(r), "--out", "dist", "--include", "src",
              "--sbom", "none", "--no-sign", "--quiet", cwd=r,
              env={"SOURCE_DATE_EPOCH": "1700000000"}, expect=EXIT_OK).stdout.strip()
    sha = hashlib.sha256(Path(out).read_bytes()).hexdigest()
    js = run("verify", out, "--expect-sha256", sha, "--json", expect=EXIT_OK)
    assert json.loads(js.stdout)["anchored"] is True


def test_key_mode_without_cosign_is_exit_3(tmp_path):
    """给了私钥就走 key 模式，PATH 里没有 cosign 属于工具异常（3）。"""
    r = repo(tmp_path)
    js = run("pack", "--repo", str(r), "--out", "dist", "--include", "src",
             "--sbom", "none", "--key", "nonexistent.key", "--json",
             cwd=r, env={"PATH": "/nonexistent", "SOURCE_DATE_EPOCH": "1700000000"},
             expect=EXIT_TOOL_FAILURE)
    assert "cosign" in json.loads(js.stdout)["error"]


def test_verify_usage_error_when_bundle_missing(tmp_path):
    run("verify", str(tmp_path / "nope.tar.gz"), "--json", expect=EXIT_USAGE)


def _pack(tmp_path: Path, *extra: str) -> str:
    r = repo(tmp_path)
    return run("pack", "--repo", str(r), "--out", "dist", "--include", "src",
               "--sbom", "none", "--no-sign", "--quiet", *extra,
               cwd=r, env={"SOURCE_DATE_EPOCH": "1700000000"}, expect=EXIT_OK).stdout.strip()


def test_verify_exit_code_mode_never_fails_the_process(tmp_path):
    """Action 需要「拿到判定再决定」，不能让退出码把后续步骤掐掉。"""
    bundle = _pack(tmp_path)
    js = run("verify", bundle, "--exit-code", "--json", expect=EXIT_OK)
    payload = json.loads(js.stdout)
    assert payload["ok"] is False
    assert payload["exit_code"] == EXIT_EVIDENCE_INVALID
    assert payload["bundle_sha256"], "失败也要带出 sha256，Action 要拿它登记锚点"


def test_verify_exit_code_mode_reports_success(tmp_path):
    import hashlib

    bundle = _pack(tmp_path)
    sha = hashlib.sha256(Path(bundle).read_bytes()).hexdigest()
    js = run("verify", bundle, "--expect-sha256", sha, "--exit-code", "--json", expect=EXIT_OK)
    payload = json.loads(js.stdout)
    assert payload["ok"] is True and payload["exit_code"] == EXIT_OK and payload["anchored"] is True


def test_identity_is_binding_not_sign_request(tmp_path):
    """--identity/--issuer 只是写进包内的期望值，不是签名开关。

    默认签名下没有 OIDC token 就该判用法错（1）—— 错因是缺 token，
    不是「给了 identity 所以顺手签了」。这里用 --no-sign 钉住另一半：
    期望身份存在，但调用方关掉了签名，产物就该是未签名。
    """
    r = repo(tmp_path)
    js = run("pack", "--repo", str(r), "--out", "dist", "--include", "src", "--sbom", "none",
             "--no-sign",
             "--identity", "https://github.com/o/r/.github/workflows/ci.yml@refs/heads/main",
             "--issuer", "https://token.actions.githubusercontent.com",
             "--json", cwd=r, env={"SOURCE_DATE_EPOCH": "1700000000"}, expect=EXIT_OK)
    assert json.loads(js.stdout)["signed"] is False


def test_sign_is_the_default_and_needs_a_token(tmp_path):
    """默认就走签名路径：没给 token 时当场判用法错，不留到 cosign 抛 HTTP 错误。"""
    r = repo(tmp_path)
    js = run("pack", "--repo", str(r), "--out", "dist", "--include", "src", "--sbom", "none",
             "--json", cwd=r, env={"SOURCE_DATE_EPOCH": "1700000000"}, expect=EXIT_USAGE)
    payload = json.loads(js.stdout)
    assert payload["error_kind"] == "usage" and "OIDC" in payload["error"]


def test_no_sign_skips_cosign_entirely(tmp_path):
    """--no-sign 要真的绕开 cosign：环境里没有 cosign 也能出包。"""
    r = repo(tmp_path)
    js = run("pack", "--repo", str(r), "--out", "dist", "--include", "src", "--sbom", "none",
             "--no-sign", "--json", cwd=r,
             env={"PATH": "/nonexistent", "SOURCE_DATE_EPOCH": "1700000000"}, expect=EXIT_OK)
    payload = json.loads(js.stdout)
    assert payload["signed"] is False and payload["signature_mode"] is None


def _fake_oidc_token() -> str:
    """形状合法的假 JWT：三段式、足够长。cosign 缺失的用例不需要它真能验。"""
    header = base64.urlsafe_b64encode(b'{"alg":"RS256","typ":"JWT"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({
        "iss": "https://token.actions.githubusercontent.com",
        "sub": "https://github.com/o/r/.github/workflows/ci.yml@refs/heads/main",
        "aud": "sigstore",
        "pad": "x" * 60,
    }).encode()).decode().rstrip("=")
    return f"{header}.{payload}.{'c2lnbmF0dXJl' * 4}"


def test_missing_cosign_under_default_sign_is_exit_3(tmp_path):
    """默认签名 + 有 token 但环境里没有 cosign：工具异常（3），不是证据有问题。"""
    r = repo(tmp_path)
    js = run("pack", "--repo", str(r), "--out", "dist", "--include", "src", "--sbom", "none",
             "--oidc-token", _fake_oidc_token(), "--json", cwd=r,
             env={"PATH": "/nonexistent", "SOURCE_DATE_EPOCH": "1700000000"},
             expect=EXIT_TOOL_FAILURE)
    assert "cosign" in json.loads(js.stdout)["error"]
