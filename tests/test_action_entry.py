"""Action 入口（`python3 -m evidence_pack.action`）的契约。

本仓库只为 GitHub Action 服务，内核只被 shell 步骤以环境变量调起来。
所以这里钉的不是「命令行长什么样」，而是**环境变量进、JSON 出**的约定：
缺哪个输入报什么、退出码怎么分流、失败结论长什么样。

`verify` 恒以 0 退出、判定放在 JSON 的 exit_code 里 —— 这条是 Action 能用
`set -e` 串起后续步骤（登记锚点、上传制品、发评论）的前提。
"""

import hashlib
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


def run(*args, cwd=None, inputs=None, env=None):
    """按 Action 的方式调内核：参数是子命令，输入全走环境变量。"""
    full_env = dict(os.environ)
    # 把上一个用例的 INPUT_* 清干净，别让测试之间互相污染。
    for key in [k for k in full_env if k.startswith("INPUT_")]:
        del full_env[key]
    full_env.pop("SIGSTORE_ID_TOKEN", None)
    full_env["PYTHONPATH"] = SRC
    full_env.update({f"INPUT_{k.upper().replace('-', '_')}": v for k, v in (inputs or {}).items()})
    full_env.update(env or {})
    proc = subprocess.run(
        [sys.executable, "-m", "evidence_pack.action", *args],
        capture_output=True,
        text=True,
        cwd=cwd,
        env=full_env,
    )
    return proc


def payload(proc):
    return json.loads(proc.stdout)


def repo(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.txt").write_text("hello")
    return tmp_path


def pack(tmp_path: Path, **extra):
    """不签名的打包：信任根留给包外锚点，测试不需要 cosign。"""
    proc = run(
        "pack",
        cwd=tmp_path,
        inputs={
            "out-dir": "dist",
            "include": "src",
            "sbom": "none",
            "sign": "false",
            **extra,
        },
        env={"SOURCE_DATE_EPOCH": "1700000000"},
    )
    assert proc.returncode == EXIT_OK, proc.stdout + proc.stderr
    return payload(proc)


def test_pack_emits_structured_result(tmp_path):
    result = pack(repo(tmp_path))
    assert result["ok"] is True
    assert result["exit_code"] == EXIT_OK
    assert result["bundle_name"].endswith(".tar.gz")
    assert Path(result["bundle_path"]).is_file()
    assert result["file_count"] >= 1
    assert result["signed"] is False
    assert result["signature_bundle"] is None


def test_pack_skips_blank_and_comment_lines(tmp_path):
    """多行输入从 YAML 里来：缩进、空行、`#` 注释都不该变成「不存在的路径」。"""
    r = repo(tmp_path)
    result = pack(r, include="\n  # 注释\n  src/  \n\n")
    assert result["file_count"] >= 1


def test_pack_without_include_is_usage_error(tmp_path):
    proc = run(
        "pack",
        cwd=repo(tmp_path),
        inputs={"out-dir": "dist", "sbom": "none", "sign": "false", "include": "  \n# 只有注释\n"},
    )
    assert proc.returncode == EXIT_USAGE
    assert "include" in payload(proc)["error"]


def test_pack_bad_include_is_usage_error(tmp_path):
    proc = run(
        "pack",
        cwd=repo(tmp_path),
        inputs={"out-dir": "dist", "include": "../escape", "sbom": "none", "sign": "false"},
    )
    assert proc.returncode == EXIT_USAGE


def test_pack_signing_without_token_is_usage_error(tmp_path):
    """要签名却没给 token：连签名的料都没有，这是用法错，不是工具坏。"""
    proc = run(
        "pack",
        cwd=repo(tmp_path),
        inputs={"out-dir": "dist", "include": "src", "sbom": "none"},
    )
    assert proc.returncode == EXIT_USAGE
    assert "OIDC" in payload(proc)["error"]


def test_pack_signing_without_cosign_is_tool_failure(tmp_path):
    """有 token 没 cosign 属于工具异常（3）：证据没坏，是流水线坏了。"""
    token = "h." + "p" * 120 + ".s"  # 形状合法的三段式 token，够过本地检查
    proc = run(
        "pack",
        cwd=repo(tmp_path),
        inputs={"out-dir": "dist", "include": "src", "sbom": "none"},
        env={
            "SIGSTORE_ID_TOKEN": token,
            "PATH": "/nonexistent",
            "SOURCE_DATE_EPOCH": "1700000000",
        },
    )
    assert proc.returncode == EXIT_TOOL_FAILURE
    assert "cosign" in payload(proc)["error"]


def _sha(path: str) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def test_verify_exit_code_lives_in_json_not_in_process(tmp_path):
    """verify 恒返回 0：结论在 JSON 里，由 shell 层决定要不要让步骤失败。"""
    bundle = pack(repo(tmp_path))["bundle_path"]
    proc = run("verify", inputs={"bundle": bundle})
    assert proc.returncode == EXIT_OK
    result = payload(proc)
    assert result["ok"] is False
    assert result["exit_code"] == EXIT_EVIDENCE_INVALID
    assert result["error_kind"] == "evidence_invalid"


def test_verify_with_anchor_passes(tmp_path):
    bundle = pack(repo(tmp_path))["bundle_path"]
    result = payload(run("verify", inputs={"bundle": bundle, "expect-sha256": _sha(bundle)}))
    assert result["ok"] is True
    assert result["exit_code"] == EXIT_OK
    assert result["anchored"] is True
    # 成功路径也留键，读的人不必猜哪些键会消失。
    assert result["error"] is None
    assert result["error_kind"] is None


def test_verify_without_bundle_is_usage_error(tmp_path):
    result = payload(run("verify", inputs={}))
    assert result["ok"] is False
    assert result["exit_code"] == EXIT_USAGE
    assert "bundle" in result["error"]


def _sigstore_bundle(tmp_path: Path, tlog: list[dict] | None) -> Path:
    bundle = tmp_path / "ev.sigstore.json"
    bundle.write_text(
        json.dumps(
            {
                "messageSignature": {"messageDigest": {"digest": "AAAA"}},
                "verificationMaterial": {"tlogEntries": tlog or []},
            }
        ),
        encoding="utf-8",
    )
    return bundle


def test_rekor_lists_entries(tmp_path):
    bundle = _sigstore_bundle(
        tmp_path,
        [{"logIndex": "123", "logId": {"keyId": "ab"}, "integratedTime": "1700000000"}],
    )
    result = payload(run("rekor", inputs={"signature-bundle": str(bundle)}))
    assert result["count"] == 1
    assert result["entries"][0]["log_index"] == "123"
    assert result["entries"][0]["log_id"] == "ab"


def test_rekor_without_tlog_is_empty_not_error(tmp_path):
    """无条目不等于解析坏了：它是「这份包不足以证明签名存在过」的事实。"""
    bundle = _sigstore_bundle(tmp_path, None)
    proc = run("rekor", inputs={"signature-bundle": str(bundle)})
    assert proc.returncode == EXIT_OK
    assert payload(proc)["count"] == 0


def test_rekor_on_non_bundle_is_exit_3(tmp_path):
    """不是 bundle 是工具层面的输入错，按契约给 3，不能报成「证据无效」。"""
    junk = tmp_path / "junk.json"
    junk.write_text('{"hello": "world"}', encoding="utf-8")
    proc = run("rekor", inputs={"signature-bundle": str(junk)})
    assert proc.returncode == EXIT_TOOL_FAILURE


def test_rekor_without_input_is_usage_error(tmp_path):
    proc = run("rekor", inputs={})
    assert proc.returncode == EXIT_USAGE


@pytest.mark.parametrize("argv", [[], ["pack", "extra"], ["nope"]])
def test_unknown_subcommand_is_tool_failure(argv):
    """子命令是 shell 与内核之间的固定约定，敲错了当场停住，不猜意图。"""
    proc = run(*argv)
    assert proc.returncode == EXIT_TOOL_FAILURE
    assert payload(proc)["ok"] is False
