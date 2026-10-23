"""Action 的 shell 层契约：输入归一化、outputs、退出码。

这里不 mock Action 运行时，直接按 GitHub 传环境变量的方式调脚本 ——
脚本里最容易出错的地方（multiline 输入被拆坏、outputs 写错、退出码吞掉）
都只在这一层暴露。
"""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None or shutil.which("git") is None, reason="需要 bash 与 git"
)


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "dist").mkdir(parents=True)
    (repo / "configs").mkdir()
    (repo / "dist" / "app.bin").write_text("artifact")
    (repo / "configs" / "app.yml").write_text("env: prod\n")
    (repo / "requirements.txt").write_text("typer>=0.12\n")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t",
         "commit", "-qm", "init"],
        check=True,
    )
    return repo


def _env(tmp_path: Path, **overrides) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("INPUT_")}
    env.update({
        "PATH": os.environ["PATH"],
        "ACTION_PATH": str(ROOT),
        "REPO_ROOT": str(tmp_path / "repo"),
        "GITHUB_OUTPUT": str(tmp_path / "out.txt"),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md"),
        "INPUT_INCLUDE": "dist/\n# 注释与空行要忽略\n\nconfigs/app.yml\n",
        "INPUT_SBOM": "auto",
        "INPUT_OUT_DIR": str(tmp_path / "out"),
        "INPUT_SIGN": "false",
        "INPUT_ISSUER": "",
        "INPUT_IDENTITY": "",
        "INPUT_BUNDLE_NAME": "",
        "INPUT_EXCLUDE": "",
    })
    env.update(overrides)
    return env


def _outputs(tmp_path: Path) -> dict:
    text = (tmp_path / "out.txt").read_text(encoding="utf-8")
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)


def _run(script: str, env: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(SCRIPTS / script)], capture_output=True, text=True, env=env, check=False,
        cwd=str(Path(env["GITHUB_OUTPUT"]).parent),
    )


def test_pack_writes_outputs_and_ignores_comment_lines(tmp_path):
    _repo(tmp_path)
    proc = _run("action-pack.sh", _env(tmp_path))
    assert proc.returncode == 0, proc.stderr
    out = _outputs(tmp_path)
    bundle = Path(out["bundle-path"])
    assert bundle.is_file() and out["signed"] == "false"
    assert len(out["bundle-sha256"]) == 64
    # 结果文件落在调用方的 cwd 里，方便 Action 之外的脚本复用同一份输出。
    payload = json.loads((tmp_path / "pack-result.json").read_text(encoding="utf-8"))
    assert payload["file_count"] >= 3


def test_pack_is_reproducible_for_the_same_commit(tmp_path):
    _repo(tmp_path)
    first = _run("action-pack.sh", _env(tmp_path, INPUT_OUT_DIR=str(tmp_path / "o1")))
    assert first.returncode == 0, first.stderr
    sha1 = _outputs(tmp_path)["bundle-sha256"]
    second = _run("action-pack.sh", _env(tmp_path, INPUT_OUT_DIR=str(tmp_path / "o2")))
    assert second.returncode == 0, second.stderr
    assert _outputs(tmp_path)["bundle-sha256"] == sha1


def test_pack_without_include_is_usage_failure(tmp_path):
    _repo(tmp_path)
    proc = _run("action-pack.sh", _env(tmp_path, INPUT_INCLUDE="  \n\n"))
    assert proc.returncode == 1
    assert "include 为空" in proc.stdout + proc.stderr


def test_verify_passes_with_matching_anchor(tmp_path):
    _repo(tmp_path)
    assert _run("action-pack.sh", _env(tmp_path)).returncode == 0
    out = _outputs(tmp_path)
    proc = _run("action-verify.sh", _env(
        tmp_path, INPUT_BUNDLE=out["bundle-path"], INPUT_EXPECT_SHA256=out["bundle-sha256"]
    ))
    assert proc.returncode == 0, proc.stdout
    verified = _outputs(tmp_path)
    assert verified["ok"] == "true" and verified["anchored"] == "true"


def test_verify_reports_2_and_never_0_when_anchor_mismatches(tmp_path):
    _repo(tmp_path)
    assert _run("action-pack.sh", _env(tmp_path)).returncode == 0
    out = _outputs(tmp_path)
    proc = _run("action-verify.sh", _env(
        tmp_path, INPUT_BUNDLE=out["bundle-path"], INPUT_EXPECT_SHA256="a" * 64
    ))
    assert proc.returncode == 2
    verified = _outputs(tmp_path)
    assert verified["ok"] == "false" and verified["exit-code"] == "2"


def test_verify_without_anchor_is_not_evidence(tmp_path):
    """包内自洽不算证据 —— 这条底线在 Action 层也不许被放宽。"""
    _repo(tmp_path)
    assert _run("action-pack.sh", _env(tmp_path)).returncode == 0
    out = _outputs(tmp_path)
    proc = _run("action-verify.sh", _env(tmp_path, INPUT_BUNDLE=out["bundle-path"]))
    assert proc.returncode == 2
    assert _outputs(tmp_path)["anchored"] == "false"


def test_anchor_file_is_appended(tmp_path):
    _repo(tmp_path)
    assert _run("action-pack.sh", _env(tmp_path)).returncode == 0
    out = _outputs(tmp_path)
    anchor = tmp_path / "anchor.txt"
    env = _env(tmp_path, INPUT_BUNDLE=out["bundle-path"], INPUT_ANCHOR_FILE=str(anchor))
    assert _run("action-anchor.sh", env).returncode == 0
    assert _run("action-anchor.sh", env).returncode == 0
    lines = [line for line in anchor.read_text(encoding="utf-8").splitlines() if line]
    assert len(lines) == 2 and all(line.startswith(out["bundle-sha256"]) for line in lines)
