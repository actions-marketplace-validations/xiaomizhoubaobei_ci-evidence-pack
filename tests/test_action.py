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
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
COSIGN = shutil.which("cosign")

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
        # 默认与 action.yml 一致（sign: 'true'）。想不签名必须显式传 "false"，
        # 别把测试的默认值和真实默认值写成两件事。
        "INPUT_SIGN": "true",
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


def _unsigned(tmp_path: Path, **overrides) -> dict:
    """不签名的环境：绝大多数用例只关心打包/验包链路，不该被签名拖下水。"""
    overrides.setdefault("INPUT_SIGN", "false")
    return _env(tmp_path, **overrides)


def test_pack_writes_outputs_and_ignores_comment_lines(tmp_path):
    _repo(tmp_path)
    proc = _run("action-pack.sh", _unsigned(tmp_path))
    assert proc.returncode == 0, proc.stderr
    out = _outputs(tmp_path)
    bundle = Path(out["bundle-path"])
    assert bundle.is_file() and out["signed"] == "false"  # sign: 'false' 时如实不签
    assert len(out["bundle-sha256"]) == 64
    # 结果文件落在调用方的 cwd 里，方便 Action 之外的脚本复用同一份输出。
    payload = json.loads((tmp_path / "pack-result.json").read_text(encoding="utf-8"))
    assert payload["file_count"] >= 3


def test_pack_is_reproducible_for_the_same_commit(tmp_path):
    _repo(tmp_path)
    first = _run("action-pack.sh", _unsigned(tmp_path, INPUT_OUT_DIR=str(tmp_path / "o1")))
    assert first.returncode == 0, first.stderr
    sha1 = _outputs(tmp_path)["bundle-sha256"]
    second = _run("action-pack.sh", _unsigned(tmp_path, INPUT_OUT_DIR=str(tmp_path / "o2")))
    assert second.returncode == 0, second.stderr
    assert _outputs(tmp_path)["bundle-sha256"] == sha1


def test_pack_without_include_is_usage_failure(tmp_path):
    _repo(tmp_path)
    proc = _run("action-pack.sh", _unsigned(tmp_path, INPUT_INCLUDE="  \n\n"))
    assert proc.returncode == 1
    assert "include 为空" in proc.stdout + proc.stderr


def test_verify_passes_with_matching_anchor(tmp_path):
    _repo(tmp_path)
    assert _run("action-pack.sh", _unsigned(tmp_path)).returncode == 0
    out = _outputs(tmp_path)
    proc = _run("action-verify.sh", _unsigned(
        tmp_path, INPUT_BUNDLE=out["bundle-path"], INPUT_EXPECT_SHA256=out["bundle-sha256"]
    ))
    assert proc.returncode == 0, proc.stdout
    verified = _outputs(tmp_path)
    assert verified["ok"] == "true" and verified["anchored"] == "true"


def test_verify_reports_2_and_never_0_when_anchor_mismatches(tmp_path):
    _repo(tmp_path)
    assert _run("action-pack.sh", _unsigned(tmp_path)).returncode == 0
    out = _outputs(tmp_path)
    proc = _run("action-verify.sh", _unsigned(
        tmp_path, INPUT_BUNDLE=out["bundle-path"], INPUT_EXPECT_SHA256="a" * 64
    ))
    assert proc.returncode == 2
    verified = _outputs(tmp_path)
    assert verified["ok"] == "false" and verified["exit-code"] == "2"


def test_verify_without_anchor_is_not_evidence(tmp_path):
    """包内自洽不算证据 —— 这条底线在 Action 层也不许被放宽。"""
    _repo(tmp_path)
    assert _run("action-pack.sh", _unsigned(tmp_path)).returncode == 0
    out = _outputs(tmp_path)
    proc = _run("action-verify.sh", _unsigned(tmp_path, INPUT_BUNDLE=out["bundle-path"]))
    assert proc.returncode == 2
    assert _outputs(tmp_path)["anchored"] == "false"


def test_anchor_file_is_appended(tmp_path):
    _repo(tmp_path)
    assert _run("action-pack.sh", _unsigned(tmp_path)).returncode == 0
    out = _outputs(tmp_path)
    anchor = tmp_path / "anchor.txt"
    env = _unsigned(tmp_path, INPUT_BUNDLE=out["bundle-path"], INPUT_ANCHOR_FILE=str(anchor))
    assert _run("action-anchor.sh", env).returncode == 0
    assert _run("action-anchor.sh", env).returncode == 0
    lines = [line for line in anchor.read_text(encoding="utf-8").splitlines() if line]
    assert len(lines) == 2 and all(line.startswith(out["bundle-sha256"]) for line in lines)


# ---------------------------------------------------------------------------
# action.yml 本身：参数、outputs、步骤接线。这些错不会在脚本测试里暴露，
# 但会让调用方 `uses:` 之后一头雾水（比如 outputs 指向不存在的 step id）。
# ---------------------------------------------------------------------------

def _manifest() -> dict:
    return yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))


def test_action_yml_is_valid_composite():
    data = _manifest()
    assert data["runs"]["using"] == "composite"
    ids = {step.get("id") for step in data["runs"]["steps"] if step.get("id")}
    assert {"pack", "verify"} <= ids
    for step in data["runs"]["steps"]:
        # composite action 里每个 run 步骤都必须显式声明 shell。
        if "run" in step:
            assert step.get("shell"), f"步骤 {step.get('name')} 缺 shell"


def test_every_output_points_at_an_existing_step():
    data = _manifest()
    ids = {step.get("id") for step in data["runs"]["steps"] if step.get("id")}
    for name, spec in data["outputs"].items():
        value = spec["value"]
        ref = value.split("steps.")[1].split(".")[0] if "steps." in value else None
        assert ref in ids, f"output {name} 引用了不存在的 step id：{value}"


def test_every_input_has_description_and_default():
    for name, spec in _manifest()["inputs"].items():
        assert spec.get("description"), f"输入 {name} 缺说明"
        if not spec.get("required"):
            assert "default" in spec, f"输入 {name} 非必填但没有 default"


def test_verify_step_can_still_fail_the_job():
    """`continue-on-error` + 自己 exit 的组合：fail-on-invalid=false 才有意义。

    反过来，任何一个让「判定失败」变成绿色结论的写法都是 bug。
    """
    steps = {step.get("id"): step for step in _manifest()["runs"]["steps"] if step.get("id")}
    verify = steps["verify"]
    assert verify.get("continue-on-error") is True
    # 用 JSON 里的判定整体换掉 process 退出码，再由 run 脚本自己决定成败。
    assert "--exit-code" in (SCRIPTS / "action-verify.sh").read_text(encoding="utf-8")
    assert "exit \"$code\"" in verify["run"]


def test_every_output_has_description():
    for name, spec in _manifest()["outputs"].items():
        assert spec.get("description"), f"output {name} 缺说明"


# ---------------------------------------------------------------------------
# 端到端：按 action.yml 的 env 约定，把 pack → verify 串起来跑一遍。
# 这是「开箱即用」最直接的证据 —— 它失败就说明用户 `uses:` 之后也会失败。
# ---------------------------------------------------------------------------

@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    repo = _repo(tmp_path)
    (repo / "dist").mkdir(exist_ok=True)
    (repo / "dist" / "bundle.bin").write_text("built")
    return repo


def _action_env(workspace: Path, **inputs: str) -> dict:
    # 给一个干净环境：不继承 INPUT_*，免得本机残留变量把结论带偏。
    base = {
        "PATH": os.environ["PATH"],
        "HOME": os.environ.get("HOME", "/tmp"),
        "ACTION_PATH": str(ROOT),
        "REPO_ROOT": str(workspace),
        "GITHUB_OUTPUT": str(workspace.parent / "gh-output.txt"),
        "GITHUB_STEP_SUMMARY": str(workspace.parent / "gh-summary.md"),
        "INPUT_INCLUDE": "dist\nconfigs\n",
        "INPUT_EXCLUDE": "",
        "INPUT_SBOM": "none",
        "INPUT_OUT_DIR": "_evidence",
        "INPUT_BUNDLE_NAME": "",
        # 与 action.yml 的默认保持一致：默认签名。不签的用例显式传 "false"。
        "INPUT_SIGN": "true",
        "INPUT_COSIGN_KEY": "",
        "INPUT_ARTIFACT_NAME": "",
        "INPUT_IDENTITY": "",
        "INPUT_ISSUER": "",
    }
    base.update({k: v for k, v in inputs.items() if v is not None})
    return base


def _gh_outputs(path: Path) -> dict:
    if not path.is_file():
        return {}
    return dict(
        line.split("=", 1) for line in path.read_text(encoding="utf-8").splitlines() if "=" in line
    )


def _call(script: str, env: dict, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(SCRIPTS / script)], capture_output=True, text=True, env=env, cwd=str(cwd),
        check=False, stdin=subprocess.DEVNULL,
    )


def test_repo_root_is_really_used_as_repo(workspace):
    """REPO_ROOT 必须真的被当成 --repo 传下去。

    Action 里 cwd 是 ${GITHUB_WORKSPACE}，脚本里再用相对路径 '.' 拼出来的
    --exclude 会落到 runner 的临时目录，进而让打包整体失败。
    """
    subdir = workspace / "sub"
    subdir.mkdir()
    proc = _call("action-pack.sh", _action_env(workspace, INPUT_SIGN="false"), cwd=subdir)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = _gh_outputs(workspace.parent / "gh-output.txt")
    assert Path(out["bundle-path"]).parent == workspace / "_evidence"


def test_default_excludes_still_pack_the_requested_dirs(workspace):
    """默认排除名单里有 dist，而 dist 恰恰是最常被 include 的目录。"""
    proc = _call("action-pack.sh", _action_env(workspace, INPUT_SIGN="false"), cwd=workspace)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    result = json.loads((workspace / "pack-result.json").read_text(encoding="utf-8"))
    assert result["file_count"] >= 4  # git.json / metadata 等 + 三个 artifacts


def test_unsignable_keyless_fails_fast_with_3(workspace):
    """默认签名、但没有私钥也没有 OIDC token：该立刻报清楚，而不是等 cosign 炸。"""
    proc = _call("action-pack.sh", _action_env(workspace), cwd=workspace)
    assert proc.returncode == 3
    assert "id-token" in proc.stdout + proc.stderr


def test_sign_defaults_to_true_in_the_manifest():
    """签名是默认动作这件事必须落在 action.yml 上，而不只是脚本里的兜底。"""
    assert _manifest()["inputs"]["sign"]["default"] == "true"


def test_pack_then_verify_roundtrip(workspace):
    # 不签名的那条路径：信任根只能来自包外锚点，所以 verify 必须带 expect-sha256。
    assert _call(
        "action-pack.sh", _action_env(workspace, INPUT_SIGN="false"), cwd=workspace
    ).returncode == 0
    out = _gh_outputs(workspace.parent / "gh-output.txt")
    env = _action_env(
        workspace,
        INPUT_SIGN="false",
        INPUT_BUNDLE=out["bundle-path"],
        INPUT_SIGNATURE_BUNDLE="",
        INPUT_COSIGN_PUBLIC_KEY="",
        INPUT_EXPECT_SHA256=out["bundle-sha256"],
        INPUT_EXPECT_REPO="",
    )
    proc = _call("action-verify.sh", env, cwd=workspace)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    verified = _gh_outputs(workspace.parent / "gh-output.txt")
    assert verified["ok"] == "true" and verified["exit-code"] == "0"


@pytest.mark.skipif(COSIGN is None, reason="需要 cosign")
def test_key_mode_sign_and_verify_through_action(workspace, tmp_path):
    """Action 的 key 模式：pack 用私钥签名，verify 用公钥验签。

    这里给的公钥与私钥是两把不同的文件 —— 这正是旧 Action 缺的那个输入。
    """
    key_prefix = tmp_path / "cosign"
    # 口令要走子进程的环境变量：Action 里由 CI 注入 COSIGN_PASSWORD。
    env = dict(os.environ, COSIGN_PASSWORD="test-only")
    made = subprocess.run(
        [COSIGN, "generate-key-pair", "--output-key-prefix", str(key_prefix)],
        capture_output=True, text=True, env=env, check=False, stdin=subprocess.DEVNULL,
    )
    assert made.returncode == 0, made.stderr

    packed = _call(
        "action-pack.sh",
        _action_env(
            workspace,
            INPUT_SIGN="true",
            INPUT_COSIGN_KEY=str(key_prefix) + ".key",
            COSIGN_PASSWORD="test-only",
        ),
        cwd=workspace,
    )
    assert packed.returncode == 0, packed.stdout + packed.stderr
    out = _gh_outputs(workspace.parent / "gh-output.txt")
    assert out["signed"] == "true" and out["signature-mode"] == "key"
    assert Path(out["signature-bundle"]).is_file()

    verified = _call(
        "action-verify.sh",
        _action_env(
            workspace,
            INPUT_BUNDLE=out["bundle-path"],
            INPUT_SIGNATURE_BUNDLE=out["signature-bundle"],
            INPUT_COSIGN_PUBLIC_KEY=str(key_prefix) + ".pub",
            INPUT_EXPECT_SHA256=out["bundle-sha256"],
            INPUT_EXPECT_REPO="",
        ),
        cwd=workspace,
    )
    assert verified.returncode == 0, verified.stdout + verified.stderr
    result = _gh_outputs(workspace.parent / "gh-output.txt")
    assert result["signature-verified"] == "true"


@pytest.mark.skipif(COSIGN is None, reason="需要 cosign")
def test_signature_without_public_key_is_usage_error_not_green(workspace, tmp_path):
    """有签名 bundle 但没给公钥：旧实现会走进 keyless 分支报用法错 —— 那没错，
    但报得太晦涩。这里只钉住「不许判绿」。"""
    key_prefix = tmp_path / "cosign"
    env = dict(os.environ, COSIGN_PASSWORD="test-only")
    subprocess.run(
        [COSIGN, "generate-key-pair", "--output-key-prefix", str(key_prefix)],
        capture_output=True, text=True, env=env, check=False, stdin=subprocess.DEVNULL,
    )
    packed = _call(
        "action-pack.sh",
        _action_env(
            workspace,
            INPUT_SIGN="true",
            INPUT_COSIGN_KEY=str(key_prefix) + ".key",
            COSIGN_PASSWORD="test-only",
        ),
        cwd=workspace,
    )
    assert packed.returncode == 0, packed.stdout + packed.stderr
    out = _gh_outputs(workspace.parent / "gh-output.txt")

    verified = _call(
        "action-verify.sh",
        _action_env(
            workspace,
            INPUT_BUNDLE=out["bundle-path"],
            INPUT_SIGNATURE_BUNDLE=out["signature-bundle"],
            INPUT_COSIGN_PUBLIC_KEY="",
            INPUT_EXPECT_SHA256=out["bundle-sha256"],
            INPUT_EXPECT_REPO="",
        ),
        cwd=workspace,
    )
    assert verified.returncode != 0


def test_anchor_then_upload_paths_are_real(workspace):
    """上传那一步列的三个路径必须都是真实文件，否则 artifact 会静默缺件。"""
    assert _call(
        "action-pack.sh", _action_env(workspace, INPUT_SIGN="false"), cwd=workspace
    ).returncode == 0
    out = _gh_outputs(workspace.parent / "gh-output.txt")
    anchor = workspace / "_evidence" / "anchor.txt"
    anchored = _call(
        "action-anchor.sh",
        _action_env(workspace, INPUT_BUNDLE=out["bundle-path"], INPUT_ANCHOR_FILE=str(anchor)),
        cwd=workspace,
    )
    assert anchored.returncode == 0, anchored.stdout + anchored.stderr
    anchor_out = _gh_outputs(workspace.parent / "gh-output.txt")
    assert Path(anchor_out["anchor-file"]).is_absolute()
    assert Path(anchor_out["anchor-file"]).is_file()


# ---------------------------------------------------------------------------
# 示例工作流：用户是照抄这些文件用的，所以它们本身也得当被测代码对待。
# 一个拼错 input 名的示例 = 用户粘过去就红，比没有示例更糟。
# ---------------------------------------------------------------------------

EXAMPLES = sorted((ROOT / "examples").glob("*.yml"))


def test_examples_exist_and_parse():
    assert EXAMPLES, "examples/ 下至少要有一份能照抄的工作流"
    for path in EXAMPLES:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert "jobs" in data, f"{path.name} 没有 jobs"


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_example_inputs_are_real_action_inputs(path):
    """示例里用的 input 名必须真的在 action.yml 里存在。

    这类错误最容易漏：YAML 合法、Action 也不会报错，
    GitHub 只是把一个不认识的 input 默默忽略掉，然后你对着
    「为什么 identity 没生效」查半天。
    """
    declared = set(_manifest()["inputs"])
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    used: set[str] = set()
    for job in data["jobs"].values():
        for step in job.get("steps", []):
            if "XMZZUZHI/Github/ci-evidence-pack" in str(step.get("uses", "")):
                used |= set((step.get("with") or {}))
    unknown = used - declared
    assert not unknown, f"{path.name} 用了 action.yml 里没有的 input：{sorted(unknown)}"


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_example_outputs_are_real_action_outputs(path):
    """引用 output 的写错名字同样会静默变成空字符串。"""
    declared = set(_manifest()["outputs"])
    text = path.read_text(encoding="utf-8")
    import re

    used = set(re.findall(r"steps\.[A-Za-z0-9_-]+\.outputs\.([A-Za-z0-9_-]+)", text))
    # 只看指向 evidence-pack 那个 step 的引用（其它 step 的 output 不归这里管）
    ep_ids = set()
    data = yaml.safe_load(text)
    for job in data["jobs"].values():
        for step in job.get("steps", []):
            if "XMZZUZHI/Github/ci-evidence-pack" in str(step.get("uses", "")):
                if step.get("id"):
                    ep_ids.add(step["id"])
    used_ep = {
        m for m in re.findall(r"steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)", text)
        if m[0] in ep_ids
    }
    unknown = {o for _, o in used_ep} - declared
    assert not unknown, f"{path.name} 引用了不存在的 output：{sorted(unknown)}"
