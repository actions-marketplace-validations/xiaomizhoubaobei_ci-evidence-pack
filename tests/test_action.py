"""Action 的 shell 层契约：输入归一化、outputs、退出码。

这里不 mock Action 运行时，直接按 GitHub 传环境变量的方式调脚本 ——
脚本里最容易出错的地方（multiline 输入被拆坏、outputs 写错、退出码吞掉）
都只在这一层暴露。
"""

import http.server
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
COSIGN = shutil.which("cosign")

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None or shutil.which("git") is None,
    reason="需要 bash 与 git",
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
        # commit.gpgsign=false 是必须的：AGENTS.md 要求提交签名，开发机 / 镜像里
        # 常常全局开了 commit.gpgsign，夹具用临时身份造的仓库没有对应私钥，
        # 一提交就 gpg failed to sign the data —— 那不是被测代码的问题，
        # 却会让每个人的本地跑出一片红。
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.email=t@t",
            "-c",
            "user.name=t",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "init",
        ],
        check=True,
    )
    return repo


# 宿主环境里与 OIDC 有关的变量：干净开发机上没有，GitHub runner 上一定有。
# 留着它们，「不签名」的用例会被脚本判成「有 OIDC、按默认签名走」（脚本的判定
# 是「有没有签发方」，而 runner 上还额外给了换 token 的凭据），于是一批本该
# 走 --no-sign 的断言在 CI 上集体变红；换 token 的用例也会拿到真实端点。
# 这类变量一律由用例显式给，不从宿主继承。
_HOST_OIDC_VARS = (
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "SIGSTORE_ID_TOKEN",
    "INPUT_SIGN",
    "INPUT_IDENTITY",
    "INPUT_ISSUER",
    "SOURCE_DATE_EPOCH",
)


def _env(tmp_path: Path, **overrides) -> dict:
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("INPUT_") and k not in _HOST_OIDC_VARS
    }
    env.update(
        {
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
        }
    )
    env.update(overrides)
    return env


def _outputs(tmp_path: Path) -> dict:
    text = (tmp_path / "out.txt").read_text(encoding="utf-8")
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)


def _run(script: str, env: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(SCRIPTS / script)],
        capture_output=True,
        text=True,
        env=env,
        check=False,
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
    first = _run(
        "action-pack.sh", _unsigned(tmp_path, INPUT_OUT_DIR=str(tmp_path / "o1"))
    )
    assert first.returncode == 0, first.stderr
    sha1 = _outputs(tmp_path)["bundle-sha256"]
    second = _run(
        "action-pack.sh", _unsigned(tmp_path, INPUT_OUT_DIR=str(tmp_path / "o2"))
    )
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
    proc = _run(
        "action-verify.sh",
        _unsigned(
            tmp_path,
            INPUT_BUNDLE=out["bundle-path"],
            INPUT_EXPECT_SHA256=out["bundle-sha256"],
        ),
    )
    assert proc.returncode == 0, proc.stdout
    verified = _outputs(tmp_path)
    assert verified["ok"] == "true" and verified["anchored"] == "true"


def test_verify_reports_2_and_never_0_when_anchor_mismatches(tmp_path):
    _repo(tmp_path)
    assert _run("action-pack.sh", _unsigned(tmp_path)).returncode == 0
    out = _outputs(tmp_path)
    proc = _run(
        "action-verify.sh",
        _unsigned(
            tmp_path, INPUT_BUNDLE=out["bundle-path"], INPUT_EXPECT_SHA256="a" * 64
        ),
    )
    assert proc.returncode == 2
    verified = _outputs(tmp_path)
    assert verified["ok"] == "false" and verified["exit-code"] == "2"


def test_verify_without_anchor_is_not_evidence(tmp_path):
    """包内自洽不算证据 —— 这条底线在 Action 层也不许被放宽。"""
    _repo(tmp_path)
    assert _run("action-pack.sh", _unsigned(tmp_path)).returncode == 0
    out = _outputs(tmp_path)
    proc = _run(
        "action-verify.sh", _unsigned(tmp_path, INPUT_BUNDLE=out["bundle-path"])
    )
    assert proc.returncode == 2
    assert _outputs(tmp_path)["anchored"] == "false"


def test_anchor_file_is_appended(tmp_path):
    _repo(tmp_path)
    assert _run("action-pack.sh", _unsigned(tmp_path)).returncode == 0
    out = _outputs(tmp_path)
    anchor = tmp_path / "anchor.txt"
    env = _unsigned(
        tmp_path, INPUT_BUNDLE=out["bundle-path"], INPUT_ANCHOR_FILE=str(anchor)
    )
    assert _run("action-anchor.sh", env).returncode == 0
    assert _run("action-anchor.sh", env).returncode == 0
    lines = [line for line in anchor.read_text(encoding="utf-8").splitlines() if line]
    assert len(lines) == 2 and all(
        line.startswith(out["bundle-sha256"]) for line in lines
    )


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
    steps = {
        step.get("id"): step for step in _manifest()["runs"]["steps"] if step.get("id")
    }
    verify = steps["verify"]
    assert verify.get("continue-on-error") is True
    # 用 JSON 里的判定整体换掉 process 退出码，再由 run 脚本自己决定成败。
    assert "--exit-code" in (SCRIPTS / "action-verify.sh").read_text(encoding="utf-8")
    assert 'exit "$code"' in verify["run"]


def _step_by_name(fragment: str) -> dict:
    for step in _manifest()["runs"]["steps"]:
        if fragment in str(step.get("name", "")):
            return step
    raise AssertionError(f"action.yml 里找不到步骤：{fragment}")


def test_cosign_install_failure_is_caught_by_a_later_step():
    """安装失败要有人接住，而不是让现场只剩一行平台级 step failed。

    这条守的是本次修的 bug：安装步骤带 continue-on-error 却不带 id，
    结论就没人读得到 —— 打包内核只剩一句退出码 3，
    「谁没装上」变成一个要花一小时去猜的问题。
    """
    install = _step_by_name("安装 cosign")
    assert install.get("id"), "安装步骤必须有 id，否则 outcome 无人可读"
    assert install.get("continue-on-error") is True
    # 判据必须与 action-pack.sh 一致：小写 'false' 才算不签。
    assert install["if"] == "inputs.sign != 'false'"

    check = _step_by_name("自检 cosign")
    assert check.get("shell") == "bash"
    # installer 失败会让依赖它的步骤按 success() 被跳过 —— 那正是最需要自检的一刻，
    # 所以判据必须显式带上 always()。
    # 先取变量再断言：行宽留给提示语，别让 black 把断言拆成两行。
    condition = str(check.get("if", ""))
    assert "always()" in condition, "自检步骤必须带 always()，否则安装失败时会被跳过"
    # 读得到安装结论：没有 id 就写不出这个引用。
    assert any(
        f"steps.{install['id']}." in v for v in (check.get("env") or {}).values()
    ), "自检步骤必须引用安装步骤的 outcome / outputs"
    # 缺 cosign 是工具异常（3），不是证据无效（2）。
    assert "exit 3" in check["run"]


def test_oidc_probe_warns_but_never_fails_the_job():
    """自托管 / sign: 'false' 不该被拦：只警告，不 exit 非零。"""
    probe = _step_by_name("自检 OIDC")
    assert "ACTIONS_ID_TOKEN_REQUEST_URL" in probe["run"]
    assert "::warning" in probe["run"]
    assert "::error" not in probe["run"]
    assert not re.search(r"^\s*exit\s+[1-9]", probe["run"], re.M)


def test_examples_pin_action_to_a_full_sha():
    """浮动引用会让「修没修好」永远说不清：一律钉 40 位 SHA。"""
    for path in EXAMPLES + [ROOT / "README.md", ROOT / "docs-usage.md"]:
        text = path.read_text(encoding="utf-8")
        for use in re.findall(r"ci-evidence-pack@(\S+)", text):
            # 先取变量再断言：中文提示语一行放不下，折行会难看。
            ref = use
            assert re.fullmatch(
                r"[0-9a-f]{40}", ref
            ), f"{path.name} 用了浮动引用：@{ref}"


def test_references_point_at_the_github_repo():
    """owner 路径必须是在 GitHub 上真实存在的那一个。

    仓库的 origin 在 CNB（cnb.cool/XMZZUZHI/...），而 Action 示例是给
    GitHub 用户照抄的：照着写 CNB 路径，`uses:` 在 GitHub 上直接找不到仓库。
    版本一律钉 40 位 SHA 而不是 tag —— tag 可被移动，SHA 不会。
    """
    for path in EXAMPLES + [ROOT / "README.md", ROOT / "docs-usage.md"]:
        text = path.read_text(encoding="utf-8")
        for owner in re.findall(
            r"(?<![\w./-])([\w.-]+/[\w.-]+)/ci-evidence-pack", text
        ):
            assert owner == "xiaomizhoubaobei", (
                f"{path.name} 指向了 {owner}/ci-evidence-pack，"
                "GitHub 侧是 xiaomizhoubaobei/ci-evidence-pack"
            )


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
        line.split("=", 1)
        for line in path.read_text(encoding="utf-8").splitlines()
        if "=" in line
    )


def _call(script: str, env: dict, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(SCRIPTS / script)],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(cwd),
        check=False,
        stdin=subprocess.DEVNULL,
    )


def test_repo_root_is_really_used_as_repo(workspace):
    """REPO_ROOT 必须真的被当成 --repo 传下去。

    Action 里 cwd 是 ${GITHUB_WORKSPACE}，脚本里再用相对路径 '.' 拼出来的
    --exclude 会落到 runner 的临时目录，进而让打包整体失败。
    """
    subdir = workspace / "sub"
    subdir.mkdir()
    proc = _call(
        "action-pack.sh", _action_env(workspace, INPUT_SIGN="false"), cwd=subdir
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = _gh_outputs(workspace.parent / "gh-output.txt")
    assert Path(out["bundle-path"]).parent == workspace / "_evidence"


def test_default_excludes_still_pack_the_requested_dirs(workspace):
    """默认排除名单里有 dist，而 dist 恰恰是最常被 include 的目录。"""
    proc = _call(
        "action-pack.sh", _action_env(workspace, INPUT_SIGN="false"), cwd=workspace
    )
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
    assert (
        _call(
            "action-pack.sh", _action_env(workspace, INPUT_SIGN="false"), cwd=workspace
        ).returncode
        == 0
    )
    out = _gh_outputs(workspace.parent / "gh-output.txt")
    env = _action_env(
        workspace,
        INPUT_SIGN="false",
        INPUT_BUNDLE=out["bundle-path"],
        INPUT_SIGNATURE_BUNDLE="",
        INPUT_EXPECT_SHA256=out["bundle-sha256"],
        INPUT_EXPECT_REPO="",
    )
    proc = _call("action-verify.sh", env, cwd=workspace)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    verified = _gh_outputs(workspace.parent / "gh-output.txt")
    assert verified["ok"] == "true" and verified["exit-code"] == "0"


def test_action_has_no_private_key_inputs():
    """私钥 fallback 必须从 Action 的契约里消失，而不只是不再被读取。

    留着 `cosign-key` 输入是最糟的一种：调用方以为配了就换了信任根，
    Action 却根本不看它 —— 于是签出来的仍然是 OIDC 身份，而没人会去核对。
    """
    inputs = _manifest()["inputs"]
    assert "cosign-key" not in inputs
    assert "cosign-public-key" not in inputs


def test_action_never_mentions_private_key_paths():
    """脚本里也不许有「有私钥就用私钥」的隐式分支。"""
    for name in ("action-pack.sh", "action-verify.sh"):
        text = (SCRIPTS / name).read_text(encoding="utf-8")
        assert "INPUT_COSIGN_KEY" not in text, f"{name} 仍在读私钥输入"
        assert "--verify-key" not in text, f"{name} 仍在用公钥验签"


def test_anchor_then_upload_paths_are_real(workspace):
    """上传那一步列的三个路径必须都是真实文件，否则 artifact 会静默缺件。"""
    assert (
        _call(
            "action-pack.sh", _action_env(workspace, INPUT_SIGN="false"), cwd=workspace
        ).returncode
        == 0
    )
    out = _gh_outputs(workspace.parent / "gh-output.txt")
    anchor = workspace / "_evidence" / "anchor.txt"
    anchored = _call(
        "action-anchor.sh",
        _action_env(
            workspace, INPUT_BUNDLE=out["bundle-path"], INPUT_ANCHOR_FILE=str(anchor)
        ),
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

    # 只看指向 evidence-pack 那个 step 的引用（其它 step 的 output 不归这里管）
    ep_ids = set()
    data = yaml.safe_load(text)
    for job in data["jobs"].values():
        for step in job.get("steps", []):
            if "XMZZUZHI/Github/ci-evidence-pack" in str(step.get("uses", "")):
                if step.get("id"):
                    ep_ids.add(step["id"])
    used_ep = {
        m
        for m in re.findall(r"steps\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)", text)
        if m[0] in ep_ids
    }
    unknown = {o for _, o in used_ep} - declared
    assert not unknown, f"{path.name} 引用了不存在的 output：{sorted(unknown)}"


# ---------------------------------------------------------------------------
# 默认签名之后，示例与脚本之间的「开关怎么传」变成最容易出事的一段：
# 少一个 token 就静默不签，多一个 False 就当场判 3。
# ---------------------------------------------------------------------------


def test_missing_oidc_endpoint_is_3_and_names_the_permission(workspace):
    """既没私钥、也没有换 token 的凭据：3，且报错要点名 id-token。"""
    proc = _call("action-pack.sh", _action_env(workspace), cwd=workspace)
    assert proc.returncode == 3
    assert "id-token" in proc.stdout + proc.stderr


def test_oidc_token_is_exchanged_before_signing(workspace, tmp_path):
    """托管 runner 上就绪的是「换 token 的凭据」，不是 token 本体。

    这一步曾是缺口：脚本只判断凭据存在与否就放行，真去签名时却没人把
    token 取回来 —— 于是 job 明明开了 id-token: write，仍然在 Fulcio 那里 401。
    这里起一个假的 OIDC 端点，确认换出来的 token 真的经 SIGSTORE_ID_TOKEN
    传到了内核（用假 cosign 记录环境变量）。
    """
    import threading

    fake_token = "h." + "p" * 120 + ".s"  # 三段式、长度过 MIN_TOKEN_LEN
    seen: list[str] = []  # 端点被真实敲过的记录，末尾非空即证明链路通

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler 约定
            assert self.path.endswith("&audience=sigstore"), self.path
            seen.append(self.path)
            body = json.dumps({"value": fake_token}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # 静音
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        env = _action_env(
            workspace,
            INPUT_SIGN="true",
            ACTIONS_ID_TOKEN_REQUEST_URL=f"http://127.0.0.1:{server.server_port}/oidc?x=1",
            ACTIONS_ID_TOKEN_REQUEST_TOKEN="request-token",
        )
        # 假 cosign：记录拿到的 token，并按 keyless 的形态造一份 bundle。
        # 内核会核对 x509 证书链与 tlog 条目（拿不到就该判 3），所以不能只 exit 0。
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        fake = bin_dir / "cosign"
        fake.write_text(
            "#!/bin/sh\n"
            'printf "%s" "${SIGSTORE_ID_TOKEN:-}" > "$CAPTURED_TOKEN"\n'
            'bundle=""\n'
            "while [ $# -gt 0 ]; do\n"
            '  if [ "$1" = "--bundle" ]; then bundle="$2"; shift; fi\n'
            "  shift\n"
            "done\n"
            "cat > \"$bundle\" <<'JSON'\n"
            '{"messageSignature": {"messageDigest": {"algorithm": "SHA2_256", "digest": ""}},\n'
            ' "verificationMaterial": {"x509CertificateChain": {"certificates": '
            '[{"rawBytes": ""}]}, "tlogEntries": [{"logIndex": "1"}]}}\n'
            "JSON\n"
            "exit 0\n",
            encoding="utf-8",
        )
        fake.chmod(0o755)
        env["PATH"] = f"{bin_dir}:{env['PATH']}"
        env["CAPTURED_TOKEN"] = str(tmp_path / "token.txt")

        proc = _call("action-pack.sh", env, cwd=workspace)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert (tmp_path / "token.txt").read_text(encoding="utf-8") == fake_token
        # token 绝不进 argv：命令行里出现它等于把它写进作业日志。
        assert fake_token not in proc.stdout
        # 且这个 token 是本进程从假端点换来的，不是环境里现成的字符串
        assert seen, "假 OIDC 端点没被请求过，说明换 token 这一步没走"
    finally:
        server.shutdown()


def test_oidc_request_failure_is_3_not_2(workspace):
    """换 token 失败属于「流水线坏了」（3），不能糊成「证据无效」（2）。"""
    env = _action_env(
        workspace,
        INPUT_SIGN="true",
        ACTIONS_ID_TOKEN_REQUEST_URL="http://127.0.0.1:1/oidc?x=1",  # 必然连不上
        ACTIONS_ID_TOKEN_REQUEST_TOKEN="request-token",
    )
    proc = _call("action-pack.sh", env, cwd=workspace)
    assert proc.returncode == 3, proc.stdout + proc.stderr
    assert "evidence invalid" not in proc.stdout.lower()


# keyless 换 token：`ACTIONS_ID_TOKEN_REQUEST_TOKEN` 只是换 token 的**凭据**，
# 不是 token 本体。把它当 token 用，就是在 Fulcio 那里换回一个 401 ——
# 现场看起来跟「id-token: write 没开」一模一样，最难查。
# 所以这里起一个假 OIDC 端点 + 假 cosign，把链路钉死。
# ---------------------------------------------------------------------------


def _fake_oidc_server(
    tmp_path: Path, *, ok: bool = True
) -> tuple[http.server.HTTPServer, str]:
    """起一个本地假 OIDC 端点，只认 audience=sigstore。"""
    import threading

    port_holder: dict[str, int] = {}
    seen: dict[str, str] = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - http.server 的接口
            seen["path"] = self.path
            seen["auth"] = self.headers.get("Authorization", "")
            if not ok:
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b'{"message":"denied"}')
                return
            body = json.dumps({"value": _OIDC_TOKEN}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    port_holder["port"] = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    server._seen = seen  # type: ignore[attr-defined]
    return server, f"http://127.0.0.1:{port_holder['port']}"


_OIDC_TOKEN = "h." + "e" * 60 + "." + "s" * 60


def _fake_cosign(tmp_path: Path, *, verify_ok: bool = True) -> Path:
    """假 cosign：sign-blob 时把 SIGSTORE_ID_TOKEN 抄进 bundle，便于断言。

    `verify_ok=False` 时 verify-blob 以非零退出，用来模拟「identity 不符 /
    签名无效」—— 那在 Action 层必须是 2，不能与「工具坏了」的 3 混在一起。
    """
    fake = tmp_path / "fakebin"
    fake.mkdir(exist_ok=True)
    script = fake / "cosign"
    verify_body = (
        "# 状态随目录走：同一个 fakebin 既能签也能验。\n"
        '[ -f "$(dirname "$0")/verify-ok" ] && NPC_VERIFY_OK="$(cat "$(dirname "$0")/verify-ok")"\n'
        'if [ "$1" = "verify-blob" ]; then\n'
        '  if [ "$NPC_VERIFY_OK" = "0" ]; then\n'
        "    echo 'Error: verifying signature: signature does not match' >&2\n"
        "    exit 1\n"
        "  fi\n"
        "  echo 'Verified OK'\n"
        "  exit 0\n"
        "fi\n"
    )
    script.write_text(
        "#!/bin/sh\n"
        "# 只实现 sign-blob / verify-blob：前者把收到的 token 原样写进 bundle。\n"
        + verify_body
        + 'out=""\n'
        'prev=""\n'
        'for a in "$@"; do\n'
        '  [ "$prev" = "--bundle" ] && out="$a"\n'
        '  prev="$a"\n'
        "done\n"
        'cat > "$out" <<JSON\n'
        '{"messageSignature":{"messageDigest":{"digest":"AAAA"}},'
        '"verificationMaterial":{"x509CertificateChain":{"certificates":[{"rawBytes":"QQ=="}]},'
        '"tlogEntries":[{"integratedTime":"1700000000"}]},'
        '"npcToken":"'
        "${SIGSTORE_ID_TOKEN:-}"
        '"}\n'
        "JSON\n"
        "echo 'token-argv-check:' \"$@\" >&2\n"
        "exit 0\n"
    )
    script.chmod(0o755)
    (fake / "verify-ok").write_text("1" if verify_ok else "0", encoding="utf-8")
    return fake


def test_keyless_exchanges_oidc_token_and_never_puts_it_in_argv(workspace, tmp_path):
    """给了签发方就要现换 token，且 token 只走环境变量。"""
    server, url = _fake_oidc_server(tmp_path)
    fake = _fake_cosign(tmp_path)
    try:
        env = _action_env(workspace, INPUT_SIGN="true")
        env.pop("SIGSTORE_ID_TOKEN", None)
        env["ACTIONS_ID_TOKEN_REQUEST_URL"] = url
        env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = "request-token-not-a-jwt"
        env["PATH"] = f"{fake}{os.pathsep}{env['PATH']}"
        proc = _call("action-pack.sh", env, cwd=workspace)
    finally:
        server.shutdown()

    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = _gh_outputs(workspace.parent / "gh-output.txt")
    bundle = json.loads(Path(out["signature-bundle"]).read_text(encoding="utf-8"))
    # 关键：被打进 bundle 的是**换回来的** token，不是那串请求凭据。
    assert bundle["npcToken"] == _OIDC_TOKEN
    # 端点收到的必须是 sigstore audience，否则 Fulcio 不认。
    assert "audience=sigstore" in server._seen["path"]  # type: ignore[attr-defined]
    # token 不出现在进程参数里。
    assert _OIDC_TOKEN not in proc.stdout and _OIDC_TOKEN not in proc.stderr


def test_keyless_without_issuer_fails_with_3(workspace):
    """没有签发方 = 凭据问题 = 3（流水线坏了），不是 2（证据无效）。"""
    env = _action_env(workspace, INPUT_SIGN="true")
    env.pop("SIGSTORE_ID_TOKEN", None)
    env.pop("ACTIONS_ID_TOKEN_REQUEST_URL", None)
    env.pop("ACTIONS_ID_TOKEN_REQUEST_TOKEN", None)


def test_examples_never_hand_a_boolean_false_to_sign():
    """`sign: ${{ ... || 'false' }}` 是坑：表达式 false 会渲染成 "False"。

    Action 只认小写 "false"，于是「没配密钥」这个最普通的场景会当场判 3。
    所以示例里只能用「空串 = 保留默认」的写法。
    """
    import re

    for path in EXAMPLES:
        text = path.read_text(encoding="utf-8")
        bad = re.findall(r"^\s*sign:\s*\$\{\{.*or\s*'false'.*\}\}", text, re.M)
        assert not bad, f"{path.name} 会把布尔 false 传给 sign：{bad}"


def test_examples_pin_identity_to_the_triggering_ref():
    """identity 必须写死到具体 workflow 文件，@ 后的 ref 要跟着触发 ref 走。

    固定在 `refs/heads/main` 的示例，一旦流水线在 tag 上跑，自检就会判 2 ——
    那是「签名身份不是我以为的那个」，与配置笔误不是一个事故等级。
    """
    for path in EXAMPLES:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.lstrip().startswith("identity:") and "github.com" in line:
                assert (
                    "/.github/workflows/" in line
                ), f"{path.name} 的 identity 没钉到具体文件"
                assert (
                    "||" not in line and "*" not in line
                ), f"{path.name} 的 identity 用了宽匹配"
                assert (
                    "@${{" in line
                ), f"{path.name} 的 identity 把 ref 写死了：{line.strip()}"


def test_examples_that_sign_enable_id_token():
    """默认签名 + 没给私钥 = keyless，那就必须有 id-token: write，否则必判 3。"""
    for path in EXAMPLES:
        text = path.read_text(encoding="utf-8")
        if "XMZZUZHI/Github/ci-evidence-pack" not in text:
            continue
        # 校验/取脚本这两类示例根本不打包，不涉及签名
        if "action-verify.sh" in text or "INPUT_BUNDLE" in text:
            continue
        assert "id-token: write" in text, f"{path.name} 默认签名却没开 id-token: write"


def test_keyless_bad_issuer_response_fails_with_3(workspace, tmp_path):
    """端点返回 401（权限没开）同样是 3：换不到 token 是工具侧的事。"""
    server, url = _fake_oidc_server(tmp_path, ok=False)
    try:
        env = _action_env(workspace, INPUT_SIGN="true")
        env.pop("SIGSTORE_ID_TOKEN", None)
        env["ACTIONS_ID_TOKEN_REQUEST_URL"] = url
        env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"] = "request-token-not-a-jwt"
        proc = _call("action-pack.sh", env, cwd=workspace)
    finally:
        server.shutdown()
    assert proc.returncode == 3


def test_caller_supplied_token_is_respected(workspace, tmp_path):
    """调用方已经换好 token 就原样用，不再去端点兜一圈。"""
    fake = _fake_cosign(tmp_path)
    env = _action_env(workspace, INPUT_SIGN="true")
    env["SIGSTORE_ID_TOKEN"] = _OIDC_TOKEN
    env.pop("ACTIONS_ID_TOKEN_REQUEST_URL", None)
    env["PATH"] = f"{fake}{os.pathsep}{env['PATH']}"
    proc = _call("action-pack.sh", env, cwd=workspace)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out = _gh_outputs(workspace.parent / "gh-output.txt")
    bundle = json.loads(Path(out["signature-bundle"]).read_text(encoding="utf-8"))
    assert bundle["npcToken"] == _OIDC_TOKEN


# ---------------------------------------------------------------------------
# 示例工作流：用户是照抄的，所以它们的写法本身也是契约。
# 布尔值渲染成 'False'、identity 写死 ref、sign 开着却没给 id-token ——
# 这三件事都不会让 YAML 报错，只会在真跑的时候红。
# ---------------------------------------------------------------------------


def _evidence_steps(path: Path) -> list[dict]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    steps = []
    for job in data["jobs"].values():
        for step in job.get("steps", []):
            if "XMZZUZHI/Github/ci-evidence-pack" in str(step.get("uses", "")):
                steps.append(step)
    return steps


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_examples_never_pass_a_boolean_to_sign(path):
    """`sign` 只认小写 'true'。把某个 outputs 直接塞给它，会渲染成 'false'/'False'。

    这类写法在 YAML 里完全合法，静默失效 —— 于是示例带着空密钥撞进 keyless，
    最普通的场景反而最红。
    """
    for step in _evidence_steps(path):
        sign = str((step.get("with") or {}).get("sign", ""))
        if not sign:
            continue
        # 只有「整串就是一个表达式」才会把布尔值原样渲染出来；
        # `cond && 'true' || ''` 已经在 YAML 层收敛成字符串了。
        assert (
            "&&" in sign or "${{" not in sign
        ), f"{path.name} 直接把 outputs 当 sign 传，会渲染出 'False'：{sign}"


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_examples_do_not_hardcode_identity_ref(path):
    """identity 的 `@refs/...` 必须跟着触发 ref 走，写死 main 在 tag 上判 2。"""
    text = path.read_text(encoding="utf-8")
    for step in _evidence_steps(path):
        identity = str((step.get("with") or {}).get("identity", ""))
        if "@" not in identity:
            continue
        tail = identity.split("@", 1)[1]
        assert (
            "refs/heads/" not in tail or "${{" in tail
        ), f"{path.name} 把 identity 的 ref 写死了：{identity}"
    # 注释里也不能把这种写法当范例教出去
    assert "yml@refs/heads/main" not in text or "${{" in text


def test_examples_that_default_to_signing_have_id_token():
    """默认签名的示例（不给 sign 或给 'true'）必须在 job 里开 id-token: write。"""
    for path in EXAMPLES:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job in data["jobs"].values():
            perms = {
                **(data.get("permissions") or {}),
                **(job.get("permissions") or {}),
            }
            for step in job.get("steps", []):
                if "XMZZUZHI/Github/ci-evidence-pack" not in str(step.get("uses", "")):
                    continue
                with_ = step.get("with") or {}
                sign = str(with_.get("sign", ""))
                # 现在的签名只有 OIDC 一条路：凡是不显式写 sign: 'false' 的示例，
                # 都必须把 id-token: write 开出来，没有别的分支可绕。
                # 显式留空 = 沿用默认（签名）；给了 sign 就必须是 'true'
                if not sign:
                    if "sign" in with_:
                        continue
                    assert (
                        perms.get("id-token") == "write"
                    ), f"{path.name} 不写 sign 就是默认签名，必须有 id-token: write"
                assert (
                    perms.get("id-token") == "write"
                ), f"{path.name} 会走 keyless 签名，却没有 id-token: write"


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_examples_do_not_manage_private_keys(path):
    """示例里不该再出现私钥那一套：密钥 secret、base64 落盘、COSIGN_PASSWORD。

    留一段「配了私钥就切 key 模式」的模板，等于把删掉的 fallback 又教回去。
    """
    text = path.read_text(encoding="utf-8")
    for banned in (
        "COSIGN_KEY_B64",
        "COSIGN_PUBLIC_KEY_B64",
        "COSIGN_PASSWORD",
        "cosign-key",
        "cosign-public-key",
    ):
        assert banned not in text, f"{path.name} 仍在示范私钥方案：{banned}"


# ---------------------------------------------------------------------------
# 默认签名之后最容易咬人的两处：装 cosign 的判据，以及「自检在签什么」。
# 前者两个脚本判据分叉时症状出现在离原因最远的地方（装没装 → 内核报 3）；
# 后者在签名默认开后，自检必过 0，那条结论的信息量接近于零。
# ---------------------------------------------------------------------------


def test_cosign_installer_runs_for_every_value_that_means_sign():
    """判据必须与 action-pack.sh 逐字一致：只有小写 'false' 才不装。

    曾经写成 `inputs.sign == 'true'`：调用方显式传 'yes' / '1' 时 installer 不跑，
    而打包脚本照签不误（它判的是 != 'false'），最后在内核里报「找不到 cosign」判 3。
    这条用例就是钉子 —— 两个脚本的判据一旦分叉，这里会立刻红。
    """
    steps = _manifest()["runs"]["steps"]
    installer = next(s for s in steps if "cosign-installer" in str(s.get("uses", "")))
    assert installer["if"] == "inputs.sign != 'false'"

    script = (SCRIPTS / "action-pack.sh").read_text(encoding="utf-8")
    # shell 层的判据：同样是「只有 'false' 才是关」，用 default 兜空串。
    assert '[ "${INPUT_SIGN:-true}" = "false" ]' in script


def test_sign_off_literal_is_shared_by_action_and_kernel():
    """ "哪种写法算关"只许有一个答案：内核、shell、action.yml 说的是同一句话。"""
    from evidence_pack.signing import SIGN_OFF_LITERAL, is_sign_off

    assert SIGN_OFF_LITERAL == "false"
    # 留空 = 没给 = 沿用默认（签名），不是「关」。
    assert is_sign_off("") is False and is_sign_off(None) is False
    # 大写的 False 渲染值不算关：悄悄当成「不签」比报错危险得多。
    assert is_sign_off("False") is False and is_sign_off("0") is False
    # 两边都只认这一个字面量。
    assert _manifest()["inputs"]["sign"]["default"] == "true"
    assert SIGN_OFF_LITERAL in (SCRIPTS / "action-pack.sh").read_text(encoding="utf-8")


def test_verify_step_does_not_pretend_the_self_digest_is_an_anchor():
    """自检回送本 job 刚算的摘要时要留下说明，别让它看起来像包外锚点。

    签名默认开后这条路必过 0：验的是「刚打出来的东西」，不是「包外那份账」。
    说明消失的那天，verify-ok 就会被当成「包来自我以为的那个人」。
    """
    steps = {s.get("id"): s for s in _manifest()["runs"]["steps"] if s.get("id")}
    env = steps["verify"]["env"]
    assert "steps.pack.outputs.bundle-sha256" in env["INPUT_EXPECT_SHA256"]
    text = (SCRIPTS / "action-pack.sh").read_text(encoding="utf-8")
    assert "自己给自己发证" in text or "包外那份账" in text

    # action.yml 的输入说明里也得写清楚这件事。
    desc = _manifest()["inputs"]["expect-sha256"]["description"]
    assert "自己给自己发证" in desc


def test_signed_verify_is_2_when_identity_does_not_match(workspace, tmp_path):
    """签名 invalid / identity 不符 → 2（证据无效），不是 3（工具坏了）。

    Action 层此前没有这条用例：签名的成败只靠 test_signing.py 的内核单测兜，
    而 verify 那一步在签名默认开启后成了每次必跑的路径。
    """
    fake = _fake_cosign(tmp_path, verify_ok=False)
    env = _action_env(workspace, INPUT_SIGN="true")
    env["SIGSTORE_ID_TOKEN"] = _OIDC_TOKEN
    env.pop("ACTIONS_ID_TOKEN_REQUEST_URL", None)
    env["PATH"] = f"{fake}{os.pathsep}{env['PATH']}"
    assert _call("action-pack.sh", env, cwd=workspace).returncode == 0, "打包本身该成功"
    out = _gh_outputs(workspace.parent / "gh-output.txt")

    verify_env = _action_env(
        workspace,
        INPUT_BUNDLE=out["bundle-path"],
        INPUT_SIGNATURE_BUNDLE=out["signature-bundle"],
        INPUT_IDENTITY="https://github.com/acme/app/.github/workflows/ci.yml@refs/heads/main",
        INPUT_ISSUER="https://token.actions.githubusercontent.com",
        INPUT_EXPECT_SHA256=out["bundle-sha256"],
    )
    verify_env["PATH"] = f"{fake}{os.pathsep}{verify_env['PATH']}"
    proc = _call("action-verify.sh", verify_env, cwd=workspace)
    assert proc.returncode == 2, proc.stdout + proc.stderr
    verified = _gh_outputs(workspace.parent / "gh-output.txt")
    assert verified["ok"] == "false" and verified["exit-code"] == "2"
    assert verified["signature-verified"] == "false"


def test_signed_verify_is_3_when_cosign_went_missing(workspace, tmp_path):
    """打包时有 cosign、验签时没有 → 3（工具坏了），不是「签名无效」。

    这两者的人工处置完全不同：一个是去修 runner，一个是去查谁动过包。
    """
    fake = _fake_cosign(tmp_path)
    env = _action_env(workspace, INPUT_SIGN="true")
    env["SIGSTORE_ID_TOKEN"] = _OIDC_TOKEN
    env.pop("ACTIONS_ID_TOKEN_REQUEST_URL", None)
    env["PATH"] = f"{fake}{os.pathsep}{env['PATH']}"
    assert _call("action-pack.sh", env, cwd=workspace).returncode == 0
    out = _gh_outputs(workspace.parent / "gh-output.txt")

    verify_env = _action_env(
        workspace,
        INPUT_BUNDLE=out["bundle-path"],
        INPUT_SIGNATURE_BUNDLE=out["signature-bundle"],
        INPUT_IDENTITY="https://github.com/acme/app/.github/workflows/ci.yml@refs/heads/main",
        INPUT_ISSUER="https://token.actions.githubusercontent.com",
        INPUT_EXPECT_SHA256=out["bundle-sha256"],
        PATH=f"{Path(sys.executable).parent}:/usr/bin:/bin",  # 这里没有 cosign，但保留运行测试的 python 路径
    )
    proc = _call("action-verify.sh", verify_env, cwd=workspace)
    assert proc.returncode == 3, proc.stdout + proc.stderr
    assert "cosign" in proc.stdout + proc.stderr


def test_oidc_probe_step_can_be_referenced_by_callers():
    """探针结论要能被调用方读到：没有 id，日志里那句 warning 就是孤证。

    OIDC 自检的价值不在它自己那行输出，而在于下游能把「有没有签发方」
    与随后那次失败对上号 —— 对不上号时，现场只剩「签名失败」四个字。
    """
    probe = _step_by_name("自检 OIDC")
    assert probe.get("id"), "OIDC 自检步骤必须有 id，否则结论无人可读"


# ---------------------------------------------------------------------------
# 发版流水线自己的契约：正文里要出现透明日志条目，且两个闸门都得在。
# 这两条一旦被改掉，流水线照样绿 —— 只是发出去的正文少了可复核的位置。
# ---------------------------------------------------------------------------


def _release_workflow() -> dict:
    return yaml.safe_load(
        (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    )


def _release_publish_step() -> dict:
    steps = _release_workflow()["jobs"]["release"]["steps"]
    for step in steps:
        if str(step.get("name", "")).startswith("挂到 Release"):
            return step
    raise AssertionError("release.yml 里找不到挂 Release 的步骤")


def test_release_body_lists_rekor_entries():
    """Release 正文必须写透明日志条目，而不是一句「已存证」。"""
    run = _release_publish_step()["run"]
    assert "### 透明日志（Rekor）" in run
    assert "logIndex" in run
    # 条目要从本仓库 CLI 读，不许在 YAML 里手搓 jq：字段一改名就静默变空。
    assert "evidence_pack.cli rekor" in run


def test_release_refuses_to_publish_unverified_evidence():
    """自检不为 0 就不许发 —— 这条闸门不能被透明日志的改动顺手冲掉。"""
    run = _release_publish_step()["run"]
    assert "VERIFY_CODE" in run
    assert "exit 1" in run


def test_release_never_rewrites_existing_body():
    """同一 tag 重跑不许改既有正文：锚点被覆盖，下游核对全部失效。"""
    run = _release_publish_step()["run"]
    assert "gh release view" in run
    assert "已存在" in run


def test_release_generator_step_runs_before_publish():
    """生成器必须先于用到它的步骤存在，否则 Release 正文会缺一整段。"""
    steps = _release_workflow()["jobs"]["release"]["steps"]
    names = [str(s.get("name", "")) for s in steps]
    gen = next(i for i, n in enumerate(names) if n.startswith("准备透明日志"))
    pub = next(i for i, n in enumerate(names) if n.startswith("挂到 Release"))
    assert gen < pub, f"生成器在第 {gen} 步，发布在第 {pub} 步：顺序反了"
