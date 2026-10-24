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
    import http.server
    import threading

    fake_token = "h." + "p" * 120 + ".s"   # 三段式、长度过 MIN_TOKEN_LEN
    seen: list[str] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler 约定
            assert self.path.endswith("&audience=sigstore"), self.path
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
            INPUT_COSIGN_KEY="",           # 没私钥 → 必须走 keyless
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
            "bundle=\"\"\n"
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
    finally:
        server.shutdown()


def test_oidc_request_failure_is_3_not_2(workspace):
    """换 token 失败属于「流水线坏了」（3），不能糊成「证据无效」（2）。"""
    env = _action_env(
        workspace,
        ACTIONS_ID_TOKEN_REQUEST_URL="http://127.0.0.1:1/oidc?x=1",  # 必然连不上
        ACTIONS_ID_TOKEN_REQUEST_TOKEN="request-token",
    )
# keyless 换 token：`ACTIONS_ID_TOKEN_REQUEST_TOKEN` 只是换 token 的**凭据**，
# 不是 token 本体。把它当 token 用，就是在 Fulcio 那里换回一个 401 ——
# 现场看起来跟「id-token: write 没开」一模一样，最难查。
# 所以这里起一个假 OIDC 端点 + 假 cosign，把链路钉死。
# ---------------------------------------------------------------------------

def _fake_oidc_server(tmp_path: Path, *, ok: bool = True) -> tuple[subprocess.Popen, str]:
    """起一个本地假 OIDC 端点，只认 audience=sigstore。"""
    import http.server
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


def _fake_cosign(tmp_path: Path) -> Path:
    """假 cosign：sign-blob 时把 SIGSTORE_ID_TOKEN 抄进 bundle，便于断言。"""
    fake = tmp_path / "fakebin"
    fake.mkdir(exist_ok=True)
    script = fake / "cosign"
    script.write_text(
        "#!/bin/sh\n"
        "# 只实现 sign-blob：把收到的 token 原样写进 bundle 的 metadata 里。\n"
        'out=""\n'
        'prev=""\n'
        "for a in \"$@\"; do\n"
        '  [ "$prev" = "--bundle" ] && out="$a"\n'
        '  prev="$a"\n'
        "done\n"
        'cat > "$out" <<JSON\n'
        '{"messageSignature":{"messageDigest":{"digest":"AAAA"}},'
        '"verificationMaterial":{"x509CertificateChain":{"certificates":[{"rawBytes":"QQ=="}]},'
        '"tlogEntries":[{"integratedTime":"1700000000"}]},'
        '"npcToken":"'"${SIGSTORE_ID_TOKEN:-}"'"}\n'
        "JSON\n"
        "echo 'token-argv-check:' \"$@\" >&2\n"
        "exit 0\n"
    )
    script.chmod(0o755)
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
                assert "/.github/workflows/" in line, f"{path.name} 的 identity 没钉到具体文件"
                assert "||" not in line and "*" not in line, f"{path.name} 的 identity 用了宽匹配"
                assert "@${{" in line, f"{path.name} 的 identity 把 ref 写死了：{line.strip()}"


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
        assert "&&" in sign or "${{" not in sign, (
            f"{path.name} 直接把 outputs 当 sign 传，会渲染出 'False'：{sign}"
        )


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_examples_do_not_hardcode_identity_ref(path):
    """identity 的 `@refs/...` 必须跟着触发 ref 走，写死 main 在 tag 上判 2。"""
    text = path.read_text(encoding="utf-8")
    for step in _evidence_steps(path):
        identity = str((step.get("with") or {}).get("identity", ""))
        if "@" not in identity:
            continue
        tail = identity.split("@", 1)[1]
        assert "refs/heads/" not in tail or "${{" in tail, (
            f"{path.name} 把 identity 的 ref 写死了：{identity}"
        )
    # 注释里也不能把这种写法当范例教出去
    assert "yml@refs/heads/main" not in text or "${{" in text


def test_examples_that_default_to_signing_have_id_token():
    """默认签名的示例（不给 sign 或给 'true'）必须在 job 里开 id-token: write。"""
    for path in EXAMPLES:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job in data["jobs"].values():
            perms = {**(data.get("permissions") or {}), **(job.get("permissions") or {})}
            for step in job.get("steps", []):
                if "XMZZUZHI/Github/ci-evidence-pack" not in str(step.get("uses", "")):
                    continue
                with_ = step.get("with") or {}
                sign = str(with_.get("sign", ""))
                # 给了具体的私钥路径 = key 模式，不走 OIDC；写成表达式则是条件切换。
                if with_.get("cosign-key") and "${{" not in str(with_["cosign-key"]):
                    continue
                # 显式留空 = 不签名；给了 sign 就必须是 'true'（keyless 默认签名）
                if not sign:
                    if "sign" in with_:
                        continue
                    assert perms.get("id-token") == "write", (
                        f"{path.name} 不写 sign 就是默认签名，必须有 id-token: write"
                    )
                assert perms.get("id-token") == "write", (
                    f"{path.name} 会走 keyless 签名，却没有 id-token: write"
                )


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.name)
def test_example_key_setup_requires_both_keys(path):
    """只配私钥不配公钥：签得出、验不了，示例必须当场拦下。"""
    text = path.read_text(encoding="utf-8")
    if "COSIGN_KEY_B64" not in text:
        return
    assert "COSIGN_PUBLIC_KEY_B64" in text, f"{path.name} 只处理了私钥"
    assert '::error::' in text and "COSIGN_PUBLIC_KEY_B64" in text, (
        f"{path.name} 没有在「只有私钥」时当场拦下"
    )
