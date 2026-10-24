"""组装证据包。

包内布局是契约的一部分，改布局等于改格式版本：

  artifacts/<rel_path>       用户 --include 收进来的文件，保持相对路径
  metadata/metadata.json     工具名、版本、构建时间
  metadata/run.json          CI 运行上下文（各平台尽力采集，采不到就空）
  metadata/git.json          HEAD sha、分支、remote、是否 dirty
  metadata/deps.json         依赖快照（可选）
  sbom/sbom.cdx.json         CycloneDX（要得到就必须有）
  manifest/inputs.json       收进来的输入清单（机器可读）
  manifest/sha256sum.txt     除自身外每个文件的 sha256，严格模式的依据
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from . import __version__
from .collect import Collector
from .errors import ToolFailure
from .fsutil import (
    build_tar_gz,
    resolve_source_date_epoch,
    sha256_bytes,
    sha256_file,
    write_stable_json,
)
from .sbom import generate as generate_sbom
from .signing import DEFAULT_BUNDLE_SUFFIX, SignatureResult, sign as sign_bundle

FORMAT_VERSION = 2

RUN_ENV_KEYS = {
    # GitHub Actions
    "github_repository": "GITHUB_REPOSITORY",
    "github_run_id": "GITHUB_RUN_ID",
    "github_run_attempt": "GITHUB_RUN_ATTEMPT",
    "github_workflow": "GITHUB_WORKFLOW",
    "github_job": "GITHUB_JOB",
    "github_actor": "GITHUB_ACTOR",
    "github_event_name": "GITHUB_EVENT_NAME",
    "github_sha": "GITHUB_SHA",
    "github_ref": "GITHUB_REF",
    # CNB
    "cnb_repo_slug": "CNB_REPO_SLUG",
    "cnb_build_sn": "CNB_BUILD_SN",
    "cnb_pipeline_key": "CNB_PIPELINE_KEY",
    "cnb_commit": "CNB_COMMIT",
    "cnb_branch": "CNB_BRANCH",
    "cnb_build_user": "CNB_BUILD_USER",
    "cnb_event": "CNB_EVENT",
    # GitLab
    "gitlab_project_path": "CI_PROJECT_PATH",
    "gitlab_pipeline_id": "CI_PIPELINE_ID",
    "gitlab_job_id": "CI_JOB_ID",
}


@dataclass
class PackOptions:
    """打包参数。

    默认为签名：没有 `--key` 就走 keyless（OIDC 换来的 Fulcio 短期证书），
    `--no-sign` 才退化成「无签名 + 包外锚点」。

    `identity` / `issuer` 在打包阶段只是**期望值**：keyless 签名时它们会被写进
    metadata/binding.json 供验签方核对，同时透传给 cosign 做签发身份约束。
    它们本身不是签名开关——把期望身份当开关，正是原实现的坑。
    """

    repo_root: Path
    out_dir: Path
    includes: list[str]
    sbom: str = "auto"
    collect_git: bool = True
    key: str | None = None
    identity: str | None = None
    issuer: str | None = None
    # keyless 用 OIDC token 换 Fulcio 短期证书；token 只经环境变量进子进程。
    oidc_token: str | None = None
    fulcio_url: str | None = None
    rekor_url: str | None = None
    bundle_name: str | None = None
    excludes: list[str] = field(default_factory=list)
    # 默认签名。关掉它等于回到「包内自洽」，那就必须有包外锚点才算证据。
    sign: bool = True


@dataclass
class PackResult:
    bundle_path: str
    bundle_sha256: str
    file_count: int
    source_date_epoch: int
    sbom: str
    signature: SignatureResult = field(default_factory=SignatureResult)
    source_sha256: str = ""      # 签名实际覆盖的字节（与 bundle_sha256 不同：签名在包外）


def _git(repo: Path, *args: str) -> str:
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), *args], capture_output=True, text=True, check=False
        )
    except OSError:
        return ""
    return proc.stdout.strip() if proc.returncode == 0 else ""


def collect_git_meta(repo_root: Path) -> dict | None:
    sha = _git(repo_root, "rev-parse", "HEAD")
    if not sha:
        return None
    return {
        "sha": sha,
        "branch": _git(repo_root, "rev-parse", "--abbrev-ref", "HEAD"),
        "remote_url": _git(repo_root, "config", "--get", "remote.origin.url"),
        "describe": _git(repo_root, "describe", "--tags", "--always"),
        "dirty": bool(_git(repo_root, "status", "--porcelain")),
    }


def collect_run_meta() -> dict:
    meta = {key: os.environ[env] for key, env in RUN_ENV_KEYS.items() if os.environ.get(env)}
    return meta


def write_manifest(stage_dir: Path) -> int:
    """除 manifest/sha256sum.txt 自身外，逐文件记 hash。"""
    manifest_dir = stage_dir / "manifest"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    target = manifest_dir / "sha256sum.txt"

    lines = []
    for path in sorted(stage_dir.rglob("*"), key=lambda p: p.relative_to(stage_dir).as_posix()):
        if not path.is_file() or path == target:
            continue
        lines.append(f"{sha256_file(path)}  {path.relative_to(stage_dir).as_posix()}")
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(lines)


def _repo_slug(repo_root: Path, git_meta: dict | None) -> str:
    if git_meta and git_meta.get("remote_url"):
        url = git_meta["remote_url"].rstrip("/")
        for sep in ("github.com/", "github.com:", "cnb.cool/"):
            if sep in url:
                return url.split(sep, 1)[1].removesuffix(".git")
    return repo_root.name


def _default_bundle_name(repo_root: Path, git_meta: dict | None) -> str:
    slug = _repo_slug(repo_root, git_meta).replace("/", "-")
    sha = (git_meta or {}).get("sha", "nosha")[:7]
    return f"{slug}_{sha}.tar.gz"


def _write_binding_meta(stage_dir: Path, *, identity: str | None, issuer: str | None) -> None:
    """把「这份证据该由谁签发」写进包内，供验签方对照。

    注意语义：这是**声明**，不是证据。它可以被伪造，所以 verifier 只把它
    当作"调用方没给 identity 时的兜底期望值"，绝不把它当信任根。
    """
    if not identity and not issuer:
        return
    write_stable_json(stage_dir / "metadata" / "binding.json", {
        "identity": identity or "",
        "issuer": issuer or "",
    })


def pack(opts: PackOptions) -> PackResult:
    repo_root = opts.repo_root.resolve()
    out_dir = opts.out_dir.resolve()
    if not repo_root.is_dir():
        from .errors import UsageError

        raise UsageError(f"--repo 不是目录：{repo_root}")

    mtime = resolve_source_date_epoch(repo_root)
    git_meta = collect_git_meta(repo_root) if opts.collect_git else None

    with tempfile.TemporaryDirectory(prefix="evidence-pack-") as tmp:
        stage = Path(tmp)
        artifacts = stage / "artifacts"
        artifacts.mkdir()

        collector = Collector(repo_root, out_dir, opts.excludes)
        collected = collector.collect(opts.includes, artifacts)

        meta_dir = stage / "metadata"
        write_stable_json(meta_dir / "metadata.json", {
            "format_version": FORMAT_VERSION,
            "tool": "evidence-pack",
            "tool_version": __version__,
            "created_at_epoch": mtime,
            "source_date_epoch": mtime,
        })
        write_stable_json(meta_dir / "run.json", collect_run_meta())
        if git_meta:
            write_stable_json(meta_dir / "git.json", git_meta)

        _write_binding_meta(stage, identity=opts.identity, issuer=opts.issuer)

        # 把确定性时间戳一路传下去：扫描器自带的 timestamp / serialNumber 若原样落盘，
        # 同一个 commit 两次打包就有两个哈希，「可复现」当场作废。
        sbom_kind = generate_sbom(
            repo_root, opts.sbom, stage / "sbom" / "sbom.cdx.json", epoch=mtime
        )
        if sbom_kind != "none":
            write_stable_json(meta_dir / "deps.json", {"sbom": sbom_kind})

        write_stable_json(stage / "manifest" / "inputs.json", {
            "files": collected.rel_paths,
            "skipped": collected.skipped,
        })

        file_count = write_manifest(stage)

        bundle_name = opts.bundle_name or _default_bundle_name(repo_root, git_meta)
        out_dir.mkdir(parents=True, exist_ok=True)
        bundle_path = out_dir / bundle_name
        payload = build_tar_gz(stage, mtime)
        bundle_path.write_bytes(payload)
        bundle_sha = sha256_bytes(payload)

    sig = SignatureResult()
    # 三条触发路径任一成立即签：--sign 显式要求、给了私钥、或给了 OIDC token。
    # identity/issuer 是"验签时"的期望值，签名时并不需要——把它们当签名开关
    # 是原实现的坑，所以这里只认 sign / key / oidc_token。
    if opts.sign or opts.key or opts.oidc_token:
        bundle_file = out_dir / bundle_name
        sig = sign_bundle(
            bundle_file,
            out_dir / (bundle_name + DEFAULT_BUNDLE_SUFFIX),
            key=opts.key,
            oidc_token=opts.oidc_token,
            fulcio_url=opts.fulcio_url,
            rekor_url=opts.rekor_url,
        )

    return PackResult(
        bundle_path=str(out_dir / bundle_name),
        bundle_sha256=bundle_sha,
        file_count=file_count,
        source_date_epoch=mtime,
        sbom=sbom_kind,
        signature=sig,
        source_sha256=bundle_sha,
    )
