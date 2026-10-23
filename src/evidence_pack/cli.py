"""命令行入口。

输出三档，永远不互相污染：
  --quiet  只吐一行结论（成功给 bundle 路径，verify 给 OK）
  --json   单行或缩进 JSON，全部走 stdout
  默认     人看的表格，走 stderr 以外的正常路径
失败时：JSON 模式照样输出结构化错误，退出码按 errors.py 的三档。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer

from . import __version__
from .errors import (
    EXIT_EVIDENCE_INVALID,
    EXIT_OK,
    EXIT_TOOL_FAILURE,
    EXIT_USAGE,
    EvidenceError,
)
from .packer import PackOptions, pack as run_pack
from .verifier import VerifyOptions, verify as run_verify

app = typer.Typer(add_completion=False, help="Deterministic, verifiable CI evidence bundles.")


def _emit(payload: dict, *, quiet_line: str | None, quiet: bool, as_json: bool) -> None:
    if as_json:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))
    elif quiet and quiet_line:
        typer.echo(quiet_line)
    else:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))


def _fail(exc: EvidenceError, *, as_json: bool) -> None:
    if as_json:
        typer.echo(json.dumps({"ok": False, "error": str(exc), "kind": exc.kind},
                              indent=2, sort_keys=True, ensure_ascii=False))
    else:
        typer.echo(f"error: {exc}", err=True)
    raise typer.Exit(code=exc.exit_code)


@app.command()
def pack(
    repo: Path = typer.Option(Path("."), "--repo", help="仓库根目录"),
    out: Path = typer.Option(Path("dist"), "--out", help="输出目录（会自动排除自身）"),
    include: list[str] = typer.Option(None, "--include", help="要收进包的文件/目录，相对仓库根；可多次"),
    sbom: str = typer.Option("auto", "--sbom", help="auto | none | python | node"),
    collect_git: bool = typer.Option(True, "--collect-git/--no-collect-git"),
    exclude: list[str] = typer.Option(None, "--exclude", help="额外排除的路径名"),
    key: str = typer.Option(None, "--key", help="cosign 私钥路径（key 模式）"),
    sign: bool = typer.Option(False, "--sign", help="用 cosign keyless 签名（需 OIDC token / id-token: write）"),
    identity: str = typer.Option(None, "--identity", help="期望签发身份，写进 metadata/binding.json 供验签方核对"),
    issuer: str = typer.Option(None, "--issuer", help="期望 OIDC issuer，同上"),
    bundle_name: str = typer.Option(None, "--bundle-name", help="自定义包名"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """生成证据包（可选 --bundle 签名）。"""
    try:
        result = run_pack(PackOptions(
            repo_root=repo,
            out_dir=out,
            includes=list(include or []),
            sbom=sbom,
            collect_git=collect_git,
            key=key,
            identity=identity,
            issuer=issuer,
            bundle_name=bundle_name,
            excludes=list(exclude or []),
            sign=sign,
        ))
        _emit({
            "ok": True,
            "bundle_path": result.bundle_path,
            "bundle_name": Path(result.bundle_path).name,
            "bundle_sha256": result.bundle_sha256,
            "file_count": result.file_count,
            "source_date_epoch": result.source_date_epoch,
            "sbom": result.sbom,
            "signed": result.signature.signed,
            "signature_mode": result.signature.mode,
            "signature_bundle": result.signature.bundle_path,
        }, quiet_line=result.bundle_path, quiet=quiet, as_json=as_json)
    except EvidenceError as exc:
        _fail(exc, as_json=as_json)


@app.command()
def verify(
    bundle: Path = typer.Argument(..., help="证据包 .tar.gz"),
    signature_bundle: Path = typer.Option(None, "--signature-bundle", help=".sigstore.json"),
    key: str = typer.Option(None, "--key", help="cosign 公钥（key 模式验签）"),
    identity: str = typer.Option(None, "--identity", help="keyless 期望身份"),
    issuer: str = typer.Option(None, "--issuer", help="keyless 期望 OIDC issuer"),
    ignore_tlog: bool = typer.Option(False, "--insecure-ignore-tlog", help="跳过透明日志校验（结果会标记 tlog_checked=false）"),
    expect_sha256: str = typer.Option(None, "--expect-sha256", help="外部锚点：期望的 bundle sha256"),
    expect_repo: str = typer.Option(None, "--expect-repo", help="外部锚点：期望的 owner/repo"),
    exit_code: bool = typer.Option(
        False, "--exit-code",
        help="只出结论：校验失败也正常结束进程，由调用方看 JSON 里的 exit_code",
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """校验证据包。退出码：0 通过 / 1 用法 / 2 证据无效 / 3 工具异常。"""
    if exit_code:
        _verify_reporting(
            bundle, signature_bundle, key, identity, issuer, ignore_tlog,
            expect_sha256, expect_repo, quiet, as_json,
        )
        return
    try:
        result = run_verify(VerifyOptions(
            bundle_path=bundle,
            signature_bundle=signature_bundle,
            key=key,
            identity=identity,
            issuer=issuer,
            ignore_tlog=ignore_tlog,
            expect_sha256=expect_sha256,
            expect_repo=expect_repo,
        ))
        _emit({
            "ok": True,
            "bundle_path": result.bundle_path,
            "bundle_sha256": result.bundle_sha256,
            "manifest_verified": result.manifest_verified,
            "signature_verified": result.signature.verified,
            "anchored": result.anchored,
            "tlog_checked": result.signature.tlog_checked,
            "signature_mode": result.signature.mode,
            "file_count": result.file_count,
            "repo": result.repo,
            "source_date_epoch": result.source_date_epoch,
        }, quiet_line="OK", quiet=quiet, as_json=as_json)
    except EvidenceError as exc:
        _fail(exc, as_json=as_json)


def _verify_reporting(
    bundle: Path,
    signature_bundle: Path | None,
    key: str | None,
    identity: str | None,
    issuer: str | None,
    ignore_tlog: bool,
    expect_sha256: str | None,
    expect_repo: str | None,
    quiet: bool,
    as_json: bool,
) -> None:
    """`--exit-code` 模式：结论永远以 JSON / 单行形式输出，进程退出码恒为 0。

    存在的理由只有一个：Action 里要先拿到整体判定再做决策（上传证据、发评论），
    而不是让一个非零退出码在 set -e 下把后续步骤全掐掉。
    """
    result = run_verify(VerifyOptions(
        bundle_path=bundle,
        signature_bundle=signature_bundle,
        key=key,
        identity=identity,
        issuer=issuer,
        ignore_tlog=ignore_tlog,
        expect_sha256=expect_sha256,
        expect_repo=expect_repo,
        exit_code_only=True,
    ))
    payload = {
        "ok": result.ok,
        "exit_code": result.exit_code,
        "error": result.error,
        "error_kind": result.error_kind,
        "bundle_path": result.bundle_path,
        "bundle_sha256": result.bundle_sha256,
        "manifest_verified": result.manifest_verified,
        "signature_verified": result.signature.verified,
        "anchored": result.anchored,
        "tlog_checked": result.signature.tlog_checked,
        "signature_mode": result.signature.mode,
        "file_count": result.file_count,
        "repo": result.repo,
        "source_date_epoch": result.source_date_epoch,
    }
    if quiet and not as_json:
        typer.echo("OK" if result.ok else f"INVALID({result.exit_code}): {result.error}")
        return
    typer.echo(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))


@app.command()
def version() -> None:
    """打印版本。"""
    typer.echo(f"evidence-pack {__version__}")


def main() -> None:
    app()


if __name__ == "__main__":
    sys.exit(main())
