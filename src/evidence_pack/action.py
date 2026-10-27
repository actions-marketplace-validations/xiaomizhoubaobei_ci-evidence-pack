"""GitHub Action 的 Python 入口。

这一步是 composite Action 唯一被 shell 调起来的地方：
`python3 -m evidence_pack.action pack|verify`，参数从 INPUT_* 环境变量来，
结论一律走 stdout 的 JSON。

为什么没有命令行外壳：本仓库只为 GitHub Action 服务，参数解析、终端渲染、
帮助文案在这里没有第二个使用者。环境变量是 Action 和脚本之间的既有契约，
再套一层 argv 只是把同一个契约写两遍，还得跟着内核一起改。

三条子命令的退出码语义（见 errors.py）：
  pack   —— 结论出得来即 0；用法错 1、工具异常 3 原样交还。
  verify —— 恒为 0，判定放在 JSON 的 `exit_code` 里。Action 要先拿到结论
            再做决策（登记锚点、上传制品、发评论），而不是让 set -e 把后面
            的步骤全掐掉；什么时候真的失败由 shell 层决定。
  rekor  —— 同理恒为 0（除非输入本身不成立）：无条目是事实，不是崩溃。
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from .errors import EXIT_OK, EXIT_TOOL_FAILURE, EvidenceError, UsageError
from .packer import PackOptions
from .packer import pack as run_pack
from .signing import is_sign_off, rekor_entries, resolve_oidc_token
from .verifier import VerifyOptions
from .verifier import verify as run_verify

# OIDC token 只从这一个环境变量读。Action 的 shell 层换好 token 放进它，
# 内核再交给 cosign 子进程 —— token 从不进 argv。
OIDC_TOKEN_ENV = "SIGSTORE_ID_TOKEN"


def _env(name: str) -> str | None:
    """读一个非空环境变量。空串按「没给」处理：Action 里未填的 input 就是空串。"""
    value = (os.environ.get(name) or "").strip()
    return value or None


def _emit(payload: dict) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))


def _fail(exc: EvidenceError) -> int:
    """失败也给一份和成功同构的 JSON：shell 层不该为读结论写两套解析。"""
    _emit(
        {
            "ok": False,
            "exit_code": exc.exit_code,
            "error": str(exc),
            "kind": exc.kind,
            "error_kind": exc.kind,
        }
    )
    return exc.exit_code


def _pack_payload(result) -> dict:
    signature = result.signature
    return {
        "ok": True,
        "exit_code": EXIT_OK,
        "bundle_path": result.bundle_path,
        "bundle_name": Path(result.bundle_path).name,
        "bundle_sha256": result.bundle_sha256,
        "file_count": result.file_count,
        "source_date_epoch": result.source_date_epoch,
        "sbom": result.sbom,
        "signed": signature.signed,
        "signature_mode": signature.mode,
        "signature_bundle": signature.bundle_path,
        "certificate_identity": signature.certificate_identity,
        "certificate_issuer": signature.certificate_issuer,
        "cert_not_before": signature.cert_not_before,
        "cert_not_after": signature.cert_not_after,
    }


def _verify_payload(result) -> dict:
    """成功与失败同构：`error` 只在失败时非空，成功路径也留键，读的人不必猜。"""
    signature = result.signature
    return {
        "ok": result.ok,
        "exit_code": result.exit_code,
        "error": result.error,
        "error_kind": result.error_kind,
        "bundle_path": result.bundle_path,
        "bundle_sha256": result.bundle_sha256,
        "manifest_verified": result.manifest_verified,
        "signature_verified": signature.verified,
        "anchored": result.anchored,
        "tlog_checked": signature.tlog_checked,
        "signature_mode": signature.mode,
        "certificate_identity": signature.certificate_identity,
        "cert_not_before": signature.cert_not_before,
        "cert_not_after": signature.cert_not_after,
        "file_count": result.file_count,
        "repo": result.repo,
        "source_date_epoch": result.source_date_epoch,
        "anchor_warnings": result.anchor_warnings,
    }


def cmd_pack() -> int:
    """按 INPUT_* 打包并签名，把结构化结果打到 stdout。"""
    try:
        # 只认小写 'false'：留空等于没给，沿用默认（签名）。
        sign = not is_sign_off(_env("INPUT_SIGN"))
        token = resolve_oidc_token(token_env=OIDC_TOKEN_ENV) if sign else None
        if sign and token is None:
            # 缺 token 是「没有签名的料」，说清楚它同时是个用法问题：
            # 要么 job 上开 id-token: write，要么显式 sign: 'false' 自备锚点。
            raise UsageError(
                f"签名需要 OIDC token：环境变量 {OIDC_TOKEN_ENV} 为空，换不到 Fulcio "
                "短期证书。拿不到签发方时请显式 sign: 'false'，并以包外 sha256 锚点当信任根。"
            )
        includes = _multi("INPUT_INCLUDE")
        if not includes:
            # include 是必填输入，漏写时 Action 不替调用方猜该收哪些目录。
            raise UsageError("include 为空：请显式列出要收进证据包的文件或目录。")
        result = run_pack(
            PackOptions(
                repo_root=Path(_env("REPO_ROOT") or "."),
                out_dir=Path(_env("INPUT_OUT_DIR") or "_evidence"),
                includes=includes,
                excludes=_multi("INPUT_EXCLUDE"),
                sbom=_env("INPUT_SBOM") or "auto",
                identity=_env("INPUT_IDENTITY"),
                issuer=_env("INPUT_ISSUER"),
                oidc_token=token,
                bundle_name=_env("INPUT_BUNDLE_NAME"),
                sign=sign,
            )
        )
    except EvidenceError as exc:
        return _fail(exc)
    _emit(_pack_payload(result))
    return EXIT_OK


def cmd_verify() -> int:
    """按 INPUT_* 校验一个已有包。恒返回 0，判定看 JSON 的 `exit_code`。"""
    bundle = _env("INPUT_BUNDLE")
    if not bundle:
        # 没有包就没有可校验的对象；这是用法错，直接给 1，不必先跑一遍内核。
        return _fail(UsageError("bundle 输入为空：没有包就没有可校验的对象"))

    signature_bundle = _env("INPUT_SIGNATURE_BUNDLE")
    result = run_verify(
        VerifyOptions(
            bundle_path=Path(bundle),
            signature_bundle=Path(signature_bundle) if signature_bundle else None,
            identity=_env("INPUT_IDENTITY"),
            issuer=_env("INPUT_ISSUER"),
            ignore_tlog=(_env("INPUT_IGNORE_TLOG") or "").lower() == "true",
            expect_sha256=_env("INPUT_EXPECT_SHA256"),
            expect_repo=_env("INPUT_EXPECT_REPO"),
            exit_code_only=True,
        )
    )
    _emit(_verify_payload(result))
    return EXIT_OK


def cmd_rekor() -> int:
    """把签名 bundle 里的透明日志条目摊平成 JSON，供 Release 正文使用。

    条目只能从 bundle 读：logIndex / logId 只有那一处是权威的。
    取不到是个事实而不是崩溃 —— 空列表由调用方决定怎么说。
    """
    path = _env("INPUT_SIGNATURE_BUNDLE")
    if not path:
        return _fail(
            UsageError("signature-bundle 输入为空：没有 bundle 就没有透明日志条目")
        )
    try:
        entries = rekor_entries(Path(path))
    except EvidenceError as exc:
        return _fail(exc)
    _emit({"ok": True, "count": len(entries), "entries": entries})
    return EXIT_OK


def _multi(name: str) -> list[str]:
    """把一个多行 INPUT_* 环境变量读成参数列表。

    归一化放在这里而不是 shell：从 YAML 的多行块里读环境变量时缩进会整块带进来，
    `"  dist/"` 在收集器眼里就是一个不存在的路径 —— 少了一个 list 元素，
    却要一路走到「包里一个文件都没有」才看得出来。空行与 `#` 注释一样忽略。
    """
    items = []
    for line in (os.environ.get(name) or "").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            items.append(line)
    return items


COMMANDS = {"pack": cmd_pack, "verify": cmd_verify, "rekor": cmd_rekor}


def main(argv: list[str] | None = None) -> int:
    """按子命令分发。子命令是 shell 与内核之间的固定约定，敲错即停。"""
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1 or args[0] not in COMMANDS:
        _emit(
            {
                "ok": False,
                "exit_code": EXIT_TOOL_FAILURE,
                "error": f"用法：python -m evidence_pack.action {{{'|'.join(COMMANDS)}}}",
                "kind": "tool_failure",
                "error_kind": "tool_failure",
            }
        )
        return EXIT_TOOL_FAILURE
    return COMMANDS[args[0]]()


if __name__ == "__main__":
    sys.exit(main())
