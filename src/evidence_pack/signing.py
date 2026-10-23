"""cosign bundle 签名层。

cosign v3 把 `--output-signature` / `--output-certificate` 这套两文件
形态整个废弃了，`.sigstore.json` bundle 是唯一前路。所以这里不为
兼容旧形态留任何分支：只产 `.sigstore.json`，不产 `.sig` / `.crt`。

核心是「一条路径，两种身份」：命令骨架相同，身份由 `--key` 或
`--certificate-identity/--certificate-oidc-issuer` 二选一注入。
不做 keyless/key 双分支——那正是原实现 `--certificate` 无条件加、
导致 key 模式必炸的根源。

另有一条铁律：**签名校验不能只信退出码**。原实现 `cosign` 返回 0 就
算 `signature_verified: true`，于是一个 `exit 0` 的假 cosign 就能骗过它。
这里除了退出码，还要独立核对三件事：
  1. bundle 的内容摘要 == 被打包文件的摘要（digest 绑定）
  2. bundle 的结构合法（有 messageSignature 或 DSSE 信封）
  3. keyless 模式下 bundle 里确有 tlog 条目，或明确标记 tlog_checked=false
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .errors import EvidenceInvalid, ToolFailure, UsageError
from .fsutil import sha256_file

DEFAULT_BUNDLE_SUFFIX = ".sigstore.json"


@dataclass
class SignatureResult:
    signed: bool = False
    verified: bool = False
    mode: str | None = None            # "key" | "keyless"
    tlog_checked: bool = False
    bundle_path: str | None = None
    detail: str = ""


def _require_cosign() -> str:
    exe = shutil.which("cosign")
    if not exe:
        raise ToolFailure("找不到 cosign。签名/验签需要 cosign v3+ 在 PATH 上。")
    return exe


def _first_error(proc: subprocess.CompletedProcess) -> str:
    """从 cosign 输出里挑出真正的错误行。

    cosign 会先在 stderr 打一段 Sigstore 服务条款横幅，直接取第一行
    等于把横幅当错误信息报给用户，毫无指向性。
    """
    for stream in (proc.stderr, proc.stdout):
        for line in (stream or "").splitlines():
            text = line.strip()
            if not text:
                continue
            if text.startswith("error during command execution:"):
                continue
            if text.startswith("The sigstore service"):
                continue
            return text
    return "未知错误"


def _run(cmd: list[str], password: str | None = None) -> subprocess.CompletedProcess:
    """cosign 只从 COSIGN_PASSWORD 读私钥口令，不接受命令行参数。

    不给口令时它会尝试从 TTY 交互读取，在 CI 里表现为莫名其妙的 ioctl 错误。
    """
    env = dict(os.environ)
    if password is not None:
        env["COSIGN_PASSWORD"] = password
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=False, env=env,
                              stdin=subprocess.DEVNULL)
    except OSError as exc:
        raise ToolFailure(f"cosign 无法执行：{exc}") from exc


def _resolve_mode(key: str | None, identity: str | None, issuer: str | None) -> str:
    if key and (identity or issuer):
        raise UsageError("--key 与 --identity/--issuer 互相排斥：要么持钥，要么 keyless。")
    if key:
        return "key"
    if not identity or not issuer:
        # 前移到本地：不把宽松判断交给 cosign。
        raise UsageError("keyless 必须同时提供 --identity 与 --issuer，否则等于接受任何人的签名。")
    return "keyless"


def sign(blob: Path, bundle: Path, *, key: str | None = None,
         password: str | None = None) -> SignatureResult:
    """对 blob 签名，产出 `.sigstore.json`。"""
    cosign = _require_cosign()
    cmd = [cosign, "sign-blob", "--yes", "--bundle", str(bundle)]
    if key:
        cmd += ["--key", key]
    cmd.append(str(blob))

    proc = _run(cmd, password)
    if proc.returncode != 0 or not bundle.is_file():
        raise ToolFailure(f"cosign sign-blob 失败：{_first_error(proc)}")
    return SignatureResult(
        signed=True,
        mode="key" if key else "keyless",
        bundle_path=str(bundle),
        detail="",
    )


def _check_bundle_structure(bundle: Path) -> dict:
    try:
        data = json.loads(bundle.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ToolFailure(f"bundle 不是合法 JSON：{exc}") from exc
    if not isinstance(data, dict):
        raise ToolFailure("bundle 顶层不是对象，不是 Sigstore bundle。")
    if "messageSignature" not in data and "dsseEnvelope" not in data:
        raise ToolFailure("bundle 里没有 messageSignature / dsseEnvelope，不是签名 bundle。")
    return data


def _bundle_digest(data: dict) -> str | None:
    msg = data.get("messageSignature") or {}
    digest = (msg.get("messageDigest") or {}).get("digest")
    if not digest:
        return None
    try:
        return base64.b64decode(digest).hex()
    except (ValueError, TypeError):
        return None


def _has_tlog(data: dict) -> bool:
    material = data.get("verificationMaterial") or {}
    return bool(material.get("tlogEntries"))


def verify(
    blob: Path,
    bundle: Path,
    *,
    key: str | None = None,
    identity: str | None = None,
    issuer: str | None = None,
    ignore_tlog: bool = False,
    password: str | None = None,
) -> SignatureResult:
    """验签。返回结构化的结果，失败按语义抛 EvidenceInvalid 或 ToolFailure。"""
    cosign = _require_cosign()
    mode = _resolve_mode(key, identity, issuer)

    data = _check_bundle_structure(bundle)

    # 第一道闸：bundle 必须真的绑在我们要验的这份字节上。
    # 假 cosign 返回 0 也过不了这一关。
    bound = _bundle_digest(data)
    actual = sha256_file(blob)
    if bound is not None and bound != actual:
        raise EvidenceInvalid(
            f"bundle 的内容摘要与文件不符：bundle 绑定 {bound}，文件实际 {actual}。"
        )

    cmd = [cosign, "verify-blob", "--bundle", str(bundle)]
    if mode == "key":
        cmd += ["--key", key or ""]
        if ignore_tlog:
            cmd.append("--insecure-ignore-tlog=true")
    else:
        cmd += [
            "--certificate-identity", identity or "",
            "--certificate-oidc-issuer", issuer or "",
        ]
        if ignore_tlog:
            cmd.append("--insecure-ignore-tlog=true")
    cmd.append(str(blob))

    proc = _run(cmd, password)
    if proc.returncode != 0:
        raise EvidenceInvalid(f"签名无效：{_first_error(proc)}")

    # 退出码 0 不足以证明"真的验过"：一个 `exit 0` 的假 cosign 也能过关。
    # 正向证据是 cosign 必须在 stdout 打出 "Verified OK"。
    # 这不是密码学保证（假程序也能打印这行），但把欺骗成本从
    # "空脚本 exit 0" 抬高到 "伪造 cosign 输出"，再叠加下游的锚点交叉校验。
    if "Verified OK" not in (proc.stdout + proc.stderr):
        raise ToolFailure(
            "cosign 退出码为 0 但未输出 Verified OK：无法确认签名真的被校验过"
            f"（stdout={proc.stdout.strip()[:120]!r}）。"
        )

    tlog_present = _has_tlog(data)
    if mode == "keyless" and not ignore_tlog and not tlog_present:
        raise EvidenceInvalid("keyless 验签通过但 bundle 内无透明日志条目（tlogEntries 为空）。")

    return SignatureResult(
        verified=True,
        mode=mode,
        tlog_checked=tlog_present and not ignore_tlog,
        bundle_path=str(bundle),
        detail="",
    )
