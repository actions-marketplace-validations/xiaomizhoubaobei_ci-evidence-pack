"""cosign bundle 签名层。

cosign v3 把 `--output-signature` / `--output-certificate` 这套两文件
形态整个废弃了，`.sigstore.json` bundle 是唯一前路。所以这里不为
兼容旧形态留任何分支：只产 `.sigstore.json`，不产 `.sig` / `.crt`。

核心是「一条路径，两种身份」：命令骨架相同，身份由 `--key` 或
`--certificate-identity/--certificate-oidc-issuer` 二选一注入。
不做 keyless/key 双分支——那正是原实现 `--certificate` 无条件加、
导致 key 模式必炸的根源。

keyless 的实质是 **OIDC 换短期证书**：CI 用平台签发的 OIDC token 向 Fulcio
证明"我是谁"，Fulcio 回一张 10 分钟就过期的证书，cosign 拿这张证书签字节，
再把证书链、签名和 Rekor 条目一起封进 bundle。所以 keyless 签名**必须有
token**——没有 token 就没有证书，没有证书就没有信任根。

token 从哪来：极少数情况下走 `--oidc-token` 显式传入（仅建议本地调试），
主路径是 `--oidc-token-env VAR` 从环境变量读，CI 里由平台注入。两种写法
都只进子进程环境，**绝不进命令行**——命令行参数会出现在 `ps`、作业日志和
调试输出里，token 一旦漏出去，别人就能拿你的身份去签任何东西。

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
    # keyless 专有：这张证书就是本次签名的短期身份，过期即失效。
    certificate_identity: str | None = None
    certificate_issuer: str | None = None
    cert_not_before: str | None = None
    cert_not_after: str | None = None
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


def _run(cmd: list[str], password: str | None = None,
         extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    """cosign 只从 COSIGN_PASSWORD 读私钥口令，不接受命令行参数。

    不给口令时它会尝试从 TTY 交互读取，在 CI 里表现为莫名其妙的 ioctl 错误。
    同理，OIDC token 走 SIGSTORE_ID_TOKEN 环境变量，不拼进 argv。
    """
    env = dict(os.environ)
    if password is not None:
        env["COSIGN_PASSWORD"] = password
    if extra_env:
        env.update(extra_env)
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=False, env=env,
                              stdin=subprocess.DEVNULL)
    except OSError as exc:
        raise ToolFailure(f"cosign 无法执行：{exc}") from exc


# Fulcio / Rekor 的公共实例。私有部署时用 --fulcio-url / --rekor-url 覆盖，
# 注意验签侧必须用**同一个** Fulcio 根，否则证书链对不上，那是 2 不是 3。
DEFAULT_FULCIO_URL = "https://fulcio.sigstore.dev"
DEFAULT_REKOR_URL = "https://rekor.sigstore.dev"

# OIDC token 只允许经环境变量进子进程。命令行里出现 token 等于把它写进作业日志。
MIN_TOKEN_LEN = 100


def resolve_oidc_token(token: str | None = None, token_env: str | None = None) -> str | None:
    """取 OIDC token：显式值优先，其次按环境变量名读。

    刻意不对空串宽容：CI 里 token 变量存在但为空（权限没开、secret 没配）
    是最常见的事故，静默回落到"没 token"会让调用方以为签过了。
    """
    if token and token_env:
        raise UsageError("--oidc-token 与 --oidc-token-env 只给一个：token 不该有两条来源。")
    if token_env:
        value = os.environ.get(token_env)
        if not value:
            raise UsageError(f"环境变量 {token_env} 不存在或为空：拿不到 OIDC token，无法换短期证书。")
        return _check_token_shape(value, f"环境变量 {token_env}")
    if token:
        return _check_token_shape(token, "--oidc-token")
    return None


def _check_token_shape(token: str, source: str) -> str:
    """只做形状检查（三段式 JWT、足够长），不解析、不校验签名。

    token 的真伪由 Fulcio 判定，本地解析除了把 token 内容多写进日志之外
    没有任何收益。这里只拦住"明显不是 token"的输入，让用户在 1 的地方停下，
    而不是等 cosign 报一个看不懂的 HTTP 错误变成 3。
    """
    compact = token.strip()
    if len(compact) < MIN_TOKEN_LEN or compact.count(".") != 2:
        raise UsageError(f"{source} 看起来不是 OIDC JWT（需要三段式且长度 >= {MIN_TOKEN_LEN}）。")
    return compact


def _decode_jwt_claims(token: str) -> dict:
    """读取 JWT payload 里的身份声明（iss/sub）。

    仅用于**回显便于核对**，不作为验签依据：bundle 里自带证书，
    验签时 cosign 会按 --certificate-identity / --certificate-oidc-issuer 硬比。
    """
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload))
    except (IndexError, ValueError, TypeError):
        return {}
    return claims if isinstance(claims, dict) else {}


def _keyless_env(token: str, *, fulcio_url: str | None, rekor_url: str | None) -> dict[str, str]:
    """token 与私有实例地址都经环境变量下发，argv 里只留非敏感开关。"""
    env = {"SIGSTORE_ID_TOKEN": token}
    if fulcio_url:
        env["SIGSTORE_FULCIO_URL"] = fulcio_url
    if rekor_url:
        env["SIGSTORE_REKOR_URL"] = rekor_url
    return env


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
         password: str | None = None, oidc_token: str | None = None,
         fulcio_url: str | None = None, rekor_url: str | None = None) -> SignatureResult:
    """对 blob 签名，产出 `.sigstore.json`。

    两条路径：
      key 模式  —— 用私钥签，无 OIDC、无证书；
      keyless   —— 用 OIDC token 向 Fulcio 换短期证书再签，token 缺失当场判 1，
                   不把"没 token"这种用法问题留给 cosign 抛出难懂的 HTTP 错误。
    """
    # 用法矛盾先于环境缺失判定：参数敲错了，跑到哪一步都不该被报成"工具坏了"。
    if key and oidc_token:
        raise UsageError("--key 与 OIDC token 互相排斥：要么持钥，要么用短期证书。")
    extra_env: dict[str, str] = {}
    claims: dict = {}
    if not key:
        if not oidc_token:
            raise UsageError(
                "keyless 签名必须有 OIDC token（--oidc-token 或 --oidc-token-env）："
                "没有 token 就换不到 Fulcio 短期证书，签出来的东西没有身份可言。"
            )
        extra_env = _keyless_env(oidc_token, fulcio_url=fulcio_url, rekor_url=rekor_url)
        claims = _decode_jwt_claims(oidc_token)

    cosign = _require_cosign()

    cmd = [cosign, "sign-blob", "--yes", "--bundle", str(bundle)]
    if key:
        cmd += ["--key", key]
    else:
        # --identity-token 与 SIGSTORE_ID_TOKEN 等价，但前者会进 argv。只用环境变量。
        if fulcio_url:
            cmd += ["--fulcio-url", fulcio_url]
        if rekor_url:
            cmd += ["--rekor-url", rekor_url]
    cmd.append(str(blob))

    proc = _run(cmd, password, extra_env=extra_env)
    if proc.returncode != 0 or not bundle.is_file():
        raise ToolFailure(f"cosign sign-blob 失败：{_first_error(proc)}")

    result = SignatureResult(
        signed=True,
        mode="key" if key else "keyless",
        bundle_path=str(bundle),
        certificate_identity=claims.get("sub"),
        certificate_issuer=claims.get("iss"),
        detail="",
    )
    if result.mode == "keyless":
        # 短期证书的形态在这里就地核对：bundle 必须带证，tlog 必须有条目。
        # 缺证书 = 拿不到身份（3）；拿不到 tlog = 签名失去了公开可审计的落点（3）。
        data = _check_bundle_structure(bundle)
        material = data.get("verificationMaterial") or {}
        chain = material.get("x509CertificateChain") or {}
        certs = chain.get("certificates") or []
        if not certs:
            raise ToolFailure("keyless 签出的 bundle 里没有 x509 证书链：Fulcio 短期证书没拿到。")
        if not material.get("tlogEntries"):
            raise ToolFailure(
                "keyless 签出的 bundle 里没有 tlogEntries：Rekor 未记录，无法证明签名存在过。"
                "检查 SIGSTORE_REKOR_URL 与网络。"
            )
        result.tlog_checked = True
        _fill_cert_window(result, certs[0])
    return result


def _fill_cert_window(result: SignatureResult, leaf: dict) -> None:
    """从叶子证书里取出有效期，填进结果里。

    用 `openssl` 解 DER 是可选的：openssl 不在就留空。它是给人看的佐证，
    不是判定依据，不能因为缺工具就让验签结论变成 3。
    """
    raw = leaf.get("rawBytes") if isinstance(leaf, dict) else None
    if not raw:
        return
    exe = shutil.which("openssl")
    if not exe:
        return
    try:
        der = base64.b64decode(raw)
        proc = subprocess.run(
            [exe, "x509", "-inform", "DER", "-noout", "-startdate", "-enddate"],
            input=der, capture_output=True, check=False,
        )
    except (OSError, ValueError, TypeError):
        return
    if proc.returncode != 0:
        return
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        key, _, value = line.partition("=")
        value = value.strip()
        if key.strip() == "notBefore":
            result.cert_not_before = _iso8601(value)
        elif key.strip() == "notAfter":
            result.cert_not_after = _iso8601(value)


def _iso8601(value: str) -> str:
    """openssl 给的是 `Oct 24 00:37:00 2026 GMT`，换成便于机读的 ISO 8601。"""
    from datetime import datetime, timezone

    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        ).isoformat()
    except ValueError:
        return value


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

    result = SignatureResult(
        verified=True,
        mode=mode,
        tlog_checked=tlog_present and not ignore_tlog,
        bundle_path=str(bundle),
        detail="",
    )
    if mode == "keyless":
        # 短期证书的窗口必须覆盖 bundle 内记录的签名时间。
        # 证书十分钟就过期，若 Rekor 记录的签名时刻落在窗口之外，
        # 说明这份 bundle 不是这张证书在那段时间签的 —— 证据链断裂（2）。
        _check_certificate_window(data)
        material = data.get("verificationMaterial") or {}
        certs = ((material.get("x509CertificateChain") or {}).get("certificates")) or []
        if certs:
            _fill_cert_window(result, certs[0])
    return result


def _check_certificate_window(data: dict) -> None:
    """核对短期证书的有效期与 bundle 里的签名时间是否相容。

    取 bundle 内 Rekor 的 integratedTime 与证书 DER 里的窗口比对；
    两者任一取不到就不作判定（缺 openssl 是环境问题，不能因此判人篡改）。
    """
    material = data.get("verificationMaterial") or {}
    certs = ((material.get("x509CertificateChain") or {}).get("certificates")) or []
    if not certs:
        return
    signed_ats = [
        int(entry["integratedTime"])
        for entry in (material.get("tlogEntries") or [])
        if isinstance(entry, dict) and str(entry.get("integratedTime", "")).isdigit()
    ]
    if not signed_ats:
        return

    window = _cert_window(certs[0])
    if window is None:
        return
    not_before, not_after = window
    for ts in signed_ats:
        if not (not_before <= ts <= not_after):
            raise EvidenceInvalid(
                "签名时间落在短期证书有效期之外："
                f"证书窗口 {_fmt(not_before)} ~ {_fmt(not_after)}，Rekor 记录 {_fmt(ts)}。"
            )


def _fmt(epoch: int) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(epoch, timezone.utc).isoformat()


def _cert_window(leaf: dict) -> tuple[int, int] | None:
    """用 openssl 取证书的 notBefore/notAfter 并转成 epoch 秒。"""
    from datetime import datetime, timezone

    raw = leaf.get("rawBytes") if isinstance(leaf, dict) else None
    exe = shutil.which("openssl")
    if not raw or not exe:
        return None
    try:
        der = base64.b64decode(raw)
        proc = subprocess.run(
            [exe, "x509", "-inform", "DER", "-noout", "-startdate", "-enddate"],
            input=der, capture_output=True, check=False,
        )
    except (OSError, ValueError, TypeError):
        return None
    if proc.returncode != 0:
        return None

    values: dict[str, int] = {}
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        key, _, value = line.partition("=")
        try:
            stamp = datetime.strptime(value.strip(), "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            continue
        values[key.strip()] = int(stamp.timestamp())
    if "notBefore" not in values or "notAfter" not in values:
        return None
    return values["notBefore"], values["notAfter"]
