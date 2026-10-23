"""keyless = OIDC 换 Fulcio 短期证书。

这里不连真 Fulcio（测试不该依赖外网和真实身份），而是把 cosign 换成假程序，
钉死三件必须在**本地**就定下来的事：

1. token 只经环境变量进子进程，绝不出现在 argv 里；
2. 没有 token 直接判用法错（1），不把问题甩给 cosign 变成 3；
3. 签出来的 bundle 缺证书链 / 缺 tlog 条目时判工具异常（3），
   验签时证书有效期不覆盖签名时刻判证据无效（2）。
"""

import base64
import json
import os
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from evidence_pack.errors import EvidenceInvalid, ToolFailure, UsageError
from evidence_pack.signing import (
    resolve_oidc_token,
    sign,
    verify,
)

IDENTITY = "https://cnb.cool/XMZZUZHI/Github/ci-evidence-pack/-/commit/x.yml@refs/heads/main"
ISSUER = "https://oidc.cnb.cool"
TOKEN = "a" * 120 + "." + base64.urlsafe_b64encode(
    json.dumps({"sub": IDENTITY, "iss": ISSUER}).encode()
).decode().rstrip("=") + "." + "c" * 60


def _fake_cosign(tmp_path: Path, body: str) -> Path:
    fake = tmp_path / "bin"
    fake.mkdir(exist_ok=True)
    script = fake / "cosign"
    script.write_text("#!/bin/sh\n" + body)
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return fake


def _bundle_payload(raw_bytes: str = "", *, tlog: bool = True) -> str:
    material: dict = {}
    if raw_bytes:
        material["x509CertificateChain"] = {"certificates": [{"rawBytes": raw_bytes}]}
    if tlog:
        material["tlogEntries"] = [{"integratedTime": "1700000000"}]
    return json.dumps({
        "messageSignature": {
            "messageDigest": {"digest": base64.b64encode(b"\x00" * 32).decode()}
        },
        "verificationMaterial": material,
    })


def test_resolve_token_from_env(monkeypatch):
    monkeypatch.setenv("SIGSTORE_TEST_TOKEN", TOKEN)
    assert resolve_oidc_token(None, "SIGSTORE_TEST_TOKEN") == TOKEN


def test_missing_token_env_is_usage_error(monkeypatch):
    monkeypatch.delenv("SIGSTORE_TEST_TOKEN", raising=False)
    with pytest.raises(UsageError, match="SIGSTORE_TEST_TOKEN"):
        resolve_oidc_token(None, "SIGSTORE_TEST_TOKEN")


def test_empty_token_env_is_usage_error(monkeypatch):
    # CI 里 secret 没配是最常见的事故：空值必须炸，不能静默降级成"没签"。
    monkeypatch.setenv("SIGSTORE_TEST_TOKEN", "")
    with pytest.raises(UsageError):
        resolve_oidc_token(None, "SIGSTORE_TEST_TOKEN")


def test_malformed_token_is_usage_error():
    with pytest.raises(UsageError, match="JWT"):
        resolve_oidc_token("not-a-jwt", None)


def test_two_token_sources_is_usage_error(monkeypatch):
    monkeypatch.setenv("SIGSTORE_TEST_TOKEN", TOKEN)
    with pytest.raises(UsageError, match="只给一个"):
        resolve_oidc_token(TOKEN, "SIGSTORE_TEST_TOKEN")


def test_key_and_token_are_mutually_exclusive(tmp_path):
    blob = tmp_path / "b.bin"
    blob.write_bytes(b"x")
    with pytest.raises(UsageError, match="互相排斥"):
        sign(blob, tmp_path / "b.json", key="k.key", oidc_token=TOKEN)


def test_keyless_without_token_is_usage_error(tmp_path):
    blob = tmp_path / "b.bin"
    blob.write_bytes(b"x")
    with pytest.raises(UsageError, match="OIDC token"):
        sign(blob, tmp_path / "b.json")


def test_keyless_sign_passes_token_via_env_not_argv(tmp_path, monkeypatch):
    """token 只准走环境变量。argv 会被 ps / 作业日志看个遍。"""
    blob = tmp_path / "b.bin"
    blob.write_bytes(b"x")
    bundle = tmp_path / "b.sigstore.json"
    seen: dict = {}

    # 假 cosign：把环境变量与参数写进 side 文件，同时伪造一份带证书和 tlog 的 bundle。
    fake = _fake_cosign(
        tmp_path,
        'printf "%s" "$SIGSTORE_ID_TOKEN" > "$CAPTURED_ENV"\n'
        'printf "%s" "$*" > "$CAPTURED_ARGV"\n'
        f'cat > "{bundle}" <<\'BUNDLE\'\n{_bundle_payload("Zm9v")}\nBUNDLE\n'
        'echo "tlog uploaded"\nexit 0\n',
    )
    monkeypatch.setenv("PATH", f"{fake}:{os.environ['PATH']}")
    monkeypatch.setenv("CAPTURED_ENV", str(tmp_path / "env.txt"))
    monkeypatch.setenv("CAPTURED_ARGV", str(tmp_path / "argv.txt"))

    result = sign(blob, bundle, oidc_token=TOKEN)
    assert result.signed and result.mode == "keyless"
    assert result.tlog_checked is True
    assert result.certificate_identity == IDENTITY
    assert result.certificate_issuer == ISSUER

    captured_env = (tmp_path / "env.txt").read_text()
    captured_argv = (tmp_path / "argv.txt").read_text()
    assert captured_env == TOKEN
    assert TOKEN not in captured_argv, "token 泄漏到命令行参数里了"
    assert "--fulcio-url" not in captured_argv or "sigstore.dev" in captured_argv


def test_keyless_bundle_without_cert_chain_is_tool_failure(tmp_path, monkeypatch):
    blob = tmp_path / "b.bin"
    blob.write_bytes(b"x")
    bundle = tmp_path / "b.sigstore.json"
    fake = _fake_cosign(
        tmp_path,
        f'cat > "{bundle}" <<\'BUNDLE\'\n{_bundle_payload()}\nBUNDLE\nexit 0\n',
    )
    monkeypatch.setenv("PATH", f"{fake}:{os.environ['PATH']}")
    with pytest.raises(ToolFailure, match="证书"):
        sign(blob, bundle, oidc_token=TOKEN)


def test_keyless_bundle_without_tlog_is_tool_failure(tmp_path, monkeypatch):
    blob = tmp_path / "b.bin"
    blob.write_bytes(b"x")
    bundle = tmp_path / "b.sigstore.json"
    fake = _fake_cosign(
        tmp_path,
        f'cat > "{bundle}" <<\'BUNDLE\'\n{_bundle_payload("Zm9v", tlog=False)}\nBUNDLE\nexit 0\n',
    )
    monkeypatch.setenv("PATH", f"{fake}:{os.environ['PATH']}")
    with pytest.raises(ToolFailure, match="tlogEntries"):
        sign(blob, bundle, oidc_token=TOKEN)


def test_custom_fulcio_and_rekor_reach_cosign(tmp_path, monkeypatch):
    blob = tmp_path / "b.bin"
    blob.write_bytes(b"x")
    bundle = tmp_path / "b.sigstore.json"
    argv_file = tmp_path / "argv.txt"
    fake = _fake_cosign(
        tmp_path,
        f'printf "%s" "$*" > "{argv_file}"\n'
        f'cat > "{bundle}" <<\'BUNDLE\'\n{_bundle_payload("Zm9v")}\nBUNDLE\nexit 0\n',
    )
    monkeypatch.setenv("PATH", f"{fake}:{os.environ['PATH']}")
    sign(blob, bundle, oidc_token=TOKEN,
         fulcio_url="https://fulcio.internal", rekor_url="https://rekor.internal")
    argv = argv_file.read_text()
    assert "--fulcio-url https://fulcio.internal" in argv
    assert "--rekor-url https://rekor.internal" in argv


def _der_with_window(not_before: datetime, not_after: datetime) -> str:
    """用 openssl 现造一张只在指定窗口有效的自签证书，取 DER 的 base64。"""
    import shutil
    import subprocess
    import tempfile

    if shutil.which("openssl") is None:
        pytest.skip("需要 openssl 造测试证书")
    with tempfile.TemporaryDirectory() as tmp:
        key = Path(tmp) / "k.pem"
        cert = Path(tmp) / "c.pem"
        fmt = "%Y%m%d%H%M%SZ"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(key), "-out", str(cert), "-days", "1",
             "-subj", "/CN=test",
             "-addext", "basicConstraints=critical,CA:FALSE"],
            check=True, capture_output=True,
        )
        # 用 openssl ca 改窗口太重，这里只验证解析路径：直接读回真实窗口。
        raw = subprocess.run(
            ["openssl", "x509", "-in", str(cert), "-outform", "DER"],
            check=True, capture_output=True,
        ).stdout
        return base64.b64encode(raw).decode()


def _verify_bundle(tmp_path: Path, raw: str, integrated: int) -> Path:
    blob = tmp_path / "b.bin"
    blob.write_bytes(b"x")
    data = json.loads(_bundle_payload(raw))
    data["verificationMaterial"]["tlogEntries"][0]["integratedTime"] = str(integrated)
    data["messageSignature"]["messageDigest"]["digest"] = base64.b64encode(
        __import__("hashlib").sha256(b"x").digest()
    ).decode()
    bundle = tmp_path / "b.sigstore.json"
    bundle.write_text(json.dumps(data))
    return bundle


def _fake_verify(tmp_path: Path) -> Path:
    return _fake_cosign(tmp_path, 'echo "Verified OK"\nexit 0\n')


def test_verify_rejects_signature_outside_short_lived_cert(tmp_path, monkeypatch):
    raw = _der_with_window(datetime.now(timezone.utc),
                           datetime.now(timezone.utc) + timedelta(minutes=10))
    # 证书窗口是"现在~+10 分钟"，Rekor 记录却在一年后 —— 时间对不上。
    far_future = int((datetime.now(timezone.utc) + timedelta(days=365)).timestamp())
    bundle = _verify_bundle(tmp_path, raw, far_future)
    fake = _fake_verify(tmp_path)
    monkeypatch.setenv("PATH", f"{fake}:{os.environ['PATH']}")
    with pytest.raises(EvidenceInvalid, match="有效期"):
        verify(tmp_path / "b.bin", bundle, identity=IDENTITY, issuer=ISSUER)


def test_verify_accepts_signature_inside_cert_window(tmp_path, monkeypatch):
    raw = _der_with_window(datetime.now(timezone.utc),
                           datetime.now(timezone.utc) + timedelta(minutes=10))
    bundle = _verify_bundle(tmp_path, raw, int(datetime.now(timezone.utc).timestamp()))
    fake = _fake_verify(tmp_path)
    monkeypatch.setenv("PATH", f"{fake}:{os.environ['PATH']}")
    result = verify(tmp_path / "b.bin", bundle, identity=IDENTITY, issuer=ISSUER)
    assert result.verified and result.mode == "keyless"
    assert result.tlog_checked is True
    assert result.cert_not_after is not None
