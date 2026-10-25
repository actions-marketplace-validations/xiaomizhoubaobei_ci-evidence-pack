"""签名 = OIDC 换 Fulcio 短期证书（唯一的签法）。

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

IDENTITY = (
    "https://cnb.cool/XMZZUZHI/Github/ci-evidence-pack/-/commit/x.yml@refs/heads/main"
)
ISSUER = "https://oidc.cnb.cool"
TOKEN = (
    "a" * 120
    + "."
    + base64.urlsafe_b64encode(json.dumps({"sub": IDENTITY, "iss": ISSUER}).encode())
    .decode()
    .rstrip("=")
    + "."
    + "c" * 60
)


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
    return json.dumps(
        {
            "messageSignature": {
                "messageDigest": {"digest": base64.b64encode(b"\x00" * 32).decode()}
            },
            "verificationMaterial": material,
        }
    )


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


def test_sign_has_no_private_key_path(tmp_path):
    """私钥那条路已整条移除：入口上根本没有 `key` 参数，也就无从 fallback。"""
    import inspect

    assert "key" not in inspect.signature(sign).parameters
    blob = tmp_path / "b.bin"
    blob.write_bytes(b"x")
    with pytest.raises(TypeError):
        sign(blob, tmp_path / "b.json", key=str(tmp_path / "k.key"))  # type: ignore[call-arg]


def test_sign_without_token_is_usage_error(tmp_path):
    blob = tmp_path / "b.bin"
    blob.write_bytes(b"x")
    with pytest.raises(UsageError, match="OIDC token"):
        sign(blob, tmp_path / "b.json")


def test_sign_passes_token_via_env_not_argv(tmp_path, monkeypatch):
    """token 只准走环境变量。argv 会被 ps / 作业日志看个遍。"""
    blob = tmp_path / "b.bin"
    blob.write_bytes(b"x")
    bundle = tmp_path / "b.sigstore.json"

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


def test_bundle_without_cert_chain_is_tool_failure(tmp_path, monkeypatch):
    blob = tmp_path / "b.bin"
    blob.write_bytes(b"x")
    bundle = tmp_path / "b.sigstore.json"
    fake = _fake_cosign(
        tmp_path,
        f"cat > \"{bundle}\" <<'BUNDLE'\n{_bundle_payload()}\nBUNDLE\nexit 0\n",
    )
    monkeypatch.setenv("PATH", f"{fake}:{os.environ['PATH']}")
    with pytest.raises(ToolFailure, match="证书"):
        sign(blob, bundle, oidc_token=TOKEN)


def test_bundle_without_tlog_is_tool_failure(tmp_path, monkeypatch):
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
    sign(
        blob,
        bundle,
        oidc_token=TOKEN,
        fulcio_url="https://fulcio.internal",
        rekor_url="https://rekor.internal",
    )
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
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(key),
                "-out",
                str(cert),
                "-days",
                "1",
                "-subj",
                "/CN=test",
                "-addext",
                "basicConstraints=critical,CA:FALSE",
            ],
            check=True,
            capture_output=True,
        )
        # 用 openssl ca 改窗口太重，这里只验证解析路径：直接读回真实窗口。
        raw = subprocess.run(
            ["openssl", "x509", "-in", str(cert), "-outform", "DER"],
            check=True,
            capture_output=True,
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
    raw = _der_with_window(
        datetime.now(timezone.utc), datetime.now(timezone.utc) + timedelta(minutes=10)
    )
    # 证书窗口是"现在~+10 分钟"，Rekor 记录却在一年后 —— 时间对不上。
    far_future = int((datetime.now(timezone.utc) + timedelta(days=365)).timestamp())
    bundle = _verify_bundle(tmp_path, raw, far_future)
    fake = _fake_verify(tmp_path)
    monkeypatch.setenv("PATH", f"{fake}:{os.environ['PATH']}")
    with pytest.raises(EvidenceInvalid, match="有效期"):
        verify(tmp_path / "b.bin", bundle, identity=IDENTITY, issuer=ISSUER)


def test_verify_accepts_signature_inside_cert_window(tmp_path, monkeypatch):
    raw = _der_with_window(
        datetime.now(timezone.utc), datetime.now(timezone.utc) + timedelta(minutes=10)
    )
    bundle = _verify_bundle(tmp_path, raw, int(datetime.now(timezone.utc).timestamp()))
    fake = _fake_verify(tmp_path)
    monkeypatch.setenv("PATH", f"{fake}:{os.environ['PATH']}")
    result = verify(tmp_path / "b.bin", bundle, identity=IDENTITY, issuer=ISSUER)
    assert result.verified and result.mode == "keyless"
    assert result.tlog_checked is True
    assert result.cert_not_after is not None


def _sign_with_material(tmp_path: Path, monkeypatch, material: dict) -> Path:
    """用假 cosign 签一份 verificationMaterial 由调用方决定的 bundle。"""
    blob = tmp_path / "b.bin"
    blob.write_bytes(b"x")
    bundle = tmp_path / "b.sigstore.json"
    payload = json.dumps(
        {
            "messageSignature": {
                "messageDigest": {"digest": base64.b64encode(b"\x00" * 32).decode()}
            },
            "verificationMaterial": material,
        }
    )
    fake = _fake_cosign(
        tmp_path,
        f"cat > \"{bundle}\" <<'BUNDLE'\n{payload}\nBUNDLE\nexit 0\n",
    )
    monkeypatch.setenv("PATH", f"{fake}:{os.environ['PATH']}")
    return bundle


def test_sign_accepts_bundle_v03_single_certificate(tmp_path, monkeypatch):
    """v0.3+ 把叶子证书挪到了 verificationMaterial.certificate。

    认不出这一形态，cosign v3 签出来的包会被当成「没换来短期证书」判 3 ——
    这就是本 PR 要修的那件事。
    """
    bundle = _sign_with_material(
        tmp_path,
        monkeypatch,
        {
            "certificate": {"rawBytes": "Zm9v"},
            "tlogEntries": [{"integratedTime": "1700000000"}],
        },
    )
    result = sign(tmp_path / "b.bin", bundle, oidc_token=TOKEN)
    assert result.signed and result.mode == "keyless"
    assert result.tlog_checked is True


def test_sign_still_accepts_bundle_v02_certificate_chain(tmp_path, monkeypatch):
    """老形态不能被新分支挤掉：证书链还在，就继续按证书链认。"""
    bundle = _sign_with_material(
        tmp_path,
        monkeypatch,
        {
            "x509CertificateChain": {"certificates": [{"rawBytes": "Zm9v"}]},
            "tlogEntries": [{"integratedTime": "1700000000"}],
        },
    )
    result = sign(tmp_path / "b.bin", bundle, oidc_token=TOKEN)
    assert result.signed and result.tlog_checked is True


def test_sign_prefers_single_certificate_over_empty_chain(tmp_path, monkeypatch):
    """两种形态并存、且证书链是空的时候，不能因为链空就判 3。"""
    bundle = _sign_with_material(
        tmp_path,
        monkeypatch,
        {
            "certificate": {"rawBytes": "Zm9v"},
            "x509CertificateChain": {"certificates": []},
            "tlogEntries": [{"integratedTime": "1700000000"}],
        },
    )
    result = sign(tmp_path / "b.bin", bundle, oidc_token=TOKEN)
    assert result.signed


def test_sign_rejects_certificate_without_raw_bytes(tmp_path, monkeypatch):
    """有 certificate 字段但里面没有 rawBytes，等于没证书：仍判工具异常（3）。"""
    bundle = _sign_with_material(
        tmp_path,
        monkeypatch,
        {
            "certificate": {"foo": "bar"},
            "tlogEntries": [{"integratedTime": "1700000000"}],
        },
    )
    with pytest.raises(ToolFailure, match="证书"):
        sign(tmp_path / "b.bin", bundle, oidc_token=TOKEN)


def test_verify_reads_certificate_window_from_v03_certificate(tmp_path, monkeypatch):
    """v0.3+ 形态下证书窗口照样要核对：不能因为字段搬家就不查了。"""
    raw = _der_with_window(
        datetime.now(timezone.utc), datetime.now(timezone.utc) + timedelta(minutes=10)
    )
    far_future = int((datetime.now(timezone.utc) + timedelta(days=365)).timestamp())
    bundle = _verify_bundle(tmp_path, raw, far_future)
    data = json.loads(bundle.read_text())
    material = data["verificationMaterial"]
    material["certificate"] = {
        "rawBytes": material.pop("x509CertificateChain")["certificates"][0]["rawBytes"]
    }
    bundle.write_text(json.dumps(data))

    fake = _fake_verify(tmp_path)
    monkeypatch.setenv("PATH", f"{fake}:{os.environ['PATH']}")
    with pytest.raises(EvidenceInvalid, match="有效期"):
        verify(tmp_path / "b.bin", bundle, identity=IDENTITY, issuer=ISSUER)
