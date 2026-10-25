"""签名层的本地契约：不用真 Fulcio，也不碰私钥。

私钥那条路已经从入口里删干净了，所以这里的每个用例都靠「假 cosign + 亲手捏的
bundle」来钉住判定逻辑：bundle 必须真的绑在这份字节上、退出码 0 不算数、
密码学层面的细节交给 test_keyless_oidc.py 里的证书窗口用例。
"""

import base64
import hashlib
import json
import os
import shutil
import stat
from pathlib import Path

import pytest

from evidence_pack.errors import EvidenceInvalid, ToolFailure, UsageError
from evidence_pack.signing import rekor_entries, sign, verify

pytestmark = pytest.mark.skipif(
    shutil.which("sh") is None or os.name != "posix",
    reason="需要 POSIX shell 造假的 cosign",
)

IDENTITY = "https://github.com/org/repo/.github/workflows/ci.yml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"
TOKEN = (
    "a" * 120
    + "."
    + base64.urlsafe_b64encode(json.dumps({"sub": IDENTITY, "iss": ISSUER}).encode())
    .decode()
    .rstrip("=")
    + "."
    + "c" * 60
)

BLOB = b"evidence"


def _fake_cosign(tmp_path: Path, body: str) -> Path:
    fake = tmp_path / "bin"
    fake.mkdir(exist_ok=True)
    script = fake / "cosign"
    script.write_text("#!/bin/sh\n" + body)
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return fake


def _bundle(digest_of: bytes = BLOB, *, cert: bool = True, tlog: bool = True) -> str:
    material: dict = {}
    if cert:
        material["x509CertificateChain"] = {"certificates": [{"rawBytes": ""}]}
    if tlog:
        material["tlogEntries"] = [{"integratedTime": "1700000000"}]
    return json.dumps(
        {
            "messageSignature": {
                "messageDigest": {
                    "algorithm": "SHA2_256",
                    "digest": base64.b64encode(
                        hashlib.sha256(digest_of).digest()
                    ).decode(),
                }
            },
            "verificationMaterial": material,
        }
    )


@pytest.fixture
def blob(tmp_path: Path) -> Path:
    path = tmp_path / "blob.bin"
    path.write_bytes(BLOB)
    return path


@pytest.fixture
def signed(tmp_path: Path, blob: Path, monkeypatch) -> tuple[Path, Path]:
    """用假 cosign 签出一份结构合法的 bundle：有证书链、有 tlog。"""
    bundle = tmp_path / "blob.sigstore.json"
    fake = _fake_cosign(
        tmp_path,
        f"cat > \"{bundle}\" <<'BUNDLE'\n{_bundle()}\nBUNDLE\nexit 0\n",
    )
    monkeypatch.setenv("PATH", f"{fake}:{os.environ['PATH']}")
    sign(blob, bundle, oidc_token=TOKEN)
    return blob, bundle


def test_sign_emits_only_sigstore_bundle(signed):
    _blob, bundle = signed
    assert bundle.is_file()
    assert not bundle.with_suffix(".sig").exists()
    assert not Path(str(bundle) + ".crt").exists()


def test_sign_requires_oidc_token(blob, tmp_path):
    """没有 token 就没有证书，也就没有身份 —— 当场判 1，不甩给 cosign。"""
    with pytest.raises(UsageError, match="OIDC token"):
        sign(blob, tmp_path / "b.sigstore.json")


def test_verify_good(signed, monkeypatch):
    blob, bundle = signed
    _fake_cosign(Path(bundle.parent), 'echo "Verified OK"\nexit 0\n')
    result = verify(blob, bundle, identity=IDENTITY, issuer=ISSUER)
    assert result.verified and result.mode == "keyless"
    assert result.tlog_checked is True


def test_verify_without_identity_is_rejected_locally(signed, monkeypatch):
    """给不出期望身份 = 接受任何人的签名，那不是验证。"""
    blob, bundle = signed
    called = []
    real_run = __import__("subprocess").run

    def spy(*args, **kwargs):
        called.append(args)
        return real_run(*args, **kwargs)

    monkeypatch.setattr("subprocess.run", spy)
    with pytest.raises(UsageError, match="identity"):
        verify(blob, bundle)
    assert called == [], "identity 缺失时不该真的去调 cosign"


def test_verify_key_is_gone_from_the_interface():
    """验签那侧也只剩短期证书一种身份：入口上不该还有 verify_key。"""
    import inspect

    assert "verify_key" not in inspect.signature(verify).parameters


def test_verify_tampered_blob_is_evidence_invalid(signed, tmp_path, monkeypatch):
    blob, bundle = signed
    _fake_cosign(tmp_path, 'echo "Verified OK"\nexit 0\n')
    tampered = tmp_path / "tampered.bin"
    tampered.write_bytes(b"evidence+evil")
    with pytest.raises(EvidenceInvalid, match="摘要"):
        verify(tampered, bundle, identity=IDENTITY, issuer=ISSUER)


def test_fake_cosign_exit_zero_but_no_output_is_tool_failure(
    signed, tmp_path, monkeypatch
):
    blob, bundle = signed
    _fake_cosign(tmp_path, "exit 0\n")
    with pytest.raises(ToolFailure, match="Verified OK"):
        verify(blob, bundle, identity=IDENTITY, issuer=ISSUER)


def test_fake_cosign_cannot_vouch_for_tampered_blob(signed, tmp_path, monkeypatch):
    _blob, bundle = signed
    tampered = tmp_path / "t.bin"
    tampered.write_bytes(b"nope")
    _fake_cosign(tmp_path, 'echo "Verified OK"\nexit 0\n')
    with pytest.raises(EvidenceInvalid, match="摘要"):
        verify(tampered, bundle, identity=IDENTITY, issuer=ISSUER)


def test_bundle_digest_must_bind_the_blob(tmp_path, blob, signed):
    _b, bundle = signed
    data = json.loads(bundle.read_text())
    data["messageSignature"]["messageDigest"]["digest"] = base64.b64encode(
        hashlib.sha256(b"something else").digest()
    ).decode()
    forged = tmp_path / "forged.sigstore.json"
    forged.write_text(json.dumps(data))
    _fake_cosign(tmp_path, 'echo "Verified OK"\nexit 0\n')
    with pytest.raises(EvidenceInvalid):
        verify(blob, forged, identity=IDENTITY, issuer=ISSUER)


def test_garbage_bundle_is_tool_failure(tmp_path, blob, monkeypatch):
    _fake_cosign(tmp_path, 'echo "Verified OK"\nexit 0\n')
    junk = tmp_path / "junk.sigstore.json"
    junk.write_text("{not json")
    with pytest.raises(ToolFailure):
        verify(blob, junk, identity=IDENTITY, issuer=ISSUER)


def test_bundle_without_tlog_is_invalid_even_if_cosign_says_ok(
    tmp_path, blob, monkeypatch
):
    """cosign 说 OK 也不够：keyless 的 bundle 必须有 tlog 落点。"""
    bundle = tmp_path / "b.sigstore.json"
    bundle.write_text(_bundle(tlog=False))
    fake = _fake_cosign(tmp_path, 'echo "Verified OK"\nexit 0\n')
    monkeypatch.setenv("PATH", f"{fake}:{os.environ['PATH']}")
    with pytest.raises(EvidenceInvalid, match="tlogEntries"):
        verify(blob, bundle, identity=IDENTITY, issuer=ISSUER)


# cosign v3.1.4 真实失败输出（原样摘录，缩进已还原成 strip 后的样子）。
# 横幅不是一行 —— 只挡首行会让"错误信息"变成一句隐私提示。
_COSIGN_V3_FULCIO_400 = """\
The sigstore service, hosted by sigstore a Series of LF Projects, LLC, is provided pursuant to the Hosted Project Tools Terms of Use, available at https://lfprojects.org/policies/hosted-project-tools-terms-of-use/.
Note that if your submission includes personal data associated with this signed artifact, it will be part of an immutable record.
This may include the email address associated with the account with which you authenticate your contractual Agreement.
This information will be used for signing this artifact and will be stored in public transparency logs and cannot be removed later, and is subject to the Immutable Record notice at https://lfprojects.org/policies/hosted-project-tools-immutable-records/.

By typing 'y', you attest that (1) you are not submitting the personal data of any other person; and (2) you understand and agree to the statement and the Agreement terms at the URLs listed above.
Generating ephemeral keys...
Using payload from: /tmp/blob.bin
Signing artifact...
Error: signing /tmp/blob.bin: signing bundle: error signing bundle: Fulcio returned 400: {"code":3,"message":"There was an error processing the identity token","details":[]}
error during command execution: signing /tmp/blob.bin: signing bundle: error signing bundle: Fulcio returned 400: {"code":3,"message":"There was an error processing the identity token","details":[]}
"""


def test_real_cosign_banner_is_not_reported_as_the_error(tmp_path, blob, monkeypatch):
    """从真 cosign 抄来的输出里，报出来的必须是 Fulcio 那句，不是隐私横幅。

    这条是实测踩到的：token 无效时 cosign 退出非 0，旧实现把
    `Note that if your submission includes personal data...` 当成了错误原因，
    用户看到的是免责声明，真正的原因（Fulcio 400）被埋掉了。
    """
    from evidence_pack.signing import _first_error

    proc = type("P", (), {"stderr": _COSIGN_V3_FULCIO_400, "stdout": ""})()
    detail = _first_error(proc)
    assert detail.startswith("signing /tmp/blob.bin")
    assert "Fulcio returned 400" in detail
    assert "personal data" not in detail


# --- 透明日志条目的展示层契约 -------------------------------------------------
# Release 正文要写的是「可复核的位置」，不是一句「已存证」。所以这几个用例钉的是
# 字段名与地址的拼法 —— 拼错了正文照样发得出去，只是没人能照着核对。


def _bundle_with_tlog(tmp_path: Path, entries: list[dict] | None) -> Path:
    bundle = tmp_path / "b.sigstore.json"
    bundle.write_text(
        json.dumps(
            {
                "messageSignature": {"messageDigest": {"digest": "AAAA"}},
                "verificationMaterial": {"tlogEntries": entries or []},
            }
        )
    )
    return bundle


def test_rekor_entries_flattens_log_index_and_url(tmp_path):
    bundle = _bundle_with_tlog(
        tmp_path,
        [
            {
                "logIndex": "987654321",
                "logId": {"keyId": "abcd"},
                "integratedTime": "1700000000",
            }
        ],
    )
    entries = rekor_entries(bundle)
    assert len(entries) == 1
    assert entries[0]["log_index"] == "987654321"
    assert entries[0]["log_id"] == "abcd"
    # 时间给人看，序号给机器核：两种都要有，少一样正文就白写了。
    assert entries[0]["integrated_time"].startswith("2023-11-14T22:13:20")
    assert entries[0]["url"] == (
        "https://rekor.sigstore.dev/api/v1/log/entries?logIndex=987654321"
    )


def test_rekor_entries_respects_custom_rekor_url(tmp_path):
    """私有 Rekor 部署时，地址不能写死成公共实例 —— 那会把人引到错的日志。"""
    bundle = _bundle_with_tlog(
        tmp_path,
        [{"logIndex": "7", "logId": {"keyId": "k"}, "integratedTime": "1700000000"}],
    )
    entries = rekor_entries(bundle, rekor_url="https://rekor.internal/")
    assert entries[0]["url"] == "https://rekor.internal/api/v1/log/entries?logIndex=7"


def test_rekor_entries_empty_when_no_tlog(tmp_path):
    """无 tlog 是「不构成证据」，不是崩溃：展示层返回空列表，判定交给 verify。"""
    assert rekor_entries(_bundle_with_tlog(tmp_path, None)) == []


def test_rekor_entries_does_not_invent_url_without_index(tmp_path):
    """序号缺了就宁可不给地址：拼一个空的 logIndex 比不给更误导。"""
    bundle = _bundle_with_tlog(tmp_path, [{"integratedTime": "1700000000"}])
    entries = rekor_entries(bundle)
    assert entries[0]["log_index"] == ""
    assert entries[0]["url"] == ""
