import json
import os
import subprocess
import shutil
import stat
import base64
import hashlib
from pathlib import Path

import pytest

from evidence_pack.errors import EvidenceInvalid, ToolFailure, UsageError
from evidence_pack.signing import sign, verify

pytestmark = pytest.mark.skipif(shutil.which("cosign") is None, reason="需要 cosign v3+")


PASSWORD = "test-only"


@pytest.fixture
def signed(tmp_path):
    key_prefix = tmp_path / "k"
    env = dict(os.environ, COSIGN_PASSWORD=PASSWORD)
    proc = subprocess.run(
        ["cosign", "generate-key-pair", "--output-key-prefix", str(key_prefix)],
        capture_output=True, text=True, check=False, env=env, stdin=subprocess.DEVNULL,
    )
    assert proc.returncode == 0, proc.stderr
    blob = tmp_path / "blob.bin"
    blob.write_bytes(b"evidence")
    bundle = tmp_path / "blob.sigstore.json"
    sign(blob, bundle, key=str(key_prefix) + ".key", password=PASSWORD)
    return blob, bundle, str(key_prefix) + ".pub"


def test_sign_emits_only_sigstore_bundle(tmp_path, signed):
    _blob, bundle, _pub = signed
    assert bundle.is_file()
    assert not bundle.with_suffix(".sig").exists()
    assert not Path(str(bundle) + ".crt").exists()


def test_verify_good(signed):
    blob, bundle, pub = signed
    result = verify(blob, bundle, key=pub, password=PASSWORD)
    assert result.verified and result.mode == "key"


def test_verify_tampered_blob_is_evidence_invalid(signed, tmp_path):
    _blob, bundle, pub = signed
    tampered = tmp_path / "tampered.bin"
    tampered.write_bytes(b"evidence+evil")
    with pytest.raises(EvidenceInvalid):
        verify(tampered, bundle, key=pub, password=PASSWORD)


def test_keyless_without_identity_is_rejected_locally(signed, monkeypatch):
    blob, bundle, _pub = signed
    called = []
    real_run = __import__("subprocess").run

    def spy(*args, **kwargs):
        called.append(args)
        return real_run(*args, **kwargs)

    monkeypatch.setattr("subprocess.run", spy)
    with pytest.raises(UsageError, match="keyless"):
        verify(blob, bundle)
    assert called == [], "identity 缺失时不该真的去调 cosign"


def test_key_and_identity_are_mutually_exclusive(signed):
    blob, bundle, pub = signed
    with pytest.raises(UsageError, match="互相排斥"):
        verify(blob, bundle, key=pub, identity="a", issuer="b")


def test_fake_cosign_exit_zero_but_no_output_is_tool_failure(signed, tmp_path, monkeypatch):
    blob, bundle, pub = signed
    fake = tmp_path / "bin"
    fake.mkdir()
    script = fake / "cosign"
    script.write_text("#!/bin/sh\nexit 0\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{fake}:{os.environ['PATH']}")
    with pytest.raises(ToolFailure, match="Verified OK"):
        verify(blob, bundle, key=pub)


def test_fake_cosign_cannot_vouch_for_tampered_blob(signed, tmp_path, monkeypatch):
    _blob, bundle, pub = signed
    tampered = tmp_path / "t.bin"
    tampered.write_bytes(b"nope")
    fake = tmp_path / "bin"
    fake.mkdir()
    script = fake / "cosign"
    script.write_text("#!/bin/sh\necho 'Verified OK'\nexit 0\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{fake}:{os.environ['PATH']}")
    with pytest.raises(EvidenceInvalid, match="摘要"):
        verify(tampered, bundle, key=pub, password=PASSWORD)


def test_bundle_digest_must_bind_the_blob(tmp_path, signed):
    _blob, bundle, pub = signed
    data = json.loads(bundle.read_text())
    data["messageSignature"]["messageDigest"]["digest"] = base64.b64encode(
        hashlib.sha256(b"something else").digest()
    ).decode()
    forged = tmp_path / "forged.sigstore.json"
    forged.write_text(json.dumps(data))
    blob = tmp_path / "blob.bin"
    blob.write_bytes(b"evidence")
    with pytest.raises(EvidenceInvalid):
        verify(blob, forged, key=pub, password=PASSWORD)


def test_garbage_bundle_is_tool_failure(tmp_path, signed):
    blob, _bundle, pub = signed
    junk = tmp_path / "junk.sigstore.json"
    junk.write_text("{not json")
    with pytest.raises(ToolFailure):
        verify(blob, junk, key=pub, password=PASSWORD)
