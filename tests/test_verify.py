import gzip
import io
import tarfile
from pathlib import Path

import pytest

from evidence_pack.errors import EvidenceInvalid, UsageError
from evidence_pack.packer import PackOptions, pack
from evidence_pack.verifier import VerifyOptions, verify


def _packed(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "a.txt").write_text("original")
    result = pack(PackOptions(
        repo_root=repo, out_dir=tmp_path / "out", includes=["src"], sbom="none", collect_git=False
    ))
    return Path(result.bundle_path)


def _evil(tmp_path: Path, members) -> Path:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for m in members:
            tar.addfile(m, io.BytesIO(b"x") if m.isfile() else None)
    out = tmp_path / "evil.tar.gz"
    with gzip.GzipFile(filename="", mode="wb", fileobj=open(out, "wb"), mtime=0) as gz:
        gz.write(buf.getvalue())
    return out


def test_manifest_only_bundle_is_not_accepted_as_evidence(tmp_path, monkeypatch):
    bundle = _packed(tmp_path, monkeypatch)
    with pytest.raises(EvidenceInvalid, match="不构成证据"):
        verify(VerifyOptions(bundle_path=bundle))


def test_anchor_makes_bundle_meaningful(tmp_path, monkeypatch):
    bundle = _packed(tmp_path, monkeypatch)
    sha = __import__("hashlib").sha256(bundle.read_bytes()).hexdigest()
    result = verify(VerifyOptions(bundle_path=bundle, expect_sha256=sha))
    assert result.anchored and result.manifest_verified


def test_wrong_anchor_fails(tmp_path, monkeypatch):
    bundle = _packed(tmp_path, monkeypatch)
    with pytest.raises(EvidenceInvalid, match="锚点不符"):
        verify(VerifyOptions(bundle_path=bundle, expect_sha256="a" * 64))


def test_bad_anchor_format_is_usage_error(tmp_path, monkeypatch):
    bundle = _packed(tmp_path, monkeypatch)
    with pytest.raises(UsageError):
        verify(VerifyOptions(bundle_path=bundle, expect_sha256="not-a-hash"))


def test_forged_bundle_with_recomputed_manifest_is_caught_by_anchor(tmp_path, monkeypatch):
    bundle = _packed(tmp_path, monkeypatch)
    real_sha = __import__("hashlib").sha256(bundle.read_bytes()).hexdigest()

    work = tmp_path / "forge"
    work.mkdir()
    with tarfile.open(bundle, "r:gz") as tar:
        tar.extractall(work)
    (work / "artifacts" / "src" / "a.txt").write_text("FORGED")
    lines = []
    for p in sorted(work.rglob("*")):
        if p.is_file() and p.name != "sha256sum.txt":
            import hashlib
            rel = p.relative_to(work).as_posix()
            lines.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {rel}")
    (work / "manifest" / "sha256sum.txt").write_text("\n".join(lines) + "\n")

    forged = tmp_path / "forged.tar.gz"
    with tarfile.open(forged, "w:gz") as tar:
        for p in sorted(work.iterdir()):
            tar.add(p, arcname=p.name)

    # manifest 自洽，但没有外部锚点时必须是"无效"
    with pytest.raises(EvidenceInvalid):
        verify(VerifyOptions(bundle_path=forged))
    # 拿真实原始锚点核对，必须被抓
    with pytest.raises(EvidenceInvalid, match="锚点不符"):
        verify(VerifyOptions(bundle_path=forged, expect_sha256=real_sha))


@pytest.mark.parametrize("kind", ["absolute", "traversal", "symlink", "hardlink"])
def test_malicious_tar_is_rejected(tmp_path, kind):
    m = tarfile.TarInfo({"absolute": "/etc/passwd", "traversal": "../x",
                         "symlink": "link", "hardlink": "hlink"}[kind])
    if kind in ("symlink", "hardlink"):
        m.type = tarfile.SYMTYPE if kind == "symlink" else tarfile.LNKTYPE
        m.linkname = "/etc/passwd"
        m.size = 0
    else:
        m.size = 1
    evil = _evil(tmp_path, [m])
    import hashlib
    sha = hashlib.sha256(evil.read_bytes()).hexdigest()
    with pytest.raises(EvidenceInvalid):
        verify(VerifyOptions(bundle_path=evil, expect_sha256=sha))


def test_missing_bundle_is_usage_error(tmp_path):
    with pytest.raises(UsageError, match="不存在"):
        verify(VerifyOptions(bundle_path=tmp_path / "nope.tar.gz"))
