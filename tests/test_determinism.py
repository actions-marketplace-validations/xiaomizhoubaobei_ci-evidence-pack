import tarfile
from pathlib import Path

from evidence_pack.fsutil import build_tar_gz, stable_json_bytes
from evidence_pack.packer import PackOptions, pack


def _repo(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("print(1)\n")
    (tmp_path / "src" / "b.py").write_text("print(2)\n")
    return tmp_path


def test_pack_is_byte_identical_across_runs(tmp_path, monkeypatch):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
    repo = _repo(tmp_path)
    # 确定性只跟「输入 + SOURCE_DATE_EPOCH」有关；签名要连外部服务，这里显式关掉。
    opts = lambda out: PackOptions(  # noqa: E731
        repo_root=repo,
        out_dir=tmp_path / out,
        includes=["src"],
        sbom="none",
        collect_git=False,
        sign=False,
    )
    first = pack(opts("out1"))
    second = pack(opts("out2"))
    a = Path(first.bundle_path).read_bytes()
    b = Path(second.bundle_path).read_bytes()
    assert a == b, "相同输入、相同 SOURCE_DATE_EPOCH 必须产出逐字节相同的结果"


def test_tar_mtime_and_ownership_normalized(tmp_path):
    stage = tmp_path / "stage"
    stage.mkdir()
    (stage / "f.txt").write_text("x")
    data = build_tar_gz(stage, mtime=12345)
    (tmp_path / "o.tar.gz").write_bytes(data)
    with tarfile.open(tmp_path / "o.tar.gz") as tar:
        info = tar.getmembers()[0]
    assert info.uid == 0 and info.gid == 0
    assert info.uname == "" and info.gname == ""
    assert info.mtime == 12345


def test_gzip_header_mtime_is_zero(tmp_path):
    stage = tmp_path / "stage"
    stage.mkdir()
    (stage / "f.txt").write_text("x")
    data = build_tar_gz(stage, mtime=999)
    # gzip MTV field: bytes 4..8, little endian
    assert data[4:8] == b"\x00\x00\x00\x00"


def test_stable_json_sorted_and_newline():
    a = stable_json_bytes({"b": 1, "a": 2})
    assert a.endswith(b"\n")
    assert a.index(b'"a"') < a.index(b'"b"')


def test_tar_entries_sorted(tmp_path):
    stage = tmp_path / "stage"
    stage.mkdir()
    for name in ("z.txt", "a.txt", "m/inner.txt"):
        p = stage / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x")
    (tmp_path / "o.tar.gz").write_bytes(build_tar_gz(stage, mtime=1))
    with tarfile.open(tmp_path / "o.tar.gz") as tar:
        names = [m.name for m in tar.getmembers()]
    assert names == sorted(names)
