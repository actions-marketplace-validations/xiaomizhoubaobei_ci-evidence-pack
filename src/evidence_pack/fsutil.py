"""把不确定的东西变成确定的东西。

确定性打包的全部秘密都在这个文件里：同样的输入字节 + 同样的
SOURCE_DATE_EPOCH，产出必须逐字节相同。任何绕过的分支都会让
「可复现」这句话作废，所以这里所有函数都不接受"差不多"。
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import subprocess
import tarfile
import time
from pathlib import Path
from typing import Any

from .errors import UsageError

CHUNK = 1 << 20


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def stable_json_bytes(data: Any) -> bytes:
    """JSON 的唯一正确写法：键排序、缩进 2、UTF-8 不转义、结尾换行。"""
    return (
        json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def write_stable_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(stable_json_bytes(data))


def resolve_source_date_epoch(repo_root: Path) -> int:
    """证据包必须说得出「何时产生」。

    优先取环境变量（CI 里由构建系统给定，可复现）；
    没有就退回最后一次提交时间；再没有才用当前时间。
    永不落 0 —— 1970-01-01 不是时间戳，是心虚。
    """
    raw = os.environ.get("SOURCE_DATE_EPOCH", "").strip()
    if raw:
        try:
            value = int(raw)
            if value > 0:
                return value
        except ValueError:
            raise UsageError(f"SOURCE_DATE_EPOCH 不是整数：{raw!r}")
        raise UsageError(f"SOURCE_DATE_EPOCH 必须是正整数：{raw!r}")

    from_git = _git_commit_epoch(repo_root)
    if from_git:
        return from_git
    return int(time.time())


def _git_commit_epoch(repo_root: Path) -> int | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo_root), "log", "-1", "--format=%ct"],
            capture_output=True,
            text=True,
            check=False,
        )
    except (OSError, ValueError):
        return None
    if out.returncode != 0:
        return None
    try:
        value = int(out.stdout.strip())
    except ValueError:
        return None
    return value or None


def normalize_tarinfo(tarinfo: tarfile.TarInfo, mtime: int) -> tarfile.TarInfo:
    """抹掉一切与"谁在哪台机器上打的包"相关的位。

    只保留 POSIX 权限的可执行位：可执行与否是内容属性，
    而 uid/gid/uname/gname/mtime 是环境属性，全部归零。
    """
    tarinfo.uid = 0
    tarinfo.gid = 0
    tarinfo.uname = ""
    tarinfo.gname = ""
    tarinfo.mtime = mtime
    tarinfo.mode = 0o755 if tarinfo.mode & 0o100 else 0o644
    return tarinfo


def build_tar_gz(stage_dir: Path, mtime: int) -> bytes:
    """把 staging 目录打成确定性 tar.gz。

    三个必要条件，缺一不可：
      - 文件按路径字典序进入
      - gzip 头的 mtime 固定为 0，且不写原始文件名
      - tar 条目属性归一（见 normalize_tarinfo）
    额外可选项（数据流不压缩）是为了让 gzip 自身不参与熵。
    """
    entries: list[Path] = sorted(
        (p for p in stage_dir.rglob("*") if p.is_file()),
        key=lambda p: p.relative_to(stage_dir).as_posix(),
    )

    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for path in entries:
            arcname = path.relative_to(stage_dir).as_posix()
            tar.add(
                path,
                arcname=arcname,
                recursive=False,
                filter=lambda ti: normalize_tarinfo(ti, mtime),
            )

    packed = io.BytesIO()
    with gzip.GzipFile(
        filename="", mode="wb", fileobj=packed, mtime=0, compresslevel=6
    ) as gz:
        gz.write(raw.getvalue())
    return packed.getvalue()
