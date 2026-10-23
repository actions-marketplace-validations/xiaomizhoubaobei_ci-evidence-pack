"""把用户说的 `--include` 变成真正落进包里的文件。

原实现最阴的一个 bug 就在这里：`src_path` 用 resolve 后的路径，
落盘用的却是用户原样字符串。于是 `--include ../outside` 会写到
`artifacts/../outside/x`，逃出 staging 根，既不在 tar 里也不在
manifest 里，退出码还是 0 —— 用户给的输入被静默吞掉。

这里的规则只有一条：越界即报错，绝不静默跳过。
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from .errors import UsageError

DEFAULT_EXCLUDES: tuple[str, ...] = (".git", "node_modules", "dist", "__pycache__", ".venv", "venv")


@dataclass(frozen=True)
class CollectResult:
    rel_paths: list[str]
    skipped: list[str]


class Collector:
    def __init__(self, repo_root: Path, out_dir: Path, excludes: list[str] | None = None) -> None:
        self.repo_root = repo_root.resolve()
        self.out_dir = out_dir.resolve()
        names = list(DEFAULT_EXCLUDES) + list(excludes or [])
        # 输出目录自身必须排除，否则上一版 bundle 会滚进这一版（雪球效应）。
        self.exclude_roots: list[Path] = []
        for inc in [self.out_dir, *(self.repo_root / n for n in names)]:
            try:
                self.exclude_roots.append(inc.resolve())
            except OSError:
                continue

    def _is_excluded(self, path: Path) -> bool:
        resolved = path.resolve()
        return any(resolved == r or r in resolved.parents for r in self.exclude_roots)

    def resolve_include(self, raw: str) -> Path:
        target = (self.repo_root / raw).resolve()
        if not target.is_relative_to(self.repo_root):
            raise UsageError(
                f"--include 越界：{raw!r} 解析到 {target}，不在 {self.repo_root} 内。"
                f" 证据包只收仓库内的路径，越界一律报错而非静默跳过。"
            )
        if not target.exists():
            raise UsageError(f"--include 指向的路径不存在：{raw!r}")
        return target

    def collect(self, includes: list[str], stage_artifacts: Path) -> CollectResult:
        if not includes:
            raise UsageError("至少要给一个 --include；空证据包没有意义。")

        collected: list[str] = []
        skipped: list[str] = []
        seen: set[str] = set()

        for raw in includes:
            target = self.resolve_include(raw)
            if target == self.repo_root:
                raise UsageError("--include . 会把整个仓库（含输出目录）装进去；请显式列出要收的路径。")
            if self._is_excluded(target):
                raise UsageError(
                    f"--include {raw!r} 被排除规则命中（默认排除 .git/node_modules/dist 等，以及输出目录自身）。"
                    f" 如果你确实想收它，换一个 --out 目录。"
                )
            rel = target.relative_to(self.repo_root)
            files = [target] if target.is_file() else sorted(self._walk(target))
            if not files:
                raise UsageError(f"--include {raw!r} 匹配不到任何文件。")
            for src in files:
                rel_path = rel if target.is_file() else src.relative_to(self.repo_root)
                if self._is_excluded(src):
                    continue
                posix = rel_path.as_posix()
                if posix in seen:
                    continue
                seen.add(posix)
                dest = stage_artifacts / rel_path
                dest.parent.mkdir(parents=True, exist_ok=True)
                # copy2 保留 mode；时间戳随后由 tar 归一，无需在此处理。
                shutil.copy2(src, dest)
                collected.append(posix)

        if not collected:
            raise UsageError("所有 --include 都被排除规则过滤掉了，证据包会为空。")
        return CollectResult(rel_paths=sorted(collected), skipped=skipped)

    def _walk(self, root: Path):
        for path in sorted(root.rglob("*")):
            if path.is_file():
                yield path
