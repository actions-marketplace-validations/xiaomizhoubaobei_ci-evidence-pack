"""把用户说的 `--include` 变成真正落进包里的文件。

原实现最阴的一个 bug 就在这里：`src_path` 用 resolve 后的路径，
落盘用的却是用户原样字符串。于是 `--include ../outside` 会写到
`artifacts/../outside/x`，逃出 staging 根，既不在 tar 里也不在
manifest 里，退出码还是 0 —— 用户给的输入被静默吞掉。

这里的规则只有一条：越界即报错，绝不静默跳过。
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from .errors import UsageError

# 默认排除只用于「遍历时顺手跳过」；用户显式 --include 的路径不受其约束，
# 否则 `--include dist` 这种最常见的用法会被自己的默认值挡死。
DEFAULT_EXCLUDES: tuple[str, ...] = (
    ".git",
    "node_modules",
    "dist",
    "__pycache__",
    ".venv",
    "venv",
)
# 无论是否显式指定，都不收：收 .git 既毁确定性，也把密钥扫进包里。
HARD_EXCLUDES: tuple[str, ...] = (".git",)


@dataclass(frozen=True)
class CollectResult:
    """一次收集的结果：收进来的相对路径，以及被跳过的路径。"""

    rel_paths: list[str]
    skipped: list[str]


class Collector:
    """按 --include/--exclude 在仓库内挑文件，保留仓库相对路径。"""

    def __init__(
        self, repo_root: Path, out_dir: Path, excludes: list[str] | None = None
    ) -> None:
        """确定根目录与排除规则。

        排除项来自三处，顺序固定：内置默认、调用方 --exclude、.gitignore。
        输出目录自身无条件排除 —— 否则上一版 bundle 会滚进这一版，越打越大。
        """
        self.repo_root = repo_root.resolve()
        self.out_dir = out_dir.resolve()
        names = [*DEFAULT_EXCLUDES, *(excludes or []), *self._from_gitignore()]
        # 输出目录自身必须排除，否则上一版 bundle 会滚进这一版（雪球效应）。
        self.exclude_roots: list[Path] = []
        hard_roots: list[Path] = []
        for pattern in names:
            self.exclude_roots.extend(self._walk_matches(pattern))
        hard_roots.append(self.out_dir)
        for name in HARD_EXCLUDES:
            hard_roots.extend(self._walk_matches(name))
        self.hard_excludes = hard_roots

    def _walk_matches(self, name: str) -> list[Path]:
        """把排除名解析成仓库里的真实路径：根目录的，以及任意深度的同名目录。

        只解析根目录那一层是不够的 —— `src/node_modules` 同样不该进包；
        反过来只按名字比后缀又会把 `src/mynode_modules/x` 误杀。
        所以这里显式走一遍目录树，拿到确定的路径。
        """
        found: list[Path] = []
        top = self.repo_root / name
        try:
            if top.exists() or top.is_symlink():
                found.append(top.resolve())
        except OSError:
            pass
        for dirpath, dirnames, _files in os.walk(self.repo_root):
            if name not in dirnames:
                continue
            candidate = Path(dirpath) / name
            try:
                resolved = candidate.resolve()
            except OSError:
                continue
            if resolved not in found:
                found.append(resolved)
        return found

    def _from_gitignore(self) -> list[str]:
        """`.gitignore` 里只有「裸名字」（.env、*.pem）才当排除项用。

        带斜杠的路径规则依赖 git 的匹配语义，自己实现一套只会做出一个错的 git，
        所以宁可只认最保守的那一类。
        """
        gitignore = self.repo_root / ".gitignore"
        if not gitignore.is_file():
            return []
        try:
            text = gitignore.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        names: list[str] = []
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith(("#", "!")) or "/" in line or "\\" in line:
                continue
            if any(ch in line for ch in "*?["):
                continue
            names.append(line)
        return names

    def _is_excluded(self, path: Path) -> bool:
        resolved = path.resolve()
        return any(resolved == r or r in resolved.parents for r in self.exclude_roots)

    def _is_hard_excluded(self, path: Path) -> bool:
        resolved = path.resolve()
        return any(resolved == r or r in resolved.parents for r in self.hard_excludes)

    def resolve_include(self, raw: str) -> Path:
        """把 --include 解析成仓库内的真实路径，越界或不存在都判用法错。"""
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
        """把 includes 指向的内容拷进 stage_artifacts，返回相对路径清单。

        路径按字典序去重后写入，绝不依赖文件系统遍历顺序 —— 这是可复现的前提。
        """
        if not includes:
            raise UsageError("至少要给一个 --include；空证据包没有意义。")

        collected: list[str] = []
        skipped: list[str] = []
        seen: set[str] = set()

        for raw in includes:
            target = self.resolve_include(raw)
            if target == self.repo_root:
                raise UsageError(
                    "--include . 会把整个仓库（含输出目录）装进去；请显式列出要收的路径。"
                )
            if self._is_hard_excluded(target):
                raise UsageError(
                    f"--include {raw!r} 落在不可收范围内（.git 或输出目录自身）。"
                    f" .git 里没有可复现的东西；输出目录收进来会让包随版本雪球。"
                )
            rel = target.relative_to(self.repo_root)
            files = [target] if target.is_file() else sorted(self._walk(target))
            if not files:
                raise UsageError(f"--include {raw!r} 匹配不到任何文件。")
            for src in files:
                rel_path = rel if target.is_file() else src.relative_to(self.repo_root)
                # 显式 include 的祖先链上的名字（如 `--include dist`）不算排除命中；
                # 但硬排除（.git / 输出目录）与更深层的匹配目录照样要挡。
                if self._matches_at_or_below(src, target):
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
            raise UsageError(
                "所有 --include 都被排除规则过滤掉了（只剩 .git / 输出目录），证据包会为空。"
            )
        return CollectResult(rel_paths=sorted(collected), skipped=skipped)

    def _matches_at_or_below(self, path: Path, include_root: Path) -> bool:
        resolved = path.resolve()
        for root in self.exclude_roots:
            if not (resolved == root or root in resolved.parents):
                continue
            # 排除项恰好就是 include 的根（或它的祖先）→ 是用户显式点名的，放行；
            # 但它内部更深层的匹配目录（src/node_modules）照旧要被挡下。
            if root == include_root.resolve() or root in include_root.resolve().parents:
                continue
            return True
        return False

    def _walk(self, root: Path):
        for path in sorted(root.rglob("*")):
            if path.is_file():
                yield path
