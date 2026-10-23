#!/usr/bin/env bash
# GitHub Action 的打包步骤。
#
# 刻意不用 `pip install <action_path>`：Action 在调用方仓库里运行时，
# 往调用方的解释器环境里装东西是有代价的（版本冲突、污染缓存、拉长时长）。
# 这里只做一件事——把本 action 的 src 目录塞进 PYTHONPATH。
set -euo pipefail

ACTION_PATH="${ACTION_PATH:?缺少 ACTION_PATH}"
REPO="${REPO_ROOT:-.}"

# ---------------------------------------------------------------------------
# 输入归一化：multiline 输入 → 参数数组。
# 空行与纯注释行忽略，行尾空白裁掉（从 YAML 复制粘贴时最常见的那种脏）。
# ---------------------------------------------------------------------------
mapfile -t INCLUDES < <(
  printf '%s\n' "${INPUT_INCLUDE:-}" \
    | sed -e 's/[[:space:]]*$//' \
    | grep -v -e '^$' -e '^#' || true
)
if [ "${#INCLUDES[@]}" -eq 0 ]; then
  echo "::error::include 为空：证据包里没有内容就没有意义，请显式列出要收的路径"
  exit 1
fi

ARGS=(
  pack
  --repo "$REPO"
  --out "${INPUT_OUT_DIR:-_evidence}"
  --sbom "${INPUT_SBOM:-auto}"
  --bundle-name "${INPUT_BUNDLE_NAME:-evidence-$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo nosha).tar.gz}"
)

for inc in "${INCLUDES[@]}"; do
  ARGS+=(--include "$inc")
done

mapfile -t EXCLUDES < <(
  printf '%s\n' "${INPUT_EXCLUDE:-}" \
    | sed -e 's/[[:space:]]*$//' \
    | grep -v -e '^$' -e '^#' || true
)
for exc in "${EXCLUDES[@]}"; do
  ARGS+=(--exclude "$exc")
done

if [ "${INPUT_SIGN:-false}" = "true" ]; then
  if [ -n "${INPUT_COSIGN_KEY:-}" ]; then
    ARGS+=(--key "$INPUT_COSIGN_KEY")
  else
    ARGS+=(--sign)
  fi
fi

# 期望身份写进包内 metadata/binding.json：验签方据此核对，别处没有第二处记录。
[ -n "${INPUT_IDENTITY:-}" ] && ARGS+=(--identity "$INPUT_IDENTITY")
[ -n "${INPUT_ISSUER:-}" ]   && ARGS+=(--issuer "$INPUT_ISSUER")

export PYTHONPATH="$ACTION_PATH/src${PYTHONPATH:+:$PYTHONPATH}"
# 证据包必须说得出「何时产生」，且同一个 commit 两次跑出来要一样。
# 所以顺序是：调用方显式给的 > 这个 commit 的时间 > 当前时间（无 git 时才轮到它）。
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
  SOURCE_DATE_EPOCH=$(git -C "$REPO" log -1 --format=%ct 2>/dev/null || true)
fi
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(date +%s)}"

python3 -m evidence_pack.cli "${ARGS[@]}" --json | tee pack-result.json

python3 - <<'PY'
import json
import os
from pathlib import Path

result = json.loads(Path("pack-result.json").read_text(encoding="utf-8"))
out = Path(os.environ.get("GITHUB_OUTPUT") or os.devnull)
lines = {
    "bundle-path": result["bundle_path"],
    "bundle-name": result["bundle_name"],
    "bundle-sha256": result["bundle_sha256"],
    "signature-bundle": result.get("signature_bundle") or "",
    "signed": str(bool(result.get("signed"))).lower(),
    "file-count": str(result.get("file_count", 0)),
    "source-date-epoch": str(result.get("source_date_epoch", "")),
}
with out.open("a", encoding="utf-8") as fh:
    for key, value in lines.items():
        fh.write(f"{key}={value}\n")

step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
if step_summary:
    with open(step_summary, "a", encoding="utf-8") as fh:
        fh.write("### evidence-pack：证据包已生成\n\n")
        fh.write(f"- 文件：`{result['bundle_path']}`\n")
        fh.write(f"- 文件数：{result['file_count']}\n")
        fh.write(f"- sha256：`{result['bundle_sha256']}`\n")
        fh.write(f"- 签名：{result.get('signature_mode') or '无（需外部锚点才能构成证据）'}\n")
PY
