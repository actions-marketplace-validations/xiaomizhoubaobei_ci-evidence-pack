#!/usr/bin/env bash
# 把 bundle 的 sha256 登记到包外。
#
# 为什么单独一步：bundle 内的 manifest 谁都能重算，真正的信任根在包外。
# 这个脚本只负责「写进哪儿」，不负责「凭什么信它」—— 那份凭证由调用方的
# 制品库 / 审计库 / 评论 / 工单系统承担。
set -euo pipefail

BUNDLE="${INPUT_BUNDLE:-}"
[ -n "$BUNDLE" ] || { echo "::error::bundle 输入为空"; exit 1; }
[ -f "$BUNDLE" ] || { echo "::error::bundle 不存在：$BUNDLE"; exit 1; }
[ -n "${INPUT_ANCHOR_FILE:-}" ] || { echo "::error::anchor-file 输入为空"; exit 1; }

if command -v sha256sum >/dev/null 2>&1; then
  DIGEST=$(sha256sum "$BUNDLE" | awk '{print $1}')
else
  DIGEST=$(shasum -a 256 "$BUNDLE" | awk '{print $1}')
fi

# 相对路径按调用方 cwd 解析并落成绝对路径：下游 job / 手工调用常常只给相对路径，
# 而 action.yml 的 outputs 要求路径能跨步骤直接用。
ANCHOR_DIR="$(dirname "${INPUT_ANCHOR_FILE}")"
ANCHOR_NAME="$(basename "${INPUT_ANCHOR_FILE}")"
mkdir -p "$ANCHOR_DIR"
ANCHOR_FILE="$(cd "$ANCHOR_DIR" && pwd)/$ANCHOR_NAME"

# 追加写：同一份 anchor 文件可以跨 step / 跨 job 累积成一册台账。
printf '%s  %s\n' "$DIGEST" "$(basename "$BUNDLE")" >> "$ANCHOR_FILE"

# 供 action.yml 的 outputs 用：anchor-file 在 action.yml 里被映射成
# `steps.pack.outputs.anchor-file`，所以这里也往 GITHUB_OUTPUT 末尾补一条。
{
  echo "sha256=$DIGEST"
  echo "anchor-file=$ANCHOR_FILE"
} >> "${GITHUB_OUTPUT:-/dev/null}"

echo "::notice::锚点已登记：$DIGEST -> $ANCHOR_FILE（包外，别只信包里的 manifest）"
