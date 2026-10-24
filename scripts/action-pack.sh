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
    | tr -d '\r' \
    | sed -e 's/[[:space:]]*$//' \
    | grep -v -e '^$' -e '^#' || true
)
if [ "${#INCLUDES[@]}" -eq 0 ]; then
  echo "::error::include 为空：证据包里没有内容就没有意义，请显式列出要收的路径"
  exit 1
fi

SHORT_SHA="$(git -C "$REPO" rev-parse --short=7 HEAD 2>/dev/null || echo nosha)"

# 相对输出目录按仓库根解析，不按 cwd：ledger、artifact、下游 verify 都靠这个
# 绝对路径找文件，cwd 一变（子目录里跑、手工调用）就会各说各话。
OUT_DIR="${INPUT_OUT_DIR:-_evidence}"
case "$OUT_DIR" in
  /*) ;;
  *) OUT_DIR="$(cd "$REPO" && pwd)/$OUT_DIR" ;;
esac

ARGS=(
  pack
  --repo "$REPO"
  --out "$OUT_DIR"
  --sbom "${INPUT_SBOM:-auto}"
  --bundle-name "${INPUT_BUNDLE_NAME:-evidence-${SHORT_SHA}.tar.gz}"
)

for inc in "${INCLUDES[@]}"; do
  ARGS+=(--include "$inc")
done

mapfile -t EXCLUDES < <(
  printf '%s\n' "${INPUT_EXCLUDE:-}" \
    | tr -d '\r' \
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
    # keyless 的身份来自 OIDC，命令行伪造不了，所以判据不是「有没有某个变量」，
    # 而是「有没有签发方」：调用方已经给好 SIGSTORE_ID_TOKEN 就原样尊重，
    # 否则现去端点换一枚。
    #
    # 换不到一律判 3 —— 凭据没到位是「流水线坏了」，不是「证据无效」，
    # 这两件事的人工处置完全不同，不能混成一个红叉。
    if ! OIDC_TOKEN="$(bash "$(dirname "${BASH_SOURCE[0]}")/action-oidc.sh")"; then
      echo "::error::sign=true 且未提供 cosign-key：keyless 需要 id-token: write（GitHub 托管 runner）。自托管 / 本地请改用 key 模式"
      exit 3
    fi
    # token 只走环境变量交给内核，绝不进 argv：argv 会被 ps、日志和调试输出记住。
    if [ -z "${SIGSTORE_ID_TOKEN:-}" ]; then
      export SIGSTORE_ID_TOKEN="$OIDC_TOKEN"
      unset OIDC_TOKEN
    fi
    ARGS+=(--sign --oidc-token-env SIGSTORE_ID_TOKEN)
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

# set -o pipefail 让 tee 不会把 python 的退出码吃掉，这里原样交还 0/1/2/3：
# 「证据无效」和「工具坏了」在 Action 里也得是两个不同的结论。
python3 -m evidence_pack.cli "${ARGS[@]}" --json | tee pack-result.json
CODE="${PIPESTATUS[0]}"
if [ "$CODE" -ne 0 ]; then
  echo "::error::证据包打包失败（退出码 ${CODE}），结论见上面的 JSON"
  exit "$CODE"
fi

# artifact 名默认取 sha256 前 16 位：跨 job 唯一，且天然不含 / : 等非法字符。
INPUT_ARTIFACT_NAME="${INPUT_ARTIFACT_NAME:-}"
export INPUT_ARTIFACT_NAME

python3 - <<'PY'
import json
import os
from pathlib import Path

result = json.loads(Path("pack-result.json").read_text(encoding="utf-8"))
out = Path(os.environ.get("GITHUB_OUTPUT") or os.devnull)
sha = result["bundle_sha256"]
lines = {
    "bundle-path": result["bundle_path"],
    "bundle-name": result["bundle_name"],
    "bundle-sha256": sha,
    "signature-bundle": result.get("signature_bundle") or "",
    "signature-mode": result.get("signature_mode") or "",
    "signed": str(bool(result.get("signed"))).lower(),
    "file-count": str(result.get("file_count", 0)),
    "source-date-epoch": str(result.get("source_date_epoch", "")),
    "artifact-name": os.environ.get("INPUT_ARTIFACT_NAME") or f"evidence-{sha[:16]}",
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
        fh.write(f"- sha256：`{sha}`\n")
        fh.write(f"- 签名：{result.get('signature_mode') or '无（需外部锚点才能构成证据）'}\n")
PY

# 调用方在 summary 里顺手就能看到结论，不必再回去翻日志。
cat >> "${GITHUB_STEP_SUMMARY:-/dev/null}" <<'MD'

> 想让它成为**证据**而不只是一份产物：把上面的 sha256 登记到包外的位置
> （制品库 / 审计库 / 工单），验的时候再回送 `--expect-sha256`。
> 包里的 manifest 只能证明包内自洽，不能证明这份包来自你以为的那个人。
MD
