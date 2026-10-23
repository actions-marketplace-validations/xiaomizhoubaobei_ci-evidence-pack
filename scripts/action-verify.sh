#!/usr/bin/env bash
# GitHub Action 的验包步骤。
#
# 两种用途：
#   1. 本 job 刚打的包 —— 显式 --signature-bundle / --expect-sha256 才可能绿；
#   2. 下游 job 拿到别处来的包 —— 用 expect-sha256 把包外锚点回送。
#
# 判定一律走 `verify --exit-code`：结论在 JSON 里，进程不吃退出码，
# 这样后续的登记錨点、发评论、上传制品不会被 set -e 掐断。
set -euo pipefail

ACTION_PATH="${ACTION_PATH:?缺少 ACTION_PATH}"
BUNDLE="${INPUT_BUNDLE:-}"
if [ -z "$BUNDLE" ]; then
  echo "::error::bundle 输入为空：没有包就没有可校验的对象"
  exit 1
fi

ARGS=(verify "$BUNDLE" --exit-code --json)

if [ -n "${INPUT_SIGNATURE_BUNDLE:-}" ]; then
  ARGS+=(--signature-bundle "$INPUT_SIGNATURE_BUNDLE")
fi
if [ -n "${INPUT_COSIGN_KEY:-}" ]; then
  ARGS+=(--key "$INPUT_COSIGN_KEY")
fi
if [ -n "${INPUT_IDENTITY:-}" ]; then
  ARGS+=(--identity "$INPUT_IDENTITY")
fi
if [ -n "${INPUT_ISSUER:-}" ]; then
  ARGS+=(--issuer "$INPUT_ISSUER")
fi
if [ -n "${INPUT_EXPECT_SHA256:-}" ]; then
  ARGS+=(--expect-sha256 "$INPUT_EXPECT_SHA256")
fi
if [ -n "${INPUT_EXPECT_REPO:-}" ]; then
  ARGS+=(--expect-repo "$INPUT_EXPECT_REPO")
fi
if [ "${INPUT_IGNORE_TLOG:-false}" = "true" ]; then
  ARGS+=(--insecure-ignore-tlog)
fi

export PYTHONPATH="$ACTION_PATH/src${PYTHONPATH:+:$PYTHONPATH}"
python3 -m evidence_pack.cli "${ARGS[@]}" | tee verify-result.json

python3 - <<'PY'
import json
import os
from pathlib import Path

result = json.loads(Path("verify-result.json").read_text(encoding="utf-8"))
code = int(result["exit_code"])
ok = bool(result["ok"])

out = Path(os.environ.get("GITHUB_OUTPUT") or os.devnull)
lines = {
    "ok": str(ok).lower(),
    "exit-code": str(code),
    "bundle-sha256": result.get("bundle_sha256") or "",
    "signature-verified": str(bool(result.get("signature_verified"))).lower(),
    "anchored": str(bool(result.get("anchored"))).lower(),
    "error": (result.get("error") or "").replace("\n", " "),
}
with out.open("a", encoding="utf-8") as fh:
    for key, value in lines.items():
        fh.write(f"{key}={value}\n")

# 徽章式结论：审计者扫一眼就知道这个 job 是「证据无效」还是「工具坏了」。
labels = {0: "证据通过", 1: "用法错误", 2: "证据无效", 3: "工具异常"}
summary = os.environ.get("GITHUB_STEP_SUMMARY")
if summary:
    with open(summary, "a", encoding="utf-8") as fh:
        fh.write("### evidence-pack：校验结论\n\n")
        fh.write(f"| 退出码 | 含义 |\n|---|---|\n| {code} | {labels.get(code, '未知')} |\n\n")
        fh.write(f"- bundle sha256：`{result.get('bundle_sha256') or '-'}`\n")
        fh.write(f"- 签名有效：{result.get('signature_verified')}\n")
        fh.write(f"- 外部锚点：{result.get('anchored')}\n")
        if result.get("error"):
            fh.write(f"- 失败原因：{result['error']}\n")

if not ok:
    # 2 和 3 在这里都以非零退出，但在 summary/输出里分得清清楚楚。
    print(f"::error::evidence-pack 判定失败（退出码 {code}）：{result.get('error')}")
    raise SystemExit(code)
PY
