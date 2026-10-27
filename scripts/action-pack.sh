#!/usr/bin/env bash
# GitHub Action 的打包步骤。
#
# 刻意不用 `pip install <action_path>`：Action 在调用方仓库里运行时，
# 往调用方的解释器环境里装东西是有代价的（版本冲突、污染缓存、拉长时长）。
# 这里只做一件事——把本 action 的 src 目录塞进 PYTHONPATH。
set -euo pipefail

ACTION_PATH="${ACTION_PATH:?缺少 ACTION_PATH}"
REPO="${REPO_ROOT:-.}"

# include 是必填输入：漏写时 inputs.include 渲染成空串，Action 不会替调用方
# 兜底选目录。所以先在这里点名「必填输入」和该填什么 —— 否则现场只会看到
# 内核那句「include 为空」，看不出是自己少写了一行。多行输入的归一化
# （裁空白、忽略空行与 # 注释）在内核里做，shell 只管把原文传下去。
if [ -z "$(printf '%s' "${INPUT_INCLUDE:-}" | tr -d '[:space:]#')" ]; then
  echo "::error::include 为空：它是必填输入，请在 uses: 的 with: 下显式列出要收进证据包的文件或目录（例如 include: | 换行 dist/ 换行 pyproject.toml）。漏写 include 已如实判为用法错误（退出码 1），证据未生成"
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

# 参数怎么来的：全部经 INPUT_* 环境变量进内核（python3 -m evidence_pack.action pack）。
# 这里只落一个必填的 bundle 名 —— 它是 shell 侧才知道的信息（短 sha），
# 其余默认值（sbom / out-dir）由内核自己兜。
export INPUT_BUNDLE_NAME="${INPUT_BUNDLE_NAME:-evidence-${SHORT_SHA}.tar.gz}"
export INPUT_OUT_DIR="$OUT_DIR"

# 签名是默认动作，只有小写 'false' 才是关 —— 判据与内核的 is_sign_off 一致，
# action.yml 里装 cosign 的 `if:` 也用同一个字面量。关掉时信任根交给包外锚点，
# 下游 verify 会按同一判断处理（包内自洽不算证据，该判 2 就判 2）。
#
# 要签就得先有签发方：靠 runner 派发的 OIDC token，命令行给不了也没法伪造。
# 判据是「有没有签发方」而不是「token 字面量在不在」—— GitHub 托管 runner 上
# 就绪的是 ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN 这对凭据，token 要拿它去换。
if [ "${INPUT_SIGN:-true}" != "false" ] \
   && [ -z "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ] \
   && [ -z "${SIGSTORE_ID_TOKEN:-}" ]; then
  echo "::error::签名的信任根只有 OIDC：job 需要 id-token: write，且只在 GitHub 托管 runner 上有 OIDC 签发方。自托管 / 本地没有签发方，请显式 sign: 'false'（此时必须有包外锚点）"
  exit 3
fi

# 期望身份（INPUT_IDENTITY / INPUT_ISSUER）由 action.yml 直接注入环境，
# 内核把它写进包内 metadata/binding.json：验签方据此核对，别处没有第二处记录。

export PYTHONPATH="$ACTION_PATH/src${PYTHONPATH:+:$PYTHONPATH}"
# 证据包必须说得出「何时产生」，且同一个 commit 两次跑出来要一样。
# 所以顺序是：调用方显式给的 > 这个 commit 的时间 > 当前时间（无 git 时才轮到它）。
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
  SOURCE_DATE_EPOCH=$(git -C "$REPO" log -1 --format=%ct 2>/dev/null || true)
fi
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(date +%s)}"

# 签名要的是 token 本体，而 GitHub 托管 runner 上就绪的
# ACTIONS_ID_TOKEN_REQUEST_TOKEN 只是**换 token 的凭据**，不是 token。
# 少了这一步，job 明明开了 id-token: write，签名仍会在 Fulcio 那里 401 ——
# 现场看起来就跟「权限没开」一模一样。所以在这里换出来，交给内核。
#
# 调用方若已显式给了 SIGSTORE_ID_TOKEN（别的平台 / cosign 自取），就原样尊重，
# 不去覆盖。token 只经环境变量传递，绝不进 argv（argv 会进作业日志）。
if [ -z "${SIGSTORE_ID_TOKEN:-}" ] \
   && [ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] \
   && [ -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]; then
  # 请求的 audience 必须与验签时的 --identity 对得上；GitHub 用 sigstore 这个值。
  # URL 可能已带 query，也可能不带 —— 无脑拼 & 会得到非法的 URL（curl: bad format）。
  req_url="${ACTIONS_ID_TOKEN_REQUEST_URL}"
  case "$req_url" in
    *\?*) req_url="${req_url}&audience=sigstore" ;;
    *)    req_url="${req_url}?audience=sigstore" ;;
  esac
  if oidc_json="$(curl -fsSL -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
        --retry 2 --max-time 30 "$req_url")"; then
    SIGSTORE_ID_TOKEN="$(printf '%s' "$oidc_json" \
      | python3 -c 'import json,sys; print(json.load(sys.stdin).get("value",""))')"
    if [ -z "$SIGSTORE_ID_TOKEN" ]; then
      echo "::error::OIDC 端点没有返回 value，拿不到 token（权限或 audience 不对）"
      exit 3
    fi
    export SIGSTORE_ID_TOKEN
  else
    # 拿不到 token 是凭据/权限问题，属于「流水线坏了」：3，不是 2。
    echo "::error::向 ACTIONS_ID_TOKEN_REQUEST_URL 换 OIDC token 失败，请确认 job 上有 id-token: write"
    exit 3
  fi
fi
# token 就在这个环境变量里，内核只从它读（不像 argv 那样会进作业日志）。

# set -o pipefail 让 tee 不会把 python 的退出码吃掉，这里原样交还 0/1/2/3：
# 「证据无效」和「工具坏了」在 Action 里也得是两个不同的结论。
python3 -m evidence_pack.action pack | tee pack-result.json
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
> （制品库 / 审计库 / 工单），验的时候再从那里取出来回送 expect-sha256。
> 包里的 manifest 只能证明包内自洽，不能证明这份包来自你以为的那个人。

> 自检（verify）默认回送的摘要就是**上一步刚算出来的**那个。签名一默认开，
> 它必然通过 —— 那条结论验的是「刚打出来的东西」，不是「包外那份账」。
> 要信任根，请指向签名身份（identity）或包外登记的 sha256。
MD
