#!/usr/bin/env bash
# 用 GitHub 托管的 OIDC 端点换一枚 sigstore 身份的 token，打到 stdout。
#
# 为什么要有这一步：`ACTIONS_ID_TOKEN_REQUEST_TOKEN` 是**换 token 的凭据**，
# 不是 token 本体。它的名字里带 TOKEN，很容易被当成 token 直接用，
# 于是拿到 Fulcio 那里就是 401 —— 现场看起来跟「权限没开」一模一样，
# 是最难查的那类故障。真正能用的是拿 URL + 凭据换回来的那个 JWT。
#
# 约定：
#   - 已经给了 SIGSTORE_ID_TOKEN（调用方自己换好 / 本地调试）就原样尊重，不动它；
#   - 缺 URL 或缺凭据 = 没有签发方，返回非零，由调用方决定判几；
#   - token 只经 stdout 交给调用方的**变量**，本脚本不写文件、不打日志。
set -uo pipefail

# cosign 默认要的 audience 是 sigstore。少数私有部署会换成自己的
# Fulcio 标识，所以留一个覆盖口子，默认仍是标准值。
AUDIENCE="${SIGSTORE_OIDC_AUDIENCE:-sigstore}"

if [ -n "${SIGSTORE_ID_TOKEN:-}" ]; then
  printf '%s' "$SIGSTORE_ID_TOKEN"
  exit 0
fi

URL="${ACTIONS_ID_TOKEN_REQUEST_URL:-}"
CRED="${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}"
if [ -z "$URL" ] || [ -z "$CRED" ]; then
  echo "::error::没有可用的 OIDC 签发方：ACTIONS_ID_TOKEN_REQUEST_URL / ACTIONS_ID_TOKEN_REQUEST_TOKEN 缺失" >&2
  exit 1
fi

# audience 是拼进 query 的，不放进 argv 以外的位置；URL 本身由 runner 注入，
# 但保险起见仍按「可能已带 query」处理。token 不走命令行，避免进 ps 与日志。
SEP='?'
case "$URL" in
  *\?*) SEP='&' ;;
esac

RESP="$(curl -sS --retry 2 --max-time 20 \
  -H "Authorization: bearer ${CRED}" \
  -H "Accept: application/json" \
  "${URL}${SEP}audience=${AUDIENCE}")" || {
  echo "::error::向 OIDC 端点换 token 失败（网络或端点异常）" >&2
  exit 1
}

# 响应体是 {"value":"<jwt>"}。故意不把响应原文打出来：里面就是凭据。
TOKEN="$(printf '%s' "$RESP" | python3 -c '
import json, sys
try:
    print(json.load(sys.stdin).get("value") or "", end="")
except Exception:
    print("", end="")
')"

if [ -z "$TOKEN" ]; then
  echo "::error::OIDC 端点没有返回 token：检查 job 的 permissions.id-token: write" >&2
  exit 1
fi

printf '%s' "$TOKEN"
