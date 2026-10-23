# evidence-pack

把一次 CI 构建钉成一份可独立验证的证据包：确定性打包、严格 manifest、
cosign bundle 签名、退出码 0/2/3 分层。

> 灵感来自 [OrygnsCode/ci-evidence-pack](https://github.com/OrygnsCode/ci-evidence-pack)（MIT）。
> 只沿用它的思路（确定性打包、严格解包、双输出模式），签名层与 CLI 全部重写。

## 为什么不是 fork

原项目的内核值得学，签名层不值得救：它产 `.sig` + `.crt` 两文件，
而 cosign v3 已经废弃这套形态；`verify` 只信退出码，一个 `exit 0`
的假 cosign 就能骗过它。与其 fork 过来背历史包袱，不如把内核重写一遍。

## 贡献与签名

提交前请读 [`AGENTS.md`](AGENTS.md)。本仓库开启 commit 签名，**commit 前必须先跑**：

```bash
export GPG_API=https://<你的密钥分发服务>   # 经密钥仓库注入，脚本不内置地址
export GPG_KEY=<passphrase>
bash install_gpg_keys.sh
```

脚本幂等、适配无 TTY 容器，末尾做真实 `git commit -S` 闭环自检，失败即退出非零。
无变量、无分发地址时直接报错 —— 这是刻意的：凭据不落仓库。

## 安装

```bash
pip install -e ".[dev]"
```

验签需要 `cosign` v3+ 在 PATH 上。

## 用法

```bash
# 打包（确定性）
evidence-pack pack --repo . --include dist --include configs --sbom auto

# 用 cosign key 模式签名（只产 .sigstore.json）
COSIGN_PASSWORD=... evidence-pack pack --repo . --include dist --key cosign.key

# keyless 签名（CI 里，需要有 OIDC token）
evidence-pack pack --repo . --include dist   # 不签

# 验包：带外部锚点
evidence-pack verify bundle.tar.gz --expect-sha256 <hex>

# 验包：带签名
evidence-pack verify bundle.tar.gz \
  --signature-bundle bundle.tar.gz.sigstore.json \
  --identity "https://github.com/org/repo/.github/workflows/ci.yml@refs/heads/main" \
  --issuer "https://token.actions.githubusercontent.com"
```

## 退出码

| 码 | 含义 | 该怎么办 |
|---|---|---|
| 0 | 证据通过 | 绿灯 |
| 1 | 用法错误 | 参数敲错了，与证据真伪无关 |
| 2 | 证据无效 | 哈希不符 / 签名 invalid / identity 不匹配 / 锚点不符 |
| 3 | 工具异常 | cosign 缺失、bundle 格式坏、SBOM 要而不得 —— 别信结论，修环境 |

2 和 3 分开是刻意的：前者意味着「有人动过手脚」，后者意味着「流水线坏了」。

## 包内布局

```
artifacts/<rel_path>        收进来的文件，保留仓库内相对路径
metadata/metadata.json      工具版本、格式版本、SOURCE_DATE_EPOCH
metadata/run.json           CI 上下文（GitHub / CNB / GitLab，采到就记）
metadata/git.json           HEAD sha、branch、remote、dirty
sbom/sbom.cdx.json          CycloneDX（要得到就必须有）
manifest/inputs.json        输入清单
manifest/sha256sum.txt      除自身外每个文件的 sha256
```

## 一条重要的判定

**manifest 自洽 ≠ 证据有效。** manifest 和内容躺在同一个包里，
谁都能改内容再重算哈希表。所以 `verify` 在既没有签名、也没有
`--expect-sha256` / `--expect-repo` 时，会明确判为「不构成证据」
并返回 2，而不是像常见做法那样吐一个绿色的 0。

证据的信任根必须来自包外：签名，或者调用方手里的锚点。

## 测试

```bash
python -m pytest -q
```

签名相关测试需要 `cosign`，没有则自动跳过。
