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

# keyless：用 OIDC token 换 Fulcio 短期证书签名（CI 里的主路径）
export SIGSTORE_ID_TOKEN=<平台注入的 OIDC token>
evidence-pack pack --repo . --include dist --oidc-token-env SIGSTORE_ID_TOKEN

# 验包：带外部锚点
evidence-pack verify bundle.tar.gz --expect-sha256 <hex>

# 验包：带签名
evidence-pack verify bundle.tar.gz \
  --signature-bundle bundle.tar.gz.sigstore.json \
  --identity "https://github.com/org/repo/.github/workflows/ci.yml@refs/heads/main" \
  --issuer "https://token.actions.githubusercontent.com"
```

## keyless：OIDC 换短期证书

没有长期私钥可管，身份来自 CI 平台签发的 OIDC token：

1. 平台给流水线一张 token，里面 `sub` 写着"谁在跑"（workflow 路径 + ref），
   `iss` 写着"谁签发的"（平台的 OIDC issuer）；
2. cosign 拿 token 找 Fulcio 换一张**十几分钟就过期**的证书，私有钥当场生成、签完即弃；
3. 签名连同证书链、Rekor 条目一起封进 `.sigstore.json`。

所以 keyless 的信任根不是密钥，而是**那对 (identity, issuer)**。验签时必须同时给：

```bash
evidence-pack verify bundle.tar.gz \
  --signature-bundle bundle.tar.gz.sigstore.json \
  --identity "https://cnb.cool/<org>/<repo>/-/build.yml@refs/heads/main" \
  --issuer "https://oidc.cnb.cool"
```

identity 请写死到具体流水线文件，别用通配 —— 宽匹配等于让别人拿同一 issuer 下的
任意 workflow 冒充你。

### token 从哪进

| 写法 | 用途 |
|---|---|
| `--oidc-token-env VAR` | **推荐**。从环境变量读，token 只进子进程环境 |
| `--oidc-token <jwt>` | 仅本地调试。会进命令行历史、`ps` 和作业日志 |

两条来源同时给会直接判 1。变量存在但为空同样判 1 —— CI 里权限没开、secret 没配
是最常见的事故，静默当成"没签"比报错危险得多。

token 只经 `SIGSTORE_ID_TOKEN` 进子进程，**从不拼进 argv**。私有 Fulcio / Rekor 用
`--fulcio-url` / `--rekor-url` 指过去，验签侧必须用同一套根，否则证书链对不上判 2。

### 短期证书的边界

证书窗口很短，所以判定也短：

- keyless 签出的 bundle **必须**带证书链和 tlog 条目，缺一样判 3（Fulcio/Rekor 没通）
- 验签时 Rekor 记录的签名时刻若落在证书有效期之外，判 2 —— 那不是这张证书签的
- `--insecure-ignore-tlog` 可以跳过 tlog，但结果里 `tlog_checked` 会是 `false`，如实标注

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
