# evidence-pack

把一次 CI 构建钉成一份可独立验证的证据包：确定性打包、严格 manifest、
cosign bundle 签名、退出码 0/2/3 分层。

**签名是默认动作。** 有私钥就 key 模式，没有就走 keyless（OIDC 换 Fulcio
短期证书）。想不签，得显式说 `--no-sign` / `sign: 'false'` —— 并且自己
准备好包外的 sha256 锚点，否则这份包不构成证据。

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

## 当 Action 用

```yaml
permissions:
  contents: read
  id-token: write          # keyless 签名必需

steps:
  - uses: actions/checkout@v4
  - uses: XMZZUZHI/Github/ci-evidence-pack@main
    id: evidence
    with:
      include: |
        dist/
        configs/
      sbom: auto
      # 签名是默认动作：给了 cosign-key 走 key，否则走 keyless。
      # 只有明确写 sign: 'false' 才会不签名 —— 那时信任根必须来自包外锚点。
      identity: https://github.com/${{ github.repository }}/.github/workflows/ci.yml@refs/heads/main
      anchor-file: _evidence/anchor.txt     # 把 sha256 留在包外
```

产物与结论都能当 output 用：

| output | 说明 |
|---|---|
| `bundle-path` / `bundle-name` | 证据包位置 |
| `bundle-sha256` | 包外锚点就是它 |
| `signature-bundle` | `.sigstore.json`，未签名为空 |
| `signature-mode` | `key` / `keyless`，未签名为空 |
| `signed` | 是否产出了签名 |
| `verify-ok` / `verify-exit-code` / `verify-error` | 自检结论、0/1/2/3 与失败原因 |
| `signature-verified` / `anchored` | 签名真的验过没有、包外锚点核对过没有 |

Action 是 composite 的，不往调用方的解释器里 `pip install`，只把本仓库的
`src` 塞进 `PYTHONPATH`；cosign 默认就装上（因为默认要签名），
只有写 `sign: 'false'` 时才跳过。

完整示例见 [`examples/`](examples)：**发版即取证**（`release.yml`，照抄即可）、
最小可用、keyless 签名、下游校验各一份。

只想尽快用起来，直接把 [`examples/release.yml`](examples/release.yml) 复制到
你仓库的 `.github/workflows/` 下，然后改两处：`include` 里的产物路径、
以及（可选）`COSIGN_KEY_B64` / `COSIGN_PUBLIC_KEY_B64` / `COSIGN_PASSWORD`
三个 secret。没配密钥也不会红：示例会显式写 `sign: 'false'`，退化成
「无签名 + sha256 锚点」，并在 job 里给出 notice 说明。

> 签名默认开启这件事，意味着 job 需要 `permissions.id-token: write`。
> 少了它，默认路径（keyless）拿不到 token，会当场判用法错（1）而不是静默不签 ——
> 这是刻意的：一份「以为签了其实没签」的证据，比没有证据更危险。

### 关于 `expect-repo`

包内若记了 git remote，`expect-repo` 就据此核对，不符判 2；
包内没有 remote 元数据（`actions/checkout` 检出的默认形态、以及剥离了 `.git`
的构建上下文都是这样）时，**不判无效**，而是在 `anchor_warnings` 里说明
「这条锚点没起作用」。缺元数据是采集环境的问题，不是篡改的证据。

### 关于 SBOM

`sbom: auto` 认出 Python 项目后，依赖清单按这个顺序取：
`requirements.txt` → `poetry.lock`/`pipenv`（交给 cyclonedx-py）→
`pyproject.toml` 的 PEP 621 依赖表。都没有才判 3。
Action 会按项目类型自动补装 `cyclonedx-bom` / `@cyclonedx/cyclonedx-npm`，
Python 3.10 还会补 `tomli`（标准库 `tomllib` 要 3.11 才有）。

扫描器自带的 `metadata.timestamp` 与 `serialNumber` 会被归一化：
前者取 `SOURCE_DATE_EPOCH`，后者由内容派生。不这么做，
同一个 commit 打两次包会得到两个哈希 —— 可复现就是句空话。

## 安装（本地 / 脚本调用）

```bash
pip install -e ".[dev]"
```

验签需要 `cosign` v3+ 在 PATH 上。SBOM 需要 `cyclonedx-py` / `cyclonedx-npm`；
Python 项目缺 `cyclonedx-py` 时会退到 `requirements.txt` 的内置解析，不静默出空 SBOM。

## 用法

```bash
# 打包 + 签名（默认）：给了 --key 走 key，否则走 keyless
COSIGN_PASSWORD=... evidence-pack pack --repo . --include dist --key cosign.key

# keyless：用 OIDC token 换 Fulcio 短期证书（CI 里的主路径）
export SIGSTORE_ID_TOKEN=<平台注入的 OIDC token>
evidence-pack pack --repo . --include dist --oidc-token-env SIGSTORE_ID_TOKEN \
  --identity "https://github.com/org/repo/.github/workflows/ci.yml@refs/heads/main"

# 不签名（此时必须有包外锚点才算证据）。--no-sign 是唯一的关闭方式
evidence-pack pack --repo . --include dist --no-sign

# 验包：带外部锚点
evidence-pack verify bundle.tar.gz --expect-sha256 <hex>

# 验包：key 模式（签名用私钥，验签用公钥）
evidence-pack verify bundle.tar.gz \
  --signature-bundle bundle.tar.gz.sigstore.json \
  --verify-key cosign.pub

# 验包：keyless，身份必须写死到具体 workflow 文件
evidence-pack verify bundle.tar.gz \
  --signature-bundle bundle.tar.gz.sigstore.json \
  --identity "https://github.com/org/repo/.github/workflows/ci.yml@refs/heads/main" \
  --issuer "https://token.actions.githubusercontent.com"

# 只取结论，不让退出码中断流水线（Action 内部就是这么用的）
evidence-pack verify bundle.tar.gz --expect-sha256 <hex> --exit-code --json
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
metadata/binding.json       打包方声明的期望签发身份（给了 --identity/--issuer 才有）
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

`metadata/binding.json` 也一样 —— 它是打包方**声明**的期望身份，可以被伪造，
所以只在调用方没显式给 `--identity/--issuer` 时用来填空，绝不能当信任根。

## 测试

```bash
python -m pytest -q
```

签名相关测试需要 `cosign`，没有则自动跳过。
