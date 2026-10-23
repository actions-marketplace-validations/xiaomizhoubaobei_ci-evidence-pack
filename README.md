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
      sign: 'true'
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
`src` 塞进 `PYTHONPATH`；cosign 只在 `sign: true` 时才装。

完整示例见 [`examples/`](examples)：最小可用、keyless 签名、下游校验各一份。

## 安装（本地 / 脚本调用）

```bash
pip install -e ".[dev]"
```

验签需要 `cosign` v3+ 在 PATH 上。SBOM 需要 `cyclonedx-py` / `cyclonedx-npm`；
Python 项目缺 `cyclonedx-py` 时会退到 `requirements.txt` 的内置解析，不静默出空 SBOM。

## 用法

```bash
# 打包（确定性）
evidence-pack pack --repo . --include dist --include configs --sbom auto

# 用 cosign key 模式签名（只产 .sigstore.json）
COSIGN_PASSWORD=... evidence-pack pack --repo . --include dist --key cosign.key

# keyless 签名（CI 里需要有 OIDC token；--identity/--issuer 只写期望值进包）
evidence-pack pack --repo . --include dist --sign \
  --identity "https://github.com/org/repo/.github/workflows/ci.yml@refs/heads/main"

# 不签（此时必须有包外锚点才算证据）
evidence-pack pack --repo . --include dist

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
