# 接入到 CI

这里只写怎么把 `evidence-pack` 接进流水线，命令本身的语义见 README。

## 关键：证据的信任根必须在包外

包内的 `manifest/sha256sum.txt` 谁都能重算，它只能证明「这个包里文件没坏」。
所以接入时至少做对一件事：

1. **签名**，并把 identity 写死到 workflow 文件路径（别用正则宽匹配）
2. **或者**把 bundle 的 sha256 记进一个包之外的不可变位置（审计库 / 制品库 / Rekor），
   验签时用 `--expect-sha256` 回送

只做第 2 条、完全不签名，证据依然有意义 —— 前提是你真的把 sha 存到了包外。

## GitHub Actions：直接用 Action

```yaml
permissions:
  contents: read
  id-token: write   # keyless 签名必需

steps:
  - uses: actions/checkout@v4
  - uses: XMZZUZHI/Github/ci-evidence-pack@main
    id: evidence
    with:
      include: |
        dist/
        configs/
      sbom: auto
      # 不用写 sign：默认就签名。不给 cosign-key 就走 keyless
      identity: https://github.com/${{ github.repository }}/.github/workflows/ci.yml@refs/heads/main
      issuer: https://token.actions.githubusercontent.com
      anchor-file: _evidence/anchor.txt
      expect-repo: ${{ github.repository }}
```

它做的事，按顺序：

1. 检查 `python3 >= 3.10`（不往你的环境里装包，只借 `PYTHONPATH`）
2. 装 cosign（除非显式 `sign: 'false'`）
3. `pack` → 包与 `.sigstore.json`（默认签名）
4. `anchor-file` 有值时把 sha256 追加登记（包外台账）
5. `verify: true`（默认）自检：有签名验签名，没签名则以 `expect-sha256` 为锚点
6. `upload-artifact: true`（默认）把包、签名、台账一起上传

### Action 的参数

| 输入 | 默认 | 说明 |
|---|---|---|
| `include` | 必填 | 一行一个，支持 `#` 注释 |
| `exclude` | 空 | 额外排除的目录名 |
| `sbom` | `auto` | `auto` / `none` / `python` / `node` |
| `out-dir` | `_evidence` | 输出目录，会自动排除在收集范围外 |
| `bundle-name` | `evidence-<短sha>.tar.gz` | 包名（保存时会去掉开头的点） |
| `sign` | `true` | 是否用 cosign 签名。`'false'` 只在你有另一条包外锚点时才是可辩护的选择 |
| `cosign-key` | 空 | cosign **私钥**，仅用于签名；口令用 `COSIGN_PASSWORD` 环境变量 |
| `cosign-public-key` | 空 | cosign **公钥**，仅用于验签。签名用私钥、验签用公钥，不能互换 |
| `identity` / `issuer` | issuer 默认 GitHub OIDC | 期望签发身份，写进包内 `binding.json` |
| `verify` | `true` | 打完包立刻自检 |
| `expect-sha256` | 空（用本次产物的 sha） | 包外锚点 |
| `expect-repo` | 空 | 包外锚点 |
| `anchor-file` | 空 | 追加登记 sha256 的文件 |
| `upload-artifact` | `true` | 是否上传 artifact |
| `retention-days` | `30` | artifact 保留天数 |
| `artifact-name` | 空（用包 sha256 前 16 位） | artifact 名；默认值跨 job 唯一，也天然不含 `/ : @` 这类非法字符 |
| `fail-on-invalid` | `true` | 自检结论为 2/3 时是否让步骤失败 |

`fail-on-invalid: false` 适合「先取证、后发版」：判定照样写进 outputs 与
job summary（含 0/1/2/3 的含义），但不会把后续步骤掐断。

`expect-sha256` 留空时用的是本次刚打出来的包的 sha —— 那只是「自己给自己发证」，
能证明产物在步骤之间没被动过，**不等于**包外锚点。真正的锚点要从你登记它的
地方（制品库 / 审计库）回送。

### 只校验、不打包

`action.yml` 是「打包 + 可选自检」的复合体。只想验一个已有包时，直接用仓库里的脚本 ——
注意 `ACTION_PATH` 必须指向 **evidence-pack 仓库的检出位置**，不能填自己的 workspace：

```yaml
- uses: actions/checkout@v4
  with:
    repository: XMZZUZHI/Github/ci-evidence-pack
    path: .evidence-pack

- shell: bash
  env:
    ACTION_PATH: ${{ github.workspace }}/.evidence-pack
    INPUT_BUNDLE: _evidence/bundle.tar.gz
    INPUT_EXPECT_SHA256: ${{ inputs.bundle-sha256 }}
  run: bash "$ACTION_PATH/scripts/action-verify.sh"
```

它同样走 `verify --exit-code`：结论在 JSON 与 `GITHUB_STEP_SUMMARY` 里，
进程退出码保留 0/1/2/3 的语义。

### 手写步骤（不用 Action）

```yaml
steps:
  - uses: actions/checkout@v4
  - run: pip install evidence-pack
  - run: evidence-pack pack --repo . --include dist --include configs --sbom auto
  - name: 登记锚点
    run: |
      sha256sum dist/*.tar.gz | tee anchor.txt
      # 把 anchor.txt 存到包外：制品库、审计库、你自己的账本
  - uses: sigstore/cosign-installer@v3
  - run: cosign sign-blob --yes --bundle dist/x.tar.gz.sigstore.json dist/x.tar.gz
```

## CNB

本仓库跑在 CNB 上。CNB 的流水线可以拿到 OIDC token，于是不需要托管任何私钥：

```yaml
main:
  push:
    - stages:
        - name: 打包并 keyless 签名
          script: |
            pip install evidence-pack
            export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
            evidence-pack pack --repo . --include dist --include configs \
              --sbom auto --oidc-token-env CNB_OIDC_TOKEN
        - name: 登记锚点
          script: |
            sha256sum dist/*.tar.gz > anchor.txt   # 存到包外：制品库 / 审计库
```

token 由平台注入到 `CNB_OIDC_TOKEN`（变量名按平台实际给的那个填）。
**别把 token 写进 `.cnb.yml`**，也别用 `--oidc-token` 直接把字面量贴在命令里 ——
`.cnb.yml` 和作业日志都是公开可读的。

验签一侧：

```bash
evidence-pack verify dist/x.tar.gz \
  --signature-bundle dist/x.tar.gz.sigstore.json \
  --identity "https://cnb.cool/<org>/<repo>/-/build.yml@refs/heads/main" \
  --issuer "https://oidc.cnb.cool" \
  --expect-sha256 "$ANCHOR"
```

identity 要和签名那次**完全一致**：workflow 文件路径 + ref。改了流水线文件名，
历史 bundle 就验不过了 —— 这是特性，不是 bug。

## GitHub Actions 的 keyless 写法

```yaml
permissions:
  contents: read
  id-token: write            # 换 OIDC token 必需，少这一行只会得到空 token

steps:
  - run: pip install evidence-pack
  - run: |
      evidence-pack pack --repo . --include dist \
        --oidc-token-env SIGSTORE_ID_TOKEN
    env:
      SIGSTORE_ID_TOKEN: ${{ steps.oidc.outputs.token }}   # 或直接让 cosign 自取
```

GitHub 上 cosign 能自动从 Actions 拿 token，不必显式传；显式传的好处是
`--oidc-token-env` 名字写死在命令里，签名身份来源可审计。

```yaml
main:
  push:
    - stages:
        - name: pack
          script: |
            pip install -e .
            evidence-pack pack --repo . --include dist --sbom auto --json | tee pack.json
            sha=$(python3 -c "import json;print(json.load(open('pack.json'))['bundle_sha256'])")
            evidence-pack verify "$(python3 -c "import json;print(json.load(open('pack.json'))['bundle_path'])")" \
              --expect-sha256 "$sha" --exit-code --json
```

## 发版场景：照抄这一份

[`examples/release.yml`](examples/release.yml) 覆盖的是最常见的发版诉求：
打 tag → 打包产物 → 签名 → 自检 → 挂到 Release，并把 sha256 写进 Release 正文。

需要你改的只有两处：

1. `include` 里的产物路径（`dist/` 换成你真实的产物目录）
2. 三个 secret（可选）：`COSIGN_KEY_B64`、`COSIGN_PUBLIC_KEY_B64`、`COSIGN_PASSWORD`

密钥用 base64 存，是因为 PEM 里的换行经 YAML / JSON 一转手很容易被吃掉，
而「少了换行的私钥」只会报一句难以理解的解析错误。

```bash
base64 -w0 cosign.key   # 填进 COSIGN_KEY_B64
base64 -w0 cosign.pub   # 填进 COSIGN_PUBLIC_KEY_B64
```

没配密钥也照样跑：示例里 `sign: ${{ steps.cosign.outputs.configured }}` 会算成
`false`，退化成「无签名 + sha256 锚点」模式，并打出 notice 说明原因。

注意默认值是 `true`：一个 job 若既没配 `cosign-key`、也没有 `id-token: write`，
会直接判退出码 1（缺 OIDC token）而不是悄悄不签。要么补权限，要么显式关签名。

## 关于 `expect-repo` 的边界

包内记了 git remote 就核对，不符判 2 —— 这条没得商量。

包内**没有** remote 元数据时不再判 2。`actions/checkout` 检出的工作区、
剥离了 `.git` 的构建上下文都属于这种情况，这是采集环境的问题，不是
篡改的证据。此时会在 `anchor_warnings` 里留一句「这条锚点没起作用」，
让 `anchored: true` 的成色不被误解成「仓库身份也核对过了」。

## 退出码怎么用

流水线上只认 0：

```bash
evidence-pack verify bundle.tar.gz --expect-sha256 "$EXPECTED"
case $? in
  0) echo "证据有效" ;;
  2) echo "证据无效 —— 停止发版"; exit 1 ;;
  3) echo "工具坏了 —— 别把这也当成篡改"; exit 1 ;;
  *) echo "参数错了"; exit 1 ;;
esac
```

2 和 3 分开的意义就在这里：一个是「有人动手脚」，一个是「你的流水线坏了」，
两者的人工处置完全不同，不该混成一个红叉。
