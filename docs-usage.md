# 接入到 CI

这里只写怎么把 `evidence-pack` 接进流水线，命令本身的语义见 README。

## 关键：证据的信任根必须在包外

包内的 `manifest/sha256sum.txt` 谁都能重算，它只能证明「这个包里文件没坏」。
所以接入时至少做对一件事：

1. **签名**，并把 identity 写死到 workflow 文件路径（别用正则宽匹配）
2. **或者**把 bundle 的 sha256 记进一个包之外的不可变位置（审计库 / 制品库 / Rekor），
   验签时用 `--expect-sha256` 回送

只做第 2 条、完全不签名，证据依然有意义 —— 前提是你真的把 sha 存到了包外。

## GitHub Actions

```yaml
permissions:
  contents: read
  id-token: write   # keyless 签名必需

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
