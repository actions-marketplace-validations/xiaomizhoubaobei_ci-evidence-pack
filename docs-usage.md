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

本仓库跑在 CNB 上，`.cnb.yml` 里同理：`pack` 之后把 sha256 写进制品或评论，
签名用 `cosign sign-blob --bundle`。

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
