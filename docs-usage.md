# 接入到 CI

这里只写怎么把 `evidence-pack` 接进流水线，各字段的语义见 README。
本仓库只提供 Action；遇到需要手写的关键动作，调的是同一个内核：
`python3 -m evidence_pack.action pack|verify|rekor`。

## 关键：证据的信任根必须在包外

包内的 `manifest/sha256sum.txt` 谁都能重算，它只能证明「这个包里文件没坏」。
所以接入时至少做对一件事：

1. **签名**，并把 identity 写死到 workflow 文件路径（别用正则宽匹配）
2. **或者**把 bundle 的 sha256 记进一个包之外的不可变位置（审计库 / 制品库 / Rekor），
   验签时回送 `expect-sha256`

只做第 2 条、完全不签名，证据依然有意义 —— 前提是你真的把 sha 存到了包外。

## GitHub Actions：直接用 Action

```yaml
permissions:
  contents: read
  id-token: write   # 签名的全部信任根

steps:
  - uses: actions/checkout@v4
  # 钉到 SHA：浮动 @main 会让「跑的是哪一版」说不清
  - uses: xiaomizhoubaobei/ci-evidence-pack@6d8ae66b768b8a77fb691fcb88729c8fc13dd912
    id: evidence
    with:
      include: |
        dist/
        configs/
      sbom: auto
      sign: 'true'                # 用 OIDC 换短期证书，没有第二种身份
      # identity 留空 = 按本次触发的 repository + workflow + ref 自动拼。
      # 要显式写就把 ref 也交给表达式，别把 @refs/heads/main 刻进文件里。
      identity: https://github.com/${{ github.repository }}/.github/workflows/ci.yml@${{ github.ref }}
      issuer: https://token.actions.githubusercontent.com
      anchor-file: _evidence/anchor.txt
      expect-repo: ${{ github.repository }}
```

它做的事，按顺序：

1. 检查 `python3 >= 3.13`（不往你的环境里装包，只借 `PYTHONPATH`；内核纯标准库）
2. `sign != 'false'` 时装 cosign，并拿 OIDC 换短期证书
3. `pack` → 包与 `.sigstore.json`
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
| `sign` | `'true'`（签名） | 只有小写 `'false'` 才算关。条件传值时用 `cond && 'false' \|\| ''`，别直接传 outputs（会渲染成 `'False'`） |
| `identity` / `issuer` | identity 按触发 ref 自动拼，issuer 默认 GitHub OIDC | 期望签发身份，写进包内 `binding.json` |
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
    repository: xiaomizhoubaobei/ci-evidence-pack
    path: .evidence-pack

- shell: bash
  env:
    ACTION_PATH: ${{ github.workspace }}/.evidence-pack
    INPUT_BUNDLE: _evidence/bundle.tar.gz
    INPUT_EXPECT_SHA256: ${{ inputs.bundle-sha256 }}
  run: bash "$ACTION_PATH/scripts/action-verify.sh"
```

它同样只出结论：JSON 与 `GITHUB_STEP_SUMMARY` 里各一份，
进程退出码保留 0/1/2/3 的语义。

### 手写步骤（不用 Action）

Action 已经把你的产物、签名、锚点、artifact 串成一条链。手写等价步骤只在
想插自己的逻辑时才需要 —— 内核是 `python3 -m evidence_pack.action`，
参数全走 `INPUT_*` 环境变量：

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: actions/checkout@v4
    with:
      repository: xiaomizhoubaobei/ci-evidence-pack
      path: .evidence-pack
  - name: 打包
    env:
      PYTHONPATH: ${{ github.workspace }}/.evidence-pack/src
      REPO_ROOT: ${{ github.workspace }}
      INPUT_INCLUDE: |
        dist/
        configs/
      INPUT_SBOM: auto
      INPUT_SIGN: 'false'          # 不签名就必须自备包外锚点
    run: |
      python3 -m evidence_pack.action pack > pack-result.json
  - name: 登记锚点
    run: |
      python3 -c 'import json;print(json.load(open("pack-result.json"))["bundle_sha256"])' > anchor.txt
      # 把 anchor.txt 存到包外：制品库、审计库、你自己的账本
```

要签名就把 `INPUT_SIGN` 去掉（默认签），并让 `SIGSTORE_ID_TOKEN` 就绪 ——
Action 的打包脚本会拿 runner 注入的凭据换 token，手写时得自己换（见下一节）。

## 别的 CI：只借用内核

本仓库不提供命令行程序，所以 CNB / GitLab 上接它只有一种形态：
把本仓库检出到工作区，设 `PYTHONPATH=<检出位置>/src`，然后调
`python3 -m evidence_pack.action pack|verify`。

```yaml
main:
  push:
    - stages:
        - name: 打包并签名（OIDC 短期证书）
          script: |
            git clone --depth 1 https://github.com/xiaomizhoubaobei/ci-evidence-pack .evidence-pack
            export PYTHONPATH="$PWD/.evidence-pack/src"
            export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
            export SIGSTORE_ID_TOKEN="$CNB_OIDC_TOKEN"     # 变量名按平台实际给的那个填
            export INPUT_INCLUDE=$'dist\nconfigs'
            python3 -m evidence_pack.action pack > pack.json
        - name: 登记锚点
          script: |
            sha256sum dist/*.tar.gz > anchor.txt   # 存到包外：制品库 / 审计库
```

token 由平台注入到环境变量（变量名按平台实际给的那个填）。
**别把 token 写进 `.cnb.yml`** —— 配置文件与作业日志都是公开可读的。
同理，内核只从 `SIGSTORE_ID_TOKEN` 读 token，它不会出现在任何命令行里。

验签一侧：

```yaml
- name: 验包
  script: |
    export PYTHONPATH="$PWD/.evidence-pack/src"
    export INPUT_BUNDLE=dist/x.tar.gz
    export INPUT_SIGNATURE_BUNDLE=dist/x.tar.gz.sigstore.json
    export INPUT_IDENTITY="https://cnb.cool/<org>/<repo>/-/build.yml@refs/heads/main"
    export INPUT_ISSUER="https://oidc.cnb.cool"
    export INPUT_EXPECT_SHA256="$ANCHOR"
    python3 -m evidence_pack.action verify | tee verify-result.json
    # verify 恒退出 0：判定在 JSON 的 exit_code 里（0/1/2/3）。
    code=$(python3 -c 'import json;print(json.load(open("verify-result.json"))["exit_code"])')
    case "$code" in
      0) echo "证据有效" ;;
      2) echo "证据无效 —— 停止发版"; exit 1 ;;
      3) echo "工具坏了 —— 别把这也当成篡改"; exit 1 ;;
      *) echo "参数错了"; exit 1 ;;
    esac
```

identity 要和签名那次**完全一致**：workflow 文件路径 + ref。改了流水线文件名，
历史 bundle 就验不过了 —— 这是特性，不是 bug。

`@` 后面那截跟着触发 ref 走，别写死。GitHub 上写 `@${{ github.ref }}`
（`refs/heads/main` / `refs/tags/v1.0.0`），CNB 上写 `@${{ CNB_BRANCH }}` 之类；
在 Action 里干脆留空 —— 它会按本次触发的 repository + workflow + ref 自动拼。
把 `@refs/heads/main` 抄进一个 tag 触发的流水线，只会在签完名之后判 2：
「签名身份不是我以为的那个」，跟配置笔误不是一个事故等级。

## GitHub Actions 的 OIDC 签名链路

用 Action 的话不必自己换 token：`sign != 'false'` 之后，`scripts/action-pack.sh`
会拿 runner 注入的 `ACTIONS_ID_TOKEN_REQUEST_URL` + `ACTIONS_ID_TOKEN_REQUEST_TOKEN`
去换一枚 `audience=sigstore` 的 token，放进 `SIGSTORE_ID_TOKEN` 交给内核。
这是唯一的签名链路，没有私钥备胎。

**这里有个坑值得单独说**：`ACTIONS_ID_TOKEN_REQUEST_TOKEN` 是**换 token 的凭据**，
不是 token 本体。把它当 token 用，Fulcio 只会回 401，而现场看起来跟
「`id-token: write` 没开」一模一样 —— 最难查的那种。判据必须是「有没有签发方」，
而不是「某个变量在不在」。

手写步骤时要自己换（Action 内部做的就是这一段）：

```yaml
permissions:
  contents: read
  id-token: write            # 换 OIDC token 必需，少这一行只会得到空 token

steps:
  - uses: actions/checkout@v4
    with:
      repository: xiaomizhoubaobei/ci-evidence-pack
      path: .evidence-pack
  - run: |
      # 注意：响应体里就是凭据，别 echo 出来
      id_token=$(curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
        "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=sigstore" | python3 -c 'import json,sys;print(json.load(sys.stdin)["value"])')
      echo "SIGSTORE_ID_TOKEN=$id_token" >> "$GITHUB_ENV"
  - env:
      PYTHONPATH: ${{ github.workspace }}/.evidence-pack/src
      INPUT_INCLUDE: |
        dist/
    run: python3 -m evidence_pack.action pack > pack-result.json
```

token 只走环境变量 `SIGSTORE_ID_TOKEN`，绝不拼进命令行：
argv 会被 `ps`、作业日志和调试输出记住。谁拿到它，谁就能用你的身份签任何东西。

换不到 token（端点 401 / 权限没开 / 变量缺失）一律是**退出码 3**：
凭据没到位是「流水线坏了」，不是「证据无效」，两者的处置完全不同。

自检（打完包立刻验一遍）就是给内核两组环境变量：

```yaml
- env:
    PYTHONPATH: ${{ github.workspace }}/.evidence-pack/src
    INPUT_BUNDLE: ${{ steps.pack.outputs.bundle-path }}
    INPUT_SIGNATURE_BUNDLE: ${{ steps.pack.outputs.signature-bundle }}
    INPUT_EXPECT_SHA256: ${{ steps.pack.outputs.bundle-sha256 }}
  run: python3 -m evidence_pack.action verify | tee verify-result.json
```

注意这里回送的摘要就是「上一步刚算出来的」那个 —— 那是自己给自己发证，
只够证明产物在步骤之间没被动过。要信任根，请给 `INPUT_IDENTITY`/`INPUT_ISSUER`、
或从包外登记的账本里取 sha 回送。

## 发版场景：照抄这一份

[`examples/release.yml`](examples/release.yml) 覆盖的是最常见的发版诉求：
打 tag → 打包产物 → 签名 → 自检 → 挂到 Release，并把 sha256 写进 Release 正文。

需要你改的只有一处：`include` 里的产物路径（`dist/` 换成你真实的产物目录）。
不需要配任何密钥 —— 信任根是 job 的 OIDC token，job 上开 `id-token: write` 即可。

想彻底不签名（比如自托管 runner 拿不到 OIDC），写 `sign: 'false'`，
并且必须自己把 sha256 登记到包外 —— 否则自检会如实判 2。

## 关于 `expect-repo` 的边界

包内记了 git remote 就核对，不符判 2 —— 这条没得商量。

包内**没有** remote 元数据时不再判 2。`actions/checkout` 检出的工作区、
剥离了 `.git` 的构建上下文都属于这种情况，这是采集环境的问题，不是
篡改的证据。此时会在 `anchor_warnings` 里留一句「这条锚点没起作用」，
让 `anchored: true` 的成色不被误解成「仓库身份也核对过了」。

## 退出码怎么用

流水线上只认 0：

```bash
# verify 恒以 0 退出，判定在 JSON 的 exit_code 里；exit_code 就是下面这三档。
code=$(python3 -c 'import json;print(json.load(open("verify-result.json"))["exit_code"])')
case "$code" in
  0) echo "证据有效" ;;
  2) echo "证据无效 —— 停止发版"; exit 1 ;;
  3) echo "工具坏了 —— 别把这也当成篡改"; exit 1 ;;
  *) echo "参数错了"; exit 1 ;;
esac
```

2 和 3 分开的意义就在这里：一个是「有人动手脚」，一个是「你的流水线坏了」，
两者的人工处置完全不同，不该混成一个红叉。
