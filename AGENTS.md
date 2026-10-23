# Agent Instructions（AGENTS.md）

> ⚠️ **身份锚定**：本仓库的 Agent 是 **SuperNPC**，不是任何 CLI 工具 / 运行时的品牌名。
> 文档里出现的 `CodeBuddy`、`Claude`、`Qwen` 等只是底层运行时可选项，**不构成 Agent 身份**。
>
> 本文件是仓库内唯一的 Agent 入口文档：第 1~7 章是通用协作规范，第 8 章是本项目技术上下文。
>
> 项目：`evidence-pack` — 把一次 CI 构建钉成可独立验证的证据包
> （确定性打包 + 严格 manifest + cosign bundle 签名 + 退出码 0/2/3 分层）。

## 1. Git 提交规范

### 1.1 语言与格式
- **提交信息一律中文**，禁止全英文描述。
- 遵循 Angular 规范：`<type>(<scope>): <subject>`，subject 不超过 50 字符。
- type：`feat` / `fix` / `docs` / `style` / `refactor` / `perf` / `test` / `chore`。

示例：
- ✅ `feat(verify): 缺少外部锚点时判为不构成证据`
- ❌ `fix: handle missing anchor`

### 1.2 GPG 签名（强制）
本仓库开启 commit 签名，**每次 `git commit` 前必须先执行**：

```bash
bash install_gpg_keys.sh
```

脚本自包含、幂等、适配无 TTY 容器，完成后会做签名闭环自检，失败即 `exit 1`。
**严禁**跳过脚本裸提交，也**严禁**自行生成新密钥（未登记的公钥在平台侧等同未签名）。

### 1.3 提交后 / 推送前验签

```bash
# 提交后：本条必须是 G 或 U
test "$(git log -1 --format='%G?')" = G || { echo "❌ 本条未签名"; exit 1; }

# 推送前：待推范围逐条验签
git log --format='%h %G? %s' "origin/main..HEAD" | tee /tmp/sig.txt
! grep -vE ' [GU] ' /tmp/sig.txt || { echo "❌ 待推范围内有未签名提交"; exit 1; }
```

`%G?` 中 `N` = 无签名，`E` = 本机缺公钥（不等于没签，须另查 `--show-signature`）。
任何一条为 `N` → 禁止 push，先修环境再重签，不要用 `--no-verify` 把问题推给平台。

### 1.4 已推上去才发现 unsigned
只重签那一条：HEAD 用 `git commit --amend -S --no-edit`，中间某条用 `rebase -i` 标 `edit` 后重签，
再 `git push --force-with-lease`。**不要**对全分支 `rebase --root` / `filter-branch`。

## 2. 编码规范

- Python 3.10+，函数与关键变量必须有类型注解；禁止图省事滥用 `Any`。
- 命名遵循 PEP 8：函数/变量 `snake_case`，类 `PascalCase`，常量 `UPPER_SNAKE_CASE`。
- **注释与文档用中文**，重点覆盖：确定性相关的排序/时间来源处理、退出码分流、签名与验签边界。
- 错误处理只区分「用法错 / 证据无效 / 工具异常」三档，与退出码 1/2/3 一一对应，不要在中间层吞异常。

## 3. 工作流准则

- **阅读先于修改**：编辑前必须读真实文件内容，不凭记忆猜代码。
- **局部精准修改**：禁止全量覆盖、禁止夹带无关改动；提交前用 `git diff` 复核。
- **闭环验证**：改完必须跑 `python -m pytest -q`；涉及 `pack`/`verify` 行为的改动，还要手跑一次端到端。
- **不直接推主分支**：所有改动走 PR，变更可审查、可追溯。

## 4. CI/CD

- 变更若影响 `pack` 输出（文件集合、哈希、metadata 字段），**必须**同时考虑确定性测试
  （同一输入两次打包产物哈希一致），否则会被测试拦住。
- 新增外部命令依赖（如 `cosign`）时，缺失路径必须走退出码 3，而不是 2。

## 5. 本项目的三条硬规矩

1. **信任根必须在包外**：`manifest/sha256sum.txt` 只能证明包内自洽。没有签名、也没有
   `--expect-sha256` / `--expect-repo` 时，`verify` 必须判 2，不许吐绿。
2. **退出码语义不许混**：2 是「有人动过手脚」，3 是「流水线坏了」，人工处置完全不同。
3. **确定性优先**：时间戳统一取 `SOURCE_DATE_EPOCH`，文件排序显式指定，禁止依赖文件系统顺序。

## 6. 敏感信息

- passphrase、私钥、token 一律经密钥仓库注入环境变量，**禁止**写进代码、`.cnb.yml`、文档、评论或测试夹具。
- `install_gpg_keys.sh` 刻意不内置任何分发地址与凭据；缺变量即报错退出，不做兜底猜测。

## 7. 运行时预装能力（按需使用）

- 镜像预装 Playwright + chromium（`PLAYWRIGHT_BROWSERS_PATH=/ms-playwright`），中文字体齐备；
  便捷脚本：`node /app/scripts/browser-automation.js {title|text|html|shot|eval} <url>`。
- 预装 CodeQL CLI（`/opt/codeql`），需要语义级安全扫描时可直接建库分析。

## 8. 本项目技术上下文

### 8.1 模块分工

```
src/evidence_pack/
├── cli.py        # Typer 入口：pack / verify，退出码分流
├── collect.py    # 按 --include/--exclude 收集输入，保留仓库相对路径
├── fsutil.py     # 排序、遍历、哈希等确定性工具
├── packer.py     # 组包：artifacts / metadata / sbom / manifest，产出 tar.gz
├── sbom.py       # CycloneDX 生成（auto 模式下拿不到即退出码 3）
├── signing.py    # cosign key / keyless，只产 .sigstore.json
├── verifier.py   # 解包校验 + 签名校验 + 包外锚点比对
└── errors.py     # 异常类型 ↔ 退出码映射
```

### 8.2 退出码契约

| 码 | 含义 | 触发点 |
|---|---|---|
| 0 | 证据通过 | 校验全绿，且有签名或包外锚点 |
| 1 | 用法错误 | 参数非法，与证据真伪无关 |
| 2 | 证据无效 | 哈希不符 / 签名 invalid / identity 不匹配 / 锚点不符 / 无信任根 |
| 3 | 工具异常 | `cosign` 缺失、bundle 格式坏、SBOM 要而不得 |

### 8.3 包内布局

```
artifacts/<rel_path>        保留仓库内相对路径
metadata/metadata.json      工具版本、格式版本、SOURCE_DATE_EPOCH
metadata/run.json           CI 上下文（GitHub / CNB / GitLab，采到就记）
metadata/git.json           HEAD sha、branch、remote、dirty
sbom/sbom.cdx.json          CycloneDX
manifest/inputs.json        输入清单
manifest/sha256sum.txt      除自身外每个文件的 sha256
```

### 8.4 开发环境

```bash
pip install -e ".[dev]"
python -m pytest -q          # 签名相关用例在无 cosign 时自动跳过
```

### 8.5 已知取舍

- **不做 fork**：只沿用上游思路（确定性打包、严格解包、双输出模式），签名层与 CLI 全重写。
  上游产 `.sig` + `.crt` 两文件，cosign v3 已废弃；其 `verify` 只信退出码，假 cosign 能骗过它。
- **包内自洽不算证据**：这是设计上的核心判断，不是 bug，不要「优化」成无锚点也返回 0。
