"""异常与退出码。

退出码是本工具的对外契约，三者互不重叠：

  0  证据通过
  1  用法错误（参数矛盾、--include 不存在、keyless 缺 identity）
     —— 用户敲错了，重敲即可，与证据真伪无关
  2  证据无效（哈希不符、签名 invalid、identity 不匹配、锚点不符）
     —— 工具工作正常，结论是「这份证据不可信」
  3  工具异常（cosign 缺失、bundle 格式坏、子进程炸、SBOM 要而不得）
     —— 不知道证据真假，请修工具或环境

2 与 3 的分界是刻意留的：只有 0 是绿灯，2 意味着「有人动过手脚」，
3 意味着「你的流水线坏了，别怪证据」。
"""

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_EVIDENCE_INVALID = 2
EXIT_TOOL_FAILURE = 3


class EvidenceError(Exception):
    """本工具所有预期失败的基类。"""

    exit_code = EXIT_TOOL_FAILURE
    kind = "tool_failure"


class UsageError(EvidenceError):
    """调用方用错了。"""

    exit_code = EXIT_USAGE
    kind = "usage"


class EvidenceInvalid(EvidenceError):
    """证据链断在内容或签名上。"""

    exit_code = EXIT_EVIDENCE_INVALID
    kind = "evidence_invalid"


class ToolFailure(EvidenceError):
    """工具/环境层面的失败，与证据真伪无关。"""

    exit_code = EXIT_TOOL_FAILURE
    kind = "tool_failure"
