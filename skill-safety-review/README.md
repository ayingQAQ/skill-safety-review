# Skill Safety Review

中文说明见下方的 [中文 README](#中文说明)。

`skill-safety-review` is a Codex skill for statically reviewing a newly downloaded local skill before you enable, install, or trust it. It is designed to be conservative: it does not execute the target skill, does not fetch extra network context, and returns an evidence-based verdict such as `appears-safe`, `needs-manual-review`, or `unsafe`.

## Why This Exists

Third-party skills can contain more than plain instructions. A downloaded skill may include scripts, references, hidden files, archives, binaries, or prompt content that encourages unsafe behavior. This project adds a repeatable first-pass review workflow so you can inspect a skill folder before deciding whether to trust it.

## What It Does

- Reviews a local unpacked skill directory
- Scans code-bearing files and text content for risky patterns
- Flags opaque binaries, archives, hidden files, and symlinks
- Highlights prompt-level red flags in `SKILL.md`
- Produces structured output in `json` or human-readable `markdown`
- Keeps the final decision with the reviewer

## What It Does Not Do

- It does not execute any script from the reviewed skill
- It does not install, delete, or quarantine the reviewed skill
- It does not fetch Git history, repository metadata, or remote URLs in v1
- It does not guarantee a skill is safe; it only reports static evidence

## Verdict Model

| Verdict | Meaning |
| --- | --- |
| `appears-safe` | No suspicious patterns were found in scanned text files |
| `needs-manual-review` | The skill contains ambiguous findings, opaque files, or malformed structure |
| `unsafe` | The skill shows clear signs of dangerous execution, exfiltration, persistence, or safety-bypass instructions |

## What Gets Checked

The bundled scanner currently looks for:

- Shell or process execution primitives such as `subprocess`, `os.system`, `Start-Process`, `Invoke-Expression`, `bash -c`
- Network and download behavior such as `requests`, `urllib`, `socket`, `curl`, `wget`, `Invoke-WebRequest`
- Dynamic execution patterns such as `eval`, `exec`, `compile`, `importlib`, encoded payload hints
- Persistence targets such as shell profiles, startup folders, or other skill directories
- Hidden files, symlinks, suspicious binaries, and archives
- Prompt-level red flags such as bypassing safeguards, revealing secrets, skipping confirmation, or destructive commands
- Overly broad trigger descriptions that could make implicit invocation risky

## Repository Layout

```text
skill-safety-review/
├── README.md
├── SKILL.md
├── agents/
│   └── openai.yaml
├── references/
│   └── risk-rubric.md
└── scripts/
    └── audit_skill.py
```

## Requirements

- Python 3.10 or newer
- No third-party Python dependencies
- A local unpacked skill directory to review

## Use It As A Codex Skill

If you want Codex to invoke this as a reusable skill instead of only running the script manually, place the `skill-safety-review` folder inside your Codex skills directory.

Typical location:

```text
~/.codex/skills/skill-safety-review
```

After that, restart Codex so the new skill metadata is picked up.

## Quick Start

### 1. Review A Local Skill Directory

Run the bundled scanner against an unpacked local skill:

```bash
python scripts/audit_skill.py /path/to/downloaded-skill
```

For a human-readable report:

```bash
python scripts/audit_skill.py /path/to/downloaded-skill --format markdown
```

### 2. Interpret The Output

The scanner returns:

- `target_path`
- `verdict`
- `risk_level`
- `key_findings`
- `findings`
- `opaque_files`
- `notes`
- `inventory`

### 3. Review The Rubric

If the output is ambiguous, use [`references/risk-rubric.md`](./references/risk-rubric.md) to interpret the findings before deciding whether to trust the skill.

## Typical Review Workflow

1. Download or unpack a skill locally.
2. Run `scripts/audit_skill.py` against the skill directory.
3. Read the highest-severity findings first.
4. Inspect the surrounding file content manually.
5. Decide whether the skill looks safe enough to use, needs deeper review, or should be rejected.

## Notes On Conservative Results

This project intentionally prefers caution over silent approval.

- A skill with embedded binaries or archives may be reported as `needs-manual-review` even if it is ultimately benign.
- A skill with executable binaries may be reported as `unsafe`.
- A clean result still does not mean the skill is fully trustworthy; it only means no suspicious static patterns were found in scanned text files.

## Skill Metadata

This repository is also a Codex skill package:

- Skill name: `skill-safety-review`
- Trigger intent: review or vet a downloaded local skill before trusting it
- Main skill instructions: [`SKILL.md`](./SKILL.md)
- UI metadata: [`agents/openai.yaml`](./agents/openai.yaml)

## Local Validation

To validate the skill structure itself, run the `skill-creator` validator:

```bash
python /path/to/skill-creator/scripts/quick_validate.py /path/to/skill-safety-review
```

To test the scanner, run it against a known fixture or another local skill folder.

## Limitations

- v1 is local-only and static-only
- The scanner is heuristic-based, not a sandbox or malware engine
- Large or non-text files may be surfaced as opaque instead of deeply analyzed
- Safety judgments still require human review for ambiguous cases

## 中文说明

`skill-safety-review` 是一个给 Codex 用的技能，用来在你启用、安装或信任一个新下载的本地 skill 之前，先做一轮静态安全审查。它的设计原则是“保守优先”：

- 不执行被审查 skill 的任何脚本
- 不补抓网络上的额外上下文
- 只基于本地静态证据给出结论
- 输出 `appears-safe`、`needs-manual-review` 或 `unsafe`

## 这个项目解决什么问题

第三方 skill 不只是几段说明文字。一个下载下来的 skill 目录里，可能包含脚本、隐藏文件、压缩包、二进制文件，甚至带有诱导代理执行危险操作的提示内容。这个项目把“下载后先审一遍”变成一个可重复的流程，降低直接信任陌生 skill 的风险。

## 它会做什么

- 审查一个本地解压后的 skill 目录
- 扫描脚本文件和文本内容中的风险模式
- 标记隐藏文件、软链接、压缩包、可疑二进制和其他不透明文件
- 检查 `SKILL.md` 里的提示词级别风险
- 输出结构化结果，支持 `json` 和 `markdown`
- 把最终是否信任的决定留给审查者

## 它不会做什么

- 不会执行被审查 skill 的脚本
- 不会自动安装、删除、隔离被审查 skill
- v1 不会抓 Git 历史、仓库元数据或远程 URL
- 不会承诺“绝对安全”，只会报告静态证据

## 结论模型

| 结论 | 含义 |
| --- | --- |
| `appears-safe` | 在已扫描的文本文件中没有发现可疑模式 |
| `needs-manual-review` | 存在模糊风险、不透明文件或结构异常，需要人工判断 |
| `unsafe` | 发现了明显的危险执行、出网、持久化或绕过安全约束的迹象 |

## 当前会检查哪些风险

当前扫描器会重点关注：

- 命令执行或子进程能力，例如 `subprocess`、`os.system`、`Start-Process`、`bash -c`
- 出网或下载行为，例如 `requests`、`urllib`、`socket`、`curl`、`wget`
- 动态执行行为，例如 `eval`、`exec`、`compile`、`importlib`、base64 解码载荷
- 持久化目标，例如 shell profile、启动目录、其他 skill 目录
- 隐藏文件、软链接、可疑可执行文件和压缩包
- `SKILL.md` 中绕过防护、索取秘密、跳过确认、破坏性命令等提示级风险
- 过于宽泛、可能导致隐式触发不安全的 skill 描述

## 仓库结构

```text
skill-safety-review/
├── README.md
├── SKILL.md
├── agents/
│   └── openai.yaml
├── references/
│   └── risk-rubric.md
└── scripts/
    └── audit_skill.py
```

## 运行要求

- Python 3.10 或更高版本
- 不依赖第三方 Python 包
- 需要一个本地解压后的 skill 目录作为审查对象

## 作为 Codex Skill 使用

如果你不只是想手动运行脚本，而是想让 Codex 把它当成一个可复用的 skill 来调用，可以把 `skill-safety-review` 目录放到 Codex 的技能目录里。

常见路径示例：

```text
~/.codex/skills/skill-safety-review
```

放好之后，重启 Codex，让新的 skill metadata 被加载。

## 快速开始

### 1. 审查一个本地 skill 目录

```bash
python scripts/audit_skill.py /path/to/downloaded-skill
```

如果你想看更适合直接阅读或贴给别人的报告：

```bash
python scripts/audit_skill.py /path/to/downloaded-skill --format markdown
```

### 2. 理解输出字段

扫描器会返回这些字段：

- `target_path`
- `verdict`
- `risk_level`
- `key_findings`
- `findings`
- `opaque_files`
- `notes`
- `inventory`

### 3. 参考判定规则

如果结果不够明确，可以查看 [`references/risk-rubric.md`](./references/risk-rubric.md) 来辅助判断，再决定是否继续信任这个 skill。

## 推荐使用流程

1. 先把 skill 下载或解压到本地目录。
2. 运行 `scripts/audit_skill.py`。
3. 优先阅读最高严重级别的发现。
4. 回到对应文件上下文做人工复核。
5. 再决定是信任、继续深挖，还是直接拒绝使用。

## 为什么它有时会偏保守

这个项目故意偏向“宁可多看一眼，也不要静默放过”。

- 带有二进制文件或压缩包的 skill，哪怕最终是无害的，也可能被标成 `needs-manual-review`
- 带有可执行二进制文件的 skill，通常会被标成 `unsafe`
- 即便结果是 `appears-safe`，也不代表完全可信，只代表在已扫描的文本文件里没有发现可疑静态模式

## 作为 Codex Skill 的元数据

这个仓库本身也是一个 Codex skill 包：

- Skill 名称：`skill-safety-review`
- 触发意图：在信任一个新下载的本地 skill 之前先做审查
- 核心说明文件：[`SKILL.md`](./SKILL.md)
- UI 元数据：[`agents/openai.yaml`](./agents/openai.yaml)

## 本地验证

如果你要验证 skill 包结构本身，可以运行 `skill-creator` 提供的校验脚本：

```bash
python /path/to/skill-creator/scripts/quick_validate.py /path/to/skill-safety-review
```

如果你要验证扫描器行为，可以拿一个测试样例目录或者另一个本地 skill 目录来跑。

## 当前限制

- v1 只做本地、静态审查
- 它是启发式扫描器，不是沙箱，也不是杀毒引擎
- 大文件或非文本文件会被标记为 opaque，而不是深度解析
- 模糊场景仍然需要人工判断
