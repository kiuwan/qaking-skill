# Kiuwan Skill for AI Coding Assistants

A skill that lets your AI coding assistant run a real [Kiuwan](https://www.kiuwan.com) security analysis on your project and remediate the results. It drives the **Kiuwan Local Analyzer (KLA)** to scan your code and brings the security findings — with CWE and source→sink taint dataflow — back to the assistant so it can explain and fix them in your editor. You say _"run a Kiuwan scan and fix what it finds,"_ and the assistant analyzes, retrieves the findings, and works through them with you.

## How it works

The skill runs a normal KLA analysis, which **uploads results to your own Kiuwan account** (so they also appear in your Kiuwan dashboards and baselines), then brings the security findings — with their source→sink taint dataflow — back to your assistant to explain and fix. It needs nothing installed beyond the KLA you already have.

## Installation

Install the skill into your assistant's skills directory using **either** method. It works with Claude Code, Cursor, Codex, and other AI coding assistants.

### Option A — Skills CLI

Cross-platform; requires Node.js. Pick your assistant with `-a` — the CLI supports Claude Code, Cursor, Codex, and many others, and you can pass several at once. Add `-g` to install globally, or omit it to install into the current project:

```sh
npx skills add kiuwan/qaking-skill -a claude-code          # or -a cursor / -a codex
npx skills add kiuwan/qaking-skill -a claude-code -a cursor -a codex   # several at once
```

### Option B — Manual (clone and copy)

Clone the repository and copy the `skills/kiuwan` folder into your assistant's global skills directory:

| Assistant | macOS / Linux | Windows |
| --- | --- | --- |
| Claude Code | `~/.claude/skills/` | `%USERPROFILE%\.claude\skills\` |
| Cursor | `~/.cursor/skills/` | `%USERPROFILE%\.cursor\skills\` |
| Codex | `~/.codex/skills/` | `%USERPROFILE%\.codex\skills\` |

Run the commands for your shell. The examples target Claude Code — swap `.claude` for `.cursor` or `.codex` for those assistants:

**macOS / Linux / Git Bash**

```sh
git clone https://github.com/kiuwan/qaking-skill.git
mkdir -p ~/.claude/skills && cp -r qaking-skill/skills/kiuwan ~/.claude/skills/
```

**Windows cmd**

```bat
git clone https://github.com/kiuwan/qaking-skill.git
xcopy /E /I /Y qaking-skill\skills\kiuwan "%USERPROFILE%\.claude\skills\kiuwan"
```

This creates a `kiuwan/` folder (containing `SKILL.md`, `kiuwan-scan.sh`, and `report.awk`) inside your skills directory.

## Configuration

Point the skill at your analyzer by setting the `KIUWAN_HOME` environment variable to the KLA directory.

**macOS / Linux / Git Bash** — add to your shell profile (e.g. `~/.bashrc` or `~/.zshrc`) so it persists:

```sh
export KIUWAN_HOME=/path/to/KiuwanLocalAnalyzer
```

**Windows** — sets it for new shells, including Git Bash:

```bat
setx KIUWAN_HOME "C:\path\to\KiuwanLocalAnalyzer"
```

Restart your assistant afterward so it picks up the variable.

## Usage

In your AI assistant, just ask — for example:

> Run a Kiuwan scan on this project

The assistant analyzes the project, retrieves the security findings, presents them grouped by file (severity, rule, `file:line`, CWE, and the source→sink taint dataflow), and helps you remediate them.
