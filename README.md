# Kiuwan Skill for Claude Code

This is a [Claude Code](https://claude.com/claude-code) **skill** that lets your AI assistant run a real [Kiuwan](https://www.kiuwan.com) analysis on your project and then remediate the results. It drives the **Kiuwan Local Analyzer (KLA)** — the same command-line analyzer you already use — to scan your code, and brings the **security findings** (with CWE and source→sink taint dataflow) back to the assistant so it can explain and fix them in your editor. Think of it as wiring Kiuwan's engine and findings directly into your AI coding workflow: you say "run a Kiuwan scan and fix what it finds," and the assistant analyzes, retrieves the findings, and works through them with you.

Under the hood the skill runs a normal KLA analysis, which **uploads results to your own Kiuwan account** (so they also appear in your Kiuwan dashboards and baselines), then retrieves the **security findings — with their source→sink taint dataflow** — through the analyzer's own threadfix export. The helper needs **no extra tooling** — just `bash`, `awk`, and the Java-based KLA you already have (no Python, jq, curl, or other interpreters), so it runs wherever Claude Code runs. It does not store or transmit your credentials anywhere except through the KLA you already configured.

## Setup (one time)

1. **Install the Kiuwan Local Analyzer** from your Kiuwan account and note its directory (the folder containing `bin/agent.sh`).
2. **Configure your Kiuwan credentials and endpoint** in `KiuwanLocalAnalyzer/conf/agent.properties` — set `username`/`password` (or `apiToken`), and make sure `url` / `rest.services.url` point at your Kiuwan (SaaS or on-prem). This is the same configuration you'd use to run the analyzer manually.
3. **Install the skill** using either method:

   - **Skills CLI** (requires Node.js). Installs into the current project's `.claude/skills/`; add `-g` to install globally into `~/.claude/skills/`:
     ```sh
     npx skills add kiuwan/qaking-skill -a claude-code
     ```
   - **Manual** (clone and copy the skill folder into your global skills directory):
     ```sh
     git clone https://github.com/kiuwan/qaking-skill.git
     cp -r qaking-skill/skills/kiuwan ~/.claude/skills/
     ```
4. **Tell the skill where your analyzer is** — either:
   - export `KIUWAN_HOME` (add it to your shell profile so it persists):
     ```sh
     export KIUWAN_HOME=/path/to/KiuwanLocalAnalyzer
     ```
   - or just run once with `--home` and it will be remembered:
     ```sh
     bash <skill-dir>/kiuwan-scan.sh --home /path/to/KiuwanLocalAnalyzer
     ```
   The location is saved to `~/.config/kiuwan-skill/home`, so you only set it once.

   `<skill-dir>` is wherever the skill was installed — `~/.claude/skills/kiuwan` for a global/manual install, or `.claude/skills/kiuwan` for a project-scoped one.

## Usage

In Claude Code, just ask — for example: *"run a Kiuwan scan on this project and fix the findings."* The assistant will analyze the project, retrieve the security findings, present them grouped by file (severity, rule, `file:line`, CWE, and the source→sink taint dataflow), and help you remediate them. You can also run the analyzer wrapper directly:

```sh
bash <skill-dir>/kiuwan-scan.sh [project-dir] [app-name]
```

`project-dir` defaults to your git top-level (or current directory); `app-name` defaults to the project folder name and is created in Kiuwan automatically if it doesn't exist.
