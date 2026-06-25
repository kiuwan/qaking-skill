---
name: kiuwan
description: This skill should be used when the user asks to "run a Kiuwan scan", "run a Kiuwan analysis", "analyze with Kiuwan", "scan my project with Kiuwan", "check my code with Kiuwan", "fix my Kiuwan findings", "remediate Kiuwan defects", or otherwise wants to find and fix code quality or security issues using Kiuwan. Runs a full Kiuwan analysis through the Kiuwan Local Analyzer and brings the findings back for AI remediation.
version: 1.0.0
---

# Kiuwan Analysis & Remediation

Run a Kiuwan static analysis on the user's project through the **Kiuwan Local Analyzer (KLA)**, then use the findings to remediate code quality and security defects.

## How it works

A Kiuwan analysis runs the engine locally (inside the KLA) and uploads the results to the user's **own** Kiuwan account. The bundled helper then retrieves the **security findings** (with taint dataflow) and **prints a formatted report to stdout** — a severity summary plus the findings grouped by file, each with its rule, CWE, sink line, and source→sink taint flow. You present that printed report; you do **not** need to parse JSON for the normal flow. It uses only **bash + `awk`** and the KLA's own Java engine — no python, jq, or curl — so it works wherever Claude Code runs.

The raw JSON also stays on disk:

- `findings.json` — the security findings with full taint dataflow (threadfix export). Read it only for a deeper drill-down on a specific finding.
- `summary.json` — analysis metrics and the Kiuwan dashboard URL.

## Prerequisites (one-time, set up by the user)

- The user has a **Kiuwan Local Analyzer (KLA)** installed, with their Kiuwan credentials + endpoint configured in its `conf/agent.properties` (username/password, or an apiToken).
- The skill locates the KLA in this order: a path it has remembered from a previous run → the `KIUWAN_HOME` environment variable → a `--home <path>` you pass. Once a valid path is given (env var or `--home`), it is remembered for next time.

## Run the analysis

Determine the project to analyze (default to the git top-level, otherwise the current directory), then run the bundled `kiuwan-scan.sh`. It lives in **this skill's own directory** (the same folder as this SKILL.md) — reference it there, not at a fixed path, since the install location varies (`~/.claude/skills/kiuwan/` for a global/manual install, `.claude/skills/kiuwan/` for a project-scoped one):

```
bash "<skill-dir>/kiuwan-scan.sh" [project-dir] [app-name]
```

- `[project-dir]` — the directory to analyze. Omit to use the git top-level / current dir.
- `[app-name]` — optional Kiuwan application name. Omit to use the project folder name (the app is auto-created in Kiuwan if it doesn't exist).

**If the helper says it doesn't know where the Kiuwan Local Analyzer is:** do **not** search the filesystem. Ask the user for the path to their `KiuwanLocalAnalyzer` directory, then run once with `--home` (the path is remembered afterward):

```
bash "<skill-dir>/kiuwan-scan.sh" --home /path/to/KiuwanLocalAnalyzer [project-dir] [app-name]
```

The analysis uploads to the user's Kiuwan account and waits for results, so it may take a few minutes. The analyzer's own output is suppressed; when it finishes, the helper **prints the formatted security report** (a severity summary, then findings grouped by file with rule, CWE, sink line, and the source→sink flow). That printed text is your source — present it as described below.

## Raw findings data (`findings.json`)

For a deeper drill-down on a specific finding, read `findings.json`. Shape:

`{ "findings": [ { "summary", "severity", "mappings": [ { "mappingType": "CWE" | "TOOL_VENDOR", "value" } ], "staticDetails": { "dataFlow": [ { "file", "lineNumber", "text" } ] } } ] }`

- `severity` — the finding severity (Critical / High / Medium / Low).
- `summary` — the issue name (e.g. "SQL Injection").
- `mappings` — the `CWE` value is the CWE id; the `TOOL_VENDOR` value is the Kiuwan `ruleCode`.
- `staticDetails.dataFlow` — the taint path: the **first** step is the source and the **last** is the **sink** (each step has `file`, `lineNumber`, and the code `text`).

## Present the findings FIRST — required, before any remediation

As soon as the analysis returns, your **first** response to the user must be the findings, formatted clearly. **Do not read source files, plan fixes, or edit any code until you have presented the findings to the user.** Showing the defects is always step one — even when the user asked you to "fix" them.

Format the findings like this:

1. **Severity summary** — a headline line with the total number of security findings and a breakdown by severity (Critical / High / Medium / Low), plus the Kiuwan dashboard URL.
2. **One Markdown table per file**, grouped by the **sink file** (use the file path as a heading). Each table has the columns **`Sev | Rule | Line | Issue`**:
   - **Sev** — a colored dot by severity: 🔴 Critical · 🟠 High · 🟡 Medium · 🔵 Low.
   - **Rule** — the finding `summary` with its CWE, e.g. `SQL Injection (CWE-89)`.
   - **Line** — the sink line (the last `dataFlow` step's `lineNumber`).
   - **Issue** — a short description: the taint path source→sink (e.g. `userId → executeQuery("...WHERE id=" + userId)`).
3. Order files and rows so the **highest-severity items come first**.
4. If there are very many findings, lead with the Critical/High tables and offer the rest, rather than dumping every row — but always show the summary.
5. If no findings are returned, say the project has no security findings and stop.

## Then agree the scope

After presenting, ask how the user wants to proceed before changing code — for example: fix everything, only the security / high-priority issues, or specific files. If they already said what to fix (e.g. "fix all of them"), restate the scope and proceed. For a large number of defects, confirm scope rather than silently fixing all of them.

## Remediate (only after presenting + agreeing scope)

- Work through the agreed findings, highest-priority first.
- For each, open the cited `file:line`, explain the issue (the rule `summary` and CWE, with the source→sink dataflow), and propose or apply a concrete fix.
- For security taint flows, follow the source→sink path to fix at the right place (e.g. parameterize the query at the sink, validate at the source).
- After fixes, offer to re-run the skill to confirm the findings are resolved.

## Secret handling (important)

- Credentials live **only** in the user's `agent.properties`. Never print, echo, or commit them.
- The helper reads them from there and never emits them; do not work around that.
