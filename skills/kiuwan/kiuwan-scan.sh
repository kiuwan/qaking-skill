#!/usr/bin/env bash
#
# kiuwan-scan.sh — run a Kiuwan analysis via the Kiuwan Local Analyzer (KLA) and
# write the findings to local JSON files for an AI assistant to read & remediate.
#
# Dependency-free by design: uses only bash and the KLA's own Java engine.
# No python, no jq, no curl.
#
# Flow:
#   1. analyze the project with the KLA (uploads results to YOUR OWN Kiuwan
#      account) and wait for results               -> summary.json
#   2. retrieve security findings + taint dataflow via the KLA's threadfix
#      export (Java, no extra tools)               -> findings.json
#
# The script writes the JSON files above and prints their location; the
# assistant reads findings.json and presents/remediates the findings (SKILL.md).
#
# Requirements:
#   - A KiuwanLocalAnalyzer install (located via --home, $KIUWAN_HOME, or a
#     remembered path). The KLA mandates a JDK, so Java is always available.
#   - Credentials + endpoint configured in $KIUWAN_HOME/conf/agent.properties
#     (username/password, or apiToken). This script never prints them.
#
# Usage: kiuwan-scan.sh [--home <KLA dir>] [project-dir] [app-name]
#
set -uo pipefail

err() { printf 'kiuwan-scan: %s\n' "$1" >&2; }

# Directory this script lives in — used to find the bundled report.awk.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

# Capture any KIUWAN_HOME from the environment before we reassign the variable.
ENV_HOME="${KIUWAN_HOME:-}"

# ── Parse args: optional --home <path>, then [project-dir] [app-name] ─────────
HOME_OVERRIDE=""
if [ "${1:-}" = "--home" ]; then HOME_OVERRIDE="${2:-}"; shift 2 || true; fi
SRC="${1:-}"
APP_ARG="${2:-}"

# Where the KLA location is remembered between runs (portable XDG path).
CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/kiuwan-skill"
CONFIG_FILE="$CONFIG_DIR/home"

is_kla()   { [ -n "${1:-}" ] && [ -f "$1/bin/agent.sh" ] && [ -f "$1/conf/agent.properties" ]; }
remember() { mkdir -p "$CONFIG_DIR" 2>/dev/null && printf '%s\n' "$1" > "$CONFIG_FILE"; }

# ── Locate the KLA: --home  →  $KIUWAN_HOME  →  remembered config ─────────────
# All customer-supplied; nothing about the location is assumed or auto-discovered.
KIUWAN_HOME=""
if [ -n "$HOME_OVERRIDE" ]; then
  is_kla "$HOME_OVERRIDE" || { err "no Kiuwan Local Analyzer at --home '$HOME_OVERRIDE' (expected bin/agent.sh and conf/agent.properties there)"; exit 1; }
  KIUWAN_HOME="$HOME_OVERRIDE"; remember "$KIUWAN_HOME"
elif is_kla "$ENV_HOME"; then
  KIUWAN_HOME="$ENV_HOME"; remember "$KIUWAN_HOME"
elif [ -f "$CONFIG_FILE" ] && is_kla "$(cat "$CONFIG_FILE" 2>/dev/null)"; then
  KIUWAN_HOME="$(cat "$CONFIG_FILE")"
else
  err "Don't know where your Kiuwan Local Analyzer is."
  err "Tell me once and I'll remember it:"
  err "    kiuwan-scan.sh --home /path/to/KiuwanLocalAnalyzer [project-dir] [app-name]"
  err "(or set the KIUWAN_HOME environment variable). Saved to $CONFIG_FILE for next time."
  exit 1
fi

AGENT="$KIUWAN_HOME/bin/agent.sh"
PROPS="$KIUWAN_HOME/conf/agent.properties"

# ── Resolve project dir + app name ───────────────────────────────────────────
if [ -z "$SRC" ]; then
  SRC="$(git -C "$(pwd)" rev-parse --show-toplevel 2>/dev/null || pwd)"
fi
SRC="$(cd "$SRC" 2>/dev/null && pwd)" || { err "project dir not found: ${1:-}"; exit 1; }

if [ -n "$APP_ARG" ]; then APP="$APP_ARG"; else APP="$(basename "$SRC")"; fi
# Kiuwan application names allow a limited charset; sanitize.
APP="$(printf '%s' "$APP" | tr -c 'A-Za-z0-9._-' '_')"

# ── Read connection settings from agent.properties (never printed) ───────────
get_prop() { grep -E "^$1=" "$PROPS" 2>/dev/null | head -1 | sed -E "s/^[^=]*=//"; }

KW_USER="$(get_prop username)"
KW_TOKEN="$(get_prop apiToken)"

if [ -z "$KW_USER" ] && [ -z "$KW_TOKEN" ]; then
  err "No credentials in $PROPS — set username/password (or apiToken) first."
  exit 1
fi

# ── Output dir (persists after exit so the assistant can read the files) ──────
OUT="${TMPDIR:-/tmp}/kiuwan-scan/$APP"
rm -rf "$OUT" 2>/dev/null; mkdir -p "$OUT"
LOG="$OUT/agent.log"

# ── 1. Analyze + upload + wait for results ───────────────────────────────────
echo "kiuwan: analyzing '$APP' ($SRC)"
echo "kiuwan: uploading to your Kiuwan account and waiting for results (this can take a few minutes)..."
"$AGENT" -n "$APP" -s "$SRC" -c -wr -o "$OUT/summary.json" > "$LOG" 2>&1
RC=$?
# Success is judged by output produced, not exit code: the architecture analysis
# step can throw on some engine builds while the code analysis still completes.
if [ ! -s "$OUT/summary.json" ]; then
  err "analysis did not complete — last lines of the analyzer log:"
  grep -viE '^\s*$|^   #|www\.kiuwan\.com' "$LOG" | tail -20 >&2
  exit "${RC:-1}"
fi

# ── 2. Retrieve security findings + taint dataflow (KLA threadfix; no deps) ───
"$AGENT" -rd -n "$APP" -f threadfix -o "$OUT/findings.json" >> "$LOG" 2>&1 \
  || err "note: threadfix retrieval failed (security dataflow may be unavailable)"

# ── 3. Format the security findings with awk and print to stdout ─────────────
# findings.json (threadfix) is the data source. report.awk turns it into a
# readable report so the assistant presents it in one step; findings.json stays
# on disk for the full taint dataflow of any finding.
echo
if [ -s "$OUT/findings.json" ]; then
  URL="$(grep -oE '"analysisURL":"[^"]*"' "$OUT/summary.json" | head -1 | sed -E 's/.*:"//; s/"$//')"
  awk -v url="$URL" -f "$SCRIPT_DIR/report.awk" "$OUT/findings.json"
else
  echo "kiuwan: analysis finished but no security findings were retrieved — see $LOG"
fi
echo
echo "kiuwan: result files in $OUT (findings.json has the full security taint dataflow)."
