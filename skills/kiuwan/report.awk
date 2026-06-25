# report.awk — format the Kiuwan threadfix export (findings.json) into a
# readable security report. Pure POSIX awk: no python, jq, or curl.
#
# Input is a single-line JSON document: { ... "findings":[ {finding}, ... ] }.
# Each finding has "severity", "summary", "mappings":[{"mappingType","value"}],
# and "staticDetails":{"dataFlow":[{"file","lineNumber","text"},...]}. The LAST
# dataFlow step is the SINK; findings are grouped by their sink file.
#
# Findings are separated by brace-matching (not a naive "},{" split), so the
# nested dataFlow / mappings arrays and quoted text don't break extraction.
# Pass the dashboard URL with -v url="...".

function strval(s, key, from,   pat, p, v) {
  pat = "\"" key "\":\""
  p = index(substr(s, from), pat)
  if (!p) return ""
  v = substr(s, from + p - 1 + length(pat))
  if (match(v, /"/)) v = substr(v, 1, RSTART - 1)
  return v
}
function numval(s, key, from,   pat, p, v) {
  pat = "\"" key "\":"
  p = index(substr(s, from), pat)
  if (!p) return ""
  v = substr(s, from + p - 1 + length(pat))
  if (match(v, /[,}\]]/)) v = substr(v, 1, RSTART - 1)
  return v
}
function mapval(f, mtype,   p) {
  p = index(f, "\"mappingType\":\"" mtype "\"")
  if (!p) return ""
  return strval(f, "value", p)
}
function basename(p,   a) { a = p; sub(/.*\//, "", a); return a }

BEGIN { rank["Critical"]=0; rank["High"]=1; rank["Medium"]=2; rank["Low"]=3; rank["Info"]=4 }

{ json = json $0 }

END {
  fi = index(json, "\"findings\":[")
  if (!fi) { print "Kiuwan: no security findings."; exit }
  arr = substr(json, fi + length("\"findings\":["))
  n = length(arr); depth = 0; instr = 0; esc = 0; start = 0
  for (i = 1; i <= n; i++) {
    ch = substr(arr, i, 1)
    if (instr) {
      if (esc) esc = 0
      else if (ch == "\\") esc = 1
      else if (ch == "\"") instr = 0
      continue
    }
    if (ch == "\"") { instr = 1; continue }
    if (ch == "{") { if (depth == 0) start = i; depth++ }
    else if (ch == "}") { depth--; if (depth == 0) handle(substr(arr, start, i - start + 1)) }
    else if (ch == "]" && depth == 0) break
  }
  emit()
}

function handle(f,   sev, sum, cwe, rc, dfp, df, ff, ll, tt, base, q, pos, sinkfile, sinkline, flow, r) {
  sev = strval(f, "severity", 1)
  sum = strval(f, "summary", 1)
  cwe = mapval(f, "CWE")
  rc  = mapval(f, "TOOL_VENDOR")
  dfp = index(f, "\"dataFlow\":[")
  flow = ""; sinkfile = ""; sinkline = ""
  if (dfp) {
    df = substr(f, dfp)
    pos = 1
    while ((q = index(substr(df, pos), "\"file\":\"")) > 0) {
      base = pos + q - 1
      ff = strval(df, "file", base)
      ll = numval(df, "lineNumber", base)
      tt = strval(df, "text", base)
      gsub(/\\"/, "\"", tt); gsub(/\\n/, " ", tt); gsub(/\\t/, " ", tt); gsub(/\\r/, "", tt)
      flow = flow (flow == "" ? "" : "  ->  ") basename(ff) ":" ll "  " tt
      sinkfile = ff; sinkline = ll
      pos = base + length("\"file\":\"")
    }
  }
  if (sinkfile == "") sinkfile = "(no location)"
  total++; bysev[sev]++
  if (!(sinkfile in seen)) { seen[sinkfile] = 1; files[++nf] = sinkfile }
  r = rank[sev] + 0
  rows[sinkfile, r, ++cnt[sinkfile, r]] = \
    sprintf("    [%s] %s (CWE-%s)  rule=%s | sink line %s\n        flow: %s", sev, sum, cwe, rc, sinkline, flow)
}

function emit(   i, j, t, r, m, c, po) {
  if (total == 0) { print "Kiuwan: no security findings."; exit }
  printf "KIUWAN SECURITY FINDINGS - %d finding(s) in %d file(s)\n", total, nf
  printf "  By severity: "
  split("Critical,High,Medium,Low,Info", po, ",")
  for (i = 1; i <= 5; i++) if (bysev[po[i]]) printf "%s: %d  ", po[i], bysev[po[i]]
  printf "\n\nDETAIL (by sink file, highest severity first):\n"
  for (i = 1; i <= nf; i++) for (j = i + 1; j <= nf; j++) if (files[j] < files[i]) { t = files[i]; files[i] = files[j]; files[j] = t }
  for (i = 1; i <= nf; i++) {
    c = files[i]; printf "\n  %s\n", c
    for (r = 0; r <= 4; r++) { m = cnt[c, r]; for (t = 1; t <= m; t++) print rows[c, r, t] }
  }
  if (url != "") printf "\nKiuwan dashboard: %s\n", url
}
