#!/usr/bin/env bash

set -u
set -o pipefail

TIMESTAMP="$(date +"%Y%m%d-%H%M%S")"
TARGET_PATH="${1:-.}"

usage() {
  cat <<'EOF'
Usage: audit-git-security.sh [path]

Audit the Git repository containing path.
If path is omitted, the current directory is used.
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "$#" -gt 1 ]]; then
  usage
  exit 2
fi

if [[ ! -d "$TARGET_PATH" ]]; then
  echo "ERRORE: path non trovato o non è una cartella: $TARGET_PATH"
  exit 1
fi

cd "$TARGET_PATH" || exit 1

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "ERRORE: il path indicato non è dentro un repository Git: $TARGET_PATH"
  exit 1
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT" || exit 1

REPORT_DIR="audit-results/security-audit-${TIMESTAMP}"
mkdir -p "$REPORT_DIR"

SUMMARY="$REPORT_DIR/REPORT.md"

echo "# Git Security Audit Report" > "$SUMMARY"
echo "" >> "$SUMMARY"
echo "Generated at: ${TIMESTAMP}" >> "$SUMMARY"
echo "" >> "$SUMMARY"

echo "Repository: $REPO_ROOT"
echo "Report dir: $REPORT_DIR"
echo ""

echo "## Repository info" >> "$SUMMARY"
{
  echo '```text'
  git remote -v || true
  echo ""
  git status --short || true
  echo ""
  git log --oneline -n 20 || true
  echo '```'
} >> "$SUMMARY"
echo "" >> "$SUMMARY"

run_section() {
  local title="$1"
  local outfile="$2"
  shift 2

  echo "==> $title"
  echo "## $title" >> "$SUMMARY"
  echo "" >> "$SUMMARY"

  {
    echo "Command:"
    printf '%q ' "$@"
    echo
    echo
    "$@"
  } > "$outfile" 2>&1

  local exit_code=$?

  echo "- Output: \`$outfile\`" >> "$SUMMARY"
  echo "- Exit code: \`$exit_code\`" >> "$SUMMARY"
  echo "" >> "$SUMMARY"

  return 0
}

scan_history_pattern() {
  local name="$1"
  local pattern="$2"
  local outfile="$REPORT_DIR/history-${name}.txt"
  local match_count

  echo "==> Git history grep: $name"

  {
    echo "Pattern name: $name"
    echo "Regex: $pattern"
    echo ""
    echo "Matches are redacted. Format: commit:path:line:<redacted>"
    echo ""

    git rev-list --all | while read -r rev; do
      git grep -n -I -E "$pattern" "$rev" -- . 2>/dev/null \
        | sed -E 's/^([^:]+:[^:]+:[0-9]+):.*$/\1:<redacted>/'
    done | sort -u
  } > "$outfile" 2>&1

  match_count="$(grep -cE '^[0-9a-f]{40}:[^:]+:[0-9]+:<redacted>$' "$outfile" 2>/dev/null || true)"
  match_count="${match_count:-0}"

  echo "## Git history grep: $name" >> "$SUMMARY"
  echo "- Output: \`$outfile\`" >> "$SUMMARY"
  echo "- Matches: \`${match_count}\`" >> "$SUMMARY"
  echo "" >> "$SUMMARY"
}

scan_current_pattern() {
  local name="$1"
  local pattern="$2"
  local outfile="$REPORT_DIR/current-${name}.txt"
  local match_count

  echo "==> Current tree grep: $name"

  {
    echo "Pattern name: $name"
    echo "Regex: $pattern"
    echo ""
    echo "Matches are redacted. Format: file:line:<redacted>"
    echo ""

    grep -RInIE "$pattern" . \
      --exclude-dir=.git \
      --exclude-dir=.venv \
      --exclude-dir=node_modules \
      --exclude-dir=vendor \
      --exclude-dir=audit-results \
      --exclude-dir=.pytest_cache \
      --exclude-dir=benchmark/results \
      2>/dev/null \
      | sed -E 's/^([^:]+:[0-9]+):.*$/\1:<redacted>/' \
      | sort -u
  } > "$outfile" 2>&1

  match_count="$(grep -cE '^\.?/?.+:[0-9]+:<redacted>$' "$outfile" 2>/dev/null || true)"
  match_count="${match_count:-0}"

  echo "## Current tree grep: $name" >> "$SUMMARY"
  echo "- Output: \`$outfile\`" >> "$SUMMARY"
  echo "- Matches: \`${match_count}\`" >> "$SUMMARY"
  echo "" >> "$SUMMARY"
}

scan_current_runtime_pattern() {
  local name="$1"
  local pattern="$2"
  local outfile="$REPORT_DIR/current-runtime-${name}.txt"
  local match_count

  echo "==> Current runtime tree grep: $name"

  {
    echo "Pattern name: $name"
    echo "Regex: $pattern"
    echo ""
    echo "Scope: runtime-oriented source files only (excludes docs/tests/spec fixtures)"
    echo "Matches are redacted. Format: file:line:<redacted>"
    echo ""

    grep -RInIE "$pattern" . \
      --exclude-dir=.git \
      --exclude-dir=.venv \
      --exclude-dir=node_modules \
      --exclude-dir=vendor \
      --exclude-dir=audit-results \
      --exclude-dir=.pytest_cache \
      --exclude-dir=benchmark/results \
      --exclude-dir=doc \
      --exclude-dir=tests \
      --exclude-dir=api/tests \
      --exclude='README.md' \
      --exclude='openapi.yaml' \
      --exclude='FEATURING-FOR-PROD.md' \
        --exclude='benchmark.py' \
      2>/dev/null \
      | sed -E 's/^([^:]+:[0-9]+):.*$/\1:<redacted>/' \
      | sort -u
  } > "$outfile" 2>&1

  match_count="$(grep -cE '^\.?/?.+:[0-9]+:<redacted>$' "$outfile" 2>/dev/null || true)"
  match_count="${match_count:-0}"

  echo "## Current runtime tree grep: $name" >> "$SUMMARY"
  echo "- Output: \`$outfile\`" >> "$SUMMARY"
  echo "- Matches: \`${match_count}\`" >> "$SUMMARY"
  echo "" >> "$SUMMARY"
}

echo "==> Checking installed tools"

{
  echo "## Tool availability"
  echo ""

  for tool in git gitleaks trufflehog; do
    if command -v "$tool" >/dev/null 2>&1; then
      echo "- $tool: OK — \`$(command -v "$tool")\`"
    else
      echo "- $tool: MISSING"
    fi
  done

  echo ""
} >> "$SUMMARY"

if ! command -v gitleaks >/dev/null 2>&1; then
  echo "ATTENZIONE: gitleaks non trovato."
  echo "Su macOS puoi installarlo con: brew install gitleaks"
fi

if ! command -v trufflehog >/dev/null 2>&1; then
  echo "ATTENZIONE: trufflehog non trovato."
  echo "Su macOS puoi installarlo con: brew install trufflehog"
fi

echo ""

run_section \
  "Suspicious files in Git history" \
  "$REPORT_DIR/suspicious-files-history.txt" \
  bash -c "git rev-list --objects --all | grep -Ei '(^|/)(\\.env($|\\.)|.*\\.(pem|key|p12|pfx|jks|keystore|sqlite|db|sql|dump|bak|backup|kdbx)$|.*(secret|credential|credentials|password|passwd).*)' || true"

run_section \
  "Sensitive file commits" \
  "$REPORT_DIR/sensitive-file-commits.txt" \
  bash -c "git log --all --name-only --pretty=format:'commit %H %ad %an' --date=iso -- .env '.env.*' '*.pem' '*.key' '*.p12' '*.pfx' '*.jks' '*.keystore' '*.sqlite' '*.db' '*.sql' '*.dump' '*.bak' '*backup*' '*secret*' '*credential*' '*password*' '*passwd*' 2>/dev/null || true"

run_section \
  "Current suspicious files" \
  "$REPORT_DIR/suspicious-files-current.txt" \
  bash -c "find . -path './.git' -prune -o -path './.venv' -prune -o -path './node_modules' -prune -o -path './vendor' -prune -o -path './audit-results' -prune -o -path './.pytest_cache' -prune -o -path './benchmark/results' -prune -o -type f | grep -Ei '(^|/)(\\.env($|\\.)|.*\\.(pem|key|p12|pfx|jks|keystore|sqlite|db|sql|dump|bak|backup|kdbx)$|.*(secret|credential|credentials|password|passwd).*)' || true"

run_section \
  "Git ignored safety check" \
  "$REPORT_DIR/gitignore-check.txt" \
  bash -c "echo 'Checking .gitignore for common sensitive patterns'; echo; grep -nE '(^|/)(\\.env|\\.env\\.|audit-results|\\.pem|\\.key|\\.sqlite|\\.db|\\.sql|dump|backup)' .gitignore 2>/dev/null || true; echo; echo 'git check-ignore results:'; git check-ignore -v .env .env.local .env.production audit-results 2>/dev/null || true"

if command -v gitleaks >/dev/null 2>&1; then
  echo "==> Running Gitleaks full history scan"

  GITLEAKS_JSON="$REPORT_DIR/gitleaks-history.json"
  GITLEAKS_LOG="$REPORT_DIR/gitleaks-history.log"

  gitleaks detect \
    --source . \
    --log-opts="--all" \
    --verbose \
    --redact \
    --report-format json \
    --report-path "$GITLEAKS_JSON" \
    > "$GITLEAKS_LOG" 2>&1 || true

  echo "## Gitleaks full history scan" >> "$SUMMARY"
  echo "- JSON: \`$GITLEAKS_JSON\`" >> "$SUMMARY"
  echo "- Log: \`$GITLEAKS_LOG\`" >> "$SUMMARY"
  echo "" >> "$SUMMARY"
else
  echo "==> Skipping Gitleaks: not installed"
fi

if command -v trufflehog >/dev/null 2>&1; then
  echo "==> Running TruffleHog verified scan"

  TRUFFLE_VERIFIED="$REPORT_DIR/trufflehog-verified.jsonl"
  TRUFFLE_VERIFIED_ERR="$REPORT_DIR/trufflehog-verified.err"

  trufflehog git "file://$REPO_ROOT" \
    --only-verified \
    --json \
    > "$TRUFFLE_VERIFIED" 2> "$TRUFFLE_VERIFIED_ERR" || true

  echo "## TruffleHog verified secrets scan" >> "$SUMMARY"
  echo "- JSONL: \`$TRUFFLE_VERIFIED\`" >> "$SUMMARY"
  echo "- STDERR: \`$TRUFFLE_VERIFIED_ERR\`" >> "$SUMMARY"
  echo "- Lines: \`$(wc -l < "$TRUFFLE_VERIFIED" | tr -d ' ')\`" >> "$SUMMARY"
  echo "" >> "$SUMMARY"

  echo "==> Running TruffleHog full scan, including unverified findings"

  TRUFFLE_ALL="$REPORT_DIR/trufflehog-all.jsonl"
  TRUFFLE_ALL_ERR="$REPORT_DIR/trufflehog-all.err"

  trufflehog git "file://$REPO_ROOT" \
    --json \
    > "$TRUFFLE_ALL" 2> "$TRUFFLE_ALL_ERR" || true

  echo "## TruffleHog full scan" >> "$SUMMARY"
  echo "- JSONL: \`$TRUFFLE_ALL\`" >> "$SUMMARY"
  echo "- STDERR: \`$TRUFFLE_ALL_ERR\`" >> "$SUMMARY"
  echo "- Lines: \`$(wc -l < "$TRUFFLE_ALL" | tr -d ' ')\`" >> "$SUMMARY"
  echo "" >> "$SUMMARY"
else
  echo "==> Skipping TruffleHog: not installed"
fi

scan_history_pattern "private-keys" "BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY"
scan_history_pattern "aws-access-keys" "AKIA[0-9A-Z]{16}"
scan_history_pattern "jwt-tokens" "eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}"
scan_history_pattern "urls-with-credentials" "https?://[^/:[:space:]]+:[^/@[:space:]]+@"
scan_history_pattern "database-urls" "(postgresql?|mysql|mariadb|redis|mongodb)://[^[:space:]]+"
scan_history_pattern "generic-secrets" "(secret|password|passwd|pwd|client[_-]?secret|access[_-]?token|refresh[_-]?token|pii[_-]?encryption[_-]?key|pii[_-]?admin[_-]?initial[_-]?key|database[_-]?url|db[_-]?password|api[_-]?secret)[[:space:]]*[:=][[:space:]]*['\\\"\`]?[^[:space:]'\\\"\`]{8,}"
scan_history_pattern "italian-fiscal-codes" "\\b[A-Z]{6}[0-9]{2}[A-Z][0-9]{2}[A-Z][0-9]{3}[A-Z]\\b"
scan_history_pattern "italian-iban" "\\bIT[0-9]{2}[A-Z][0-9A-Z]{22}\\b"
scan_history_pattern "emails" "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"
scan_history_pattern "italian-phones" "(\\+39[[:space:].-]?)?3[0-9]{2}[[:space:].-]?[0-9]{3}[[:space:].-]?[0-9]{4}"

scan_current_pattern "private-keys" "BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY"
scan_current_pattern "aws-access-keys" "AKIA[0-9A-Z]{16}"
scan_current_pattern "jwt-tokens" "eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}"
scan_current_pattern "urls-with-credentials" "https?://[^/:[:space:]]+:[^/@[:space:]]+@"
scan_current_pattern "database-urls" "(postgresql?|mysql|mariadb|redis|mongodb)://[^[:space:]]+"
scan_current_pattern "generic-secrets" "(secret|password|passwd|pwd|client[_-]?secret|access[_-]?token|refresh[_-]?token|pii[_-]?encryption[_-]?key|pii[_-]?admin[_-]?initial[_-]?key|database[_-]?url|db[_-]?password|api[_-]?secret)[[:space:]]*[:=][[:space:]]*['\\\"\`]?[^[:space:]'\\\"\`]{8,}"
scan_current_pattern "italian-fiscal-codes" "\\b[A-Z]{6}[0-9]{2}[A-Z][0-9]{2}[A-Z][0-9]{3}[A-Z]\\b"
scan_current_pattern "italian-iban" "\\bIT[0-9]{2}[A-Z][0-9A-Z]{22}\\b"
scan_current_pattern "emails" "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"
scan_current_pattern "italian-phones" "(\\+39[[:space:].-]?)?3[0-9]{2}[[:space:].-]?[0-9]{3}[[:space:].-]?[0-9]{4}"

scan_current_runtime_pattern "private-keys" "BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY"
scan_current_runtime_pattern "aws-access-keys" "AKIA[0-9A-Z]{16}"
scan_current_runtime_pattern "jwt-tokens" "eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}"
scan_current_runtime_pattern "urls-with-credentials" "https?://[^/:[:space:]]+:[^/@[:space:]]+@"
scan_current_runtime_pattern "database-urls" "(postgresql?|mysql|mariadb|redis|mongodb)://[^[:space:]]+"
scan_current_runtime_pattern "generic-secrets" "(secret|password|passwd|pwd|client[_-]?secret|access[_-]?token|refresh[_-]?token|pii[_-]?encryption[_-]?key|pii[_-]?admin[_-]?initial[_-]?key|database[_-]?url|db[_-]?password|api[_-]?secret)[[:space:]]*[:=][[:space:]]*['\\\"\`]?[^[:space:]'\\\"\`]{8,}"
scan_current_runtime_pattern "italian-fiscal-codes" "\\b[A-Z]{6}[0-9]{2}[A-Z][0-9]{2}[A-Z][0-9]{3}[A-Z]\\b"
scan_current_runtime_pattern "italian-iban" "\\bIT[0-9]{2}[A-Z][0-9A-Z]{22}\\b"
scan_current_runtime_pattern "emails" "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"
scan_current_runtime_pattern "italian-phones" "(\\+39[[:space:].-]?)?3[0-9]{2}[[:space:].-]?[0-9]{3}[[:space:].-]?[0-9]{4}"

echo "## Final notes" >> "$SUMMARY"
echo "" >> "$SUMMARY"
echo "Important:" >> "$SUMMARY"
echo "" >> "$SUMMARY"
echo "- Review every finding manually." >> "$SUMMARY"
echo "- False positives are expected." >> "$SUMMARY"
echo "- If a real secret appears anywhere in Git history, rotate/revoke it immediately." >> "$SUMMARY"
echo "- Do not commit the \`audit-results/\` directory." >> "$SUMMARY"
echo "- If real PII appears in examples/tests, replace it with synthetic data." >> "$SUMMARY"
echo "" >> "$SUMMARY"

echo ""
echo "Audit completed."
echo "Open report:"
echo "  $SUMMARY"
echo ""
echo "Important: do NOT commit audit-results/."
