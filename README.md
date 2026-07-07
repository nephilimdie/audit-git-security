# audit-git-security

`audit-git-security.sh` is a Bash command that audits a Git repository for secrets, sensitive files, and personal data indicators in both the current working tree and the full Git history.

It combines lightweight built-in checks with optional scans from [Gitleaks](https://github.com/gitleaks/gitleaks) and [TruffleHog](https://github.com/trufflesecurity/trufflehog), then writes all findings to a timestamped report directory.

## What it checks

The command looks for common security issues that are easy to accidentally commit:

- Suspicious files in Git history, such as `.env`, private keys, database dumps, backups, keystores, credential files, and password-related filenames.
- Suspicious files in the current working tree, with common dependency and generated folders excluded.
- Sensitive files referenced by commits across the full history.
- Missing `.gitignore` coverage for common sensitive files and generated audit reports.
- Secret-like values in Git history and the current working tree.
- Runtime-only secret-like values, excluding documentation and test-oriented folders.
- Optional full-history Gitleaks findings.
- Optional verified and unverified TruffleHog findings.
- Italian PII-like indicators, including fiscal codes, IBANs, mobile phone numbers, and email addresses.

All grep-based match output is redacted. The generated files show where a match was found, but not the matched secret value.

## Requirements

Required:

- Bash
- Git
- A Unix-like shell environment with standard tools such as `grep`, `sed`, `find`, `sort`, `wc`, and `date`

Optional but recommended:

- `gitleaks`
- `trufflehog`

On macOS, you can install the optional scanners with Homebrew:

```bash
brew install gitleaks
brew install trufflehog
```

Check what is available on your machine:

```bash
command -v git
command -v gitleaks
command -v trufflehog
```

The command still runs when `gitleaks` or `trufflehog` are missing. Missing optional tools are reported in the generated summary, and their scan sections are skipped.

## Installation

Clone or copy this repository, then make sure the script is executable:

```bash
chmod +x audit-git-security.sh
```

You can run it directly from this project:

```bash
./audit-git-security.sh
```

Or pass the directory you want to audit:

```bash
./audit-git-security.sh /path/to/your/repository
```

Or copy it somewhere in your `PATH`, for example:

```bash
mkdir -p "$HOME/bin"
cp audit-git-security.sh "$HOME/bin/audit-git-security"
chmod +x "$HOME/bin/audit-git-security"
```

Then run it as:

```bash
audit-git-security
```

## Basic usage

Run the command with no arguments to audit the repository containing the current directory:

```bash
cd /path/to/your/repository
/path/to/audit-git-security.sh
```

Or pass a directory explicitly:

```bash
/path/to/audit-git-security.sh /path/to/your/repository
```

Usage:

```text
audit-git-security.sh [path]
```

If `path` is omitted, the current directory is used. The path must be a directory inside a Git work tree.

The command detects the repository root automatically:

```text
Repository: /path/to/your/repository
Report dir: audit-results/security-audit-20260705-204512

==> Checking installed tools
==> Suspicious files in Git history
==> Sensitive file commits
==> Current suspicious files
...

Audit completed.
Open report:
  audit-results/security-audit-20260705-204512/REPORT.md

Important: do NOT commit audit-results/.
```

There are currently no scan-tuning flags. The command is intentionally run-and-report: point it at a repository, then review the generated files.

## Output layout

Each run creates a new timestamped directory:

```text
audit-results/
└── security-audit-YYYYMMDD-HHMMSS/
    ├── REPORT.md
    ├── suspicious-files-history.txt
    ├── sensitive-file-commits.txt
    ├── suspicious-files-current.txt
    ├── gitignore-check.txt
    ├── history-private-keys.txt
    ├── history-aws-access-keys.txt
    ├── history-jwt-tokens.txt
    ├── history-urls-with-credentials.txt
    ├── history-database-urls.txt
    ├── history-generic-secrets.txt
    ├── history-italian-fiscal-codes.txt
    ├── history-italian-iban.txt
    ├── history-emails.txt
    ├── history-italian-phones.txt
    ├── current-private-keys.txt
    ├── current-aws-access-keys.txt
    ├── current-jwt-tokens.txt
    ├── current-urls-with-credentials.txt
    ├── current-database-urls.txt
    ├── current-generic-secrets.txt
    ├── current-italian-fiscal-codes.txt
    ├── current-italian-iban.txt
    ├── current-emails.txt
    ├── current-italian-phones.txt
    ├── current-runtime-private-keys.txt
    ├── current-runtime-aws-access-keys.txt
    ├── current-runtime-jwt-tokens.txt
    ├── current-runtime-urls-with-credentials.txt
    ├── current-runtime-database-urls.txt
    ├── current-runtime-generic-secrets.txt
    ├── current-runtime-italian-fiscal-codes.txt
    ├── current-runtime-italian-iban.txt
    ├── current-runtime-emails.txt
    ├── current-runtime-italian-phones.txt
    ├── gitleaks-history.json
    ├── gitleaks-history.log
    ├── trufflehog-verified.jsonl
    ├── trufflehog-verified.err
    ├── trufflehog-all.jsonl
    └── trufflehog-all.err
```

Files produced by optional tools are only present when those tools are installed.

## Reading the summary

Start with:

```bash
less audit-results/security-audit-YYYYMMDD-HHMMSS/REPORT.md
```

`REPORT.md` contains:

- Repository remotes, status, and recent commits.
- Tool availability.
- One section for each check.
- A path to each detailed output file.
- Exit codes for command-based checks.
- Match counts for grep-based pattern checks.
- Final remediation notes.

Example summary section:

```markdown
## Git history grep: generic-secrets
- Output: `audit-results/security-audit-20260705-204512/history-generic-secrets.txt`
- Matches: `2`
```

Then inspect the referenced file:

```bash
sed -n '1,120p' audit-results/security-audit-20260705-204512/history-generic-secrets.txt
```

Example redacted output:

```text
Pattern name: generic-secrets
Regex: (...)

Matches are redacted. Format: commit:path:line:<redacted>

1111111111111111111111111111111111111111:config/app.example:42:<redacted>
2222222222222222222222222222222222222222:src/settings.sample:18:<redacted>
```

The script tells you where to look. It does not print secret values from its own grep-based checks.

## Common examples

### Audit the current repository

```bash
./audit-git-security.sh
```

Open the latest report:

```bash
latest_report="$(find audit-results -maxdepth 1 -type d -name 'security-audit-*' | sort | tail -n 1)"
less "$latest_report/REPORT.md"
```

### Audit another local repository

```bash
~/tools/audit-git-security/audit-git-security.sh ~/work/my-service
```

The report is written inside the audited repository:

```text
~/work/my-service/audit-results/security-audit-YYYYMMDD-HHMMSS/
```

You can also pass a subdirectory of a repository. The command still audits the full Git repository:

```bash
~/tools/audit-git-security/audit-git-security.sh ~/work/my-service/src
```

### Run before opening a pull request

```bash
git status --short
./audit-git-security.sh
latest_report="$(find audit-results -maxdepth 1 -type d -name 'security-audit-*' | sort | tail -n 1)"
grep -n "Matches:" "$latest_report/REPORT.md"
```

Use this as a review helper, not as an automatic approval gate. Some matches are expected to be false positives, especially in documentation, fixtures, generated examples, and test data.

### Review only current-tree findings

```bash
latest_report="$(find audit-results -maxdepth 1 -type d -name 'security-audit-*' | sort | tail -n 1)"
ls "$latest_report"/current-*.txt
```

Inspect a specific check:

```bash
less "$latest_report/current-generic-secrets.txt"
```

### Review only Git-history findings

```bash
latest_report="$(find audit-results -maxdepth 1 -type d -name 'security-audit-*' | sort | tail -n 1)"
ls "$latest_report"/history-*.txt
```

Inspect a specific check:

```bash
less "$latest_report/history-private-keys.txt"
```

### Review Gitleaks output

When `gitleaks` is installed:

```bash
latest_report="$(find audit-results -maxdepth 1 -type d -name 'security-audit-*' | sort | tail -n 1)"
less "$latest_report/gitleaks-history.log"
```

The JSON report is written to:

```bash
"$latest_report/gitleaks-history.json"
```

### Review TruffleHog output

When `trufflehog` is installed:

```bash
latest_report="$(find audit-results -maxdepth 1 -type d -name 'security-audit-*' | sort | tail -n 1)"
wc -l "$latest_report"/trufflehog-*.jsonl
```

Verified findings:

```bash
less "$latest_report/trufflehog-verified.jsonl"
```

All findings, including unverified ones:

```bash
less "$latest_report/trufflehog-all.jsonl"
```

### Check whether generated reports are ignored

```bash
git check-ignore -v audit-results
```

Expected result in this repository:

```text
.gitignore:1:audit-results/
```

For repositories you audit, add `audit-results/` to `.gitignore` before committing.

## Scan scopes

### Git history

History scans walk all commits reachable from all refs:

```bash
git rev-list --all
```

The script uses `git grep` against each revision and redacts matching lines.

History checks can find issues that no longer exist in the working tree. If a real secret was committed in the past, deleting it in a later commit is not enough. Rotate or revoke it.

### Current working tree

Current-tree scans use recursive grep and exclude common generated or third-party directories:

- `.git`
- `.venv`
- `node_modules`
- `vendor`
- `audit-results`
- `.pytest_cache`
- `benchmark/results`

### Current runtime tree

Runtime scans are narrower than full current-tree scans. They additionally exclude documentation, tests, API tests, and selected example/spec files:

- `doc`
- `tests`
- `api/tests`
- `README.md`
- `openapi.yaml`
- `FEATURING-FOR-PROD.md`
- `benchmark.py`

This helps separate findings that may affect runtime code from findings that are probably in examples, docs, fixtures, or tests.

## Handling findings

Treat every finding as a lead that needs manual review.

Recommended workflow:

1. Open `REPORT.md`.
2. Check all sections with non-zero match counts or scanner output.
3. Inspect the referenced files.
4. Decide whether each finding is a real issue or a false positive.
5. If a real secret appears in current code, remove it and move it to a proper secret manager or environment-specific configuration.
6. If a real secret appears anywhere in Git history, rotate or revoke it immediately.
7. If sensitive personal data appears in examples, tests, or fixtures, replace it with synthetic data.
8. Keep `audit-results/` out of version control.

Do not rely on history rewriting as the only remediation for leaked credentials. Even if you purge a value from Git history, assume it may already have been copied, cached, indexed, or pulled.

## Exit behavior

The command exits with an error when the selected path does not exist, is not a directory, or is not inside a Git work tree.

The command exits with status `2` when too many arguments are passed.

Scanner findings do not make the command fail. Individual scan sections record their own exit codes in `REPORT.md`, and optional tools are skipped when missing. This makes the command suitable for manual audits and exploratory review.

## Limitations

- The script is not a replacement for a complete security review.
- Regex checks can produce false positives and false negatives.
- Redaction applies to the script's grep-based checks; external tools may include their own metadata formats.
- The command does not automatically remove secrets.
- The command does not rewrite Git history.
- Large repositories with long histories can take time to scan.
- Binary files are mostly ignored by the grep-based checks.

## Recommended `.gitignore` entries for audited repositories

At minimum:

```gitignore
audit-results/
```

For application repositories, also consider ignoring local environment and credential files:

```gitignore
.env
.env.*
*.pem
*.key
*.p12
*.pfx
*.jks
*.keystore
*.sqlite
*.db
*.dump
*.bak
```

Adjust these patterns to your project. Some repositories intentionally track safe example files such as `.env.example`; review before adding broad ignore rules.

## Troubleshooting

### `ERRORE: il path indicato non è dentro un repository Git: ...`

Run the command with a directory inside a Git repository:

```bash
/path/to/audit-git-security.sh /path/to/repository
```

### `ERRORE: path non trovato o non è una cartella: ...`

Check the path and pass an existing directory:

```bash
/path/to/audit-git-security.sh /path/to/existing/repository
```

### `gitleaks` is missing

Install it or let the script skip that section:

```bash
brew install gitleaks
```

### `trufflehog` is missing

Install it or let the script skip that section:

```bash
brew install trufflehog
```

### The audit takes too long

Large histories can be slow because the script checks every reachable commit. Start by reviewing current-tree findings while the history scan runs, or run the audit on a machine with local access to the repository instead of a slow network filesystem.

### Documentation or fixtures trigger findings

That is expected. Use the full current-tree scan to see all possible matches, then compare it with the runtime-only scan to prioritize production-relevant files.

## Safety notes

- Do not commit `audit-results/`.
- Do not paste raw findings into tickets, chats, or pull requests without reviewing them first.
- Rotate or revoke any real secret found in Git history.
- Replace real personal data in test fixtures with synthetic data.
- Store production secrets in a dedicated secret manager or deployment platform, not in Git.
