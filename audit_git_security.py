#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


SECRET_FILE_PATTERNS = (
    ".env",
    ".pem",
    ".p12",
    ".pfx",
    ".key",
    "id_rsa",
    "id_dsa",
    "credentials",
)

MAX_TEXT_FILE_SIZE = 1024 * 1024

SECRET_CONTENT_PATTERNS = (
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    re.compile(
        r"(?i)(?:password|secret|token|api[_-]?key)\s*[:=]\s*(?:\"(?:\\.|[^\"\\])+\"|'(?:\\.|[^'\\])+'|[^\r\n#]+)"
    ),
)


@dataclass
class Issue:
    check: str
    severity: str
    message: str
    file: str | None = None


def run_git(repo_path: Path, *args: str, allow_failure: bool = False) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo_path), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        if allow_failure:
            return result.stdout
        error = result.stderr.strip() or result.stdout.strip() or "git command failed"
        raise ValueError(f"git {' '.join(args)} failed: {error}")
    return result.stdout


def is_git_repo(repo_path: Path) -> bool:
    result = subprocess.run(
        ["git", "-C", str(repo_path), "rev-parse", "--is-inside-work-tree"],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0 and result.stdout.strip() == "true"


def get_tracked_files(repo_path: Path) -> list[Path]:
    output = run_git(repo_path, "ls-files", "-z")
    return [repo_path / part for part in output.split("\0") if part]


def looks_binary(content: bytes) -> bool:
    return b"\0" in content


def audit_repo(repo_path: Path) -> list[Issue]:
    issues: list[Issue] = []

    for line in run_git(repo_path, "remote", "-v").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].startswith("http://"):
            issues.append(
                Issue(
                    check="remote-url",
                    severity="high",
                    message=f"Insecure remote URL uses HTTP: {parts[1]}",
                )
            )

    credential_helpers = {
        helper.strip()
        for helper in run_git(
            repo_path, "config", "--get-all", "credential.helper", allow_failure=True
        ).splitlines()
        if helper.strip()
    }
    if "store" in credential_helpers:
        issues.append(
            Issue(
                check="credential-helper",
                severity="medium",
                message="credential.helper=store keeps credentials in plaintext on disk",
            )
        )

    for tracked_file in get_tracked_files(repo_path):
        relative_path = tracked_file.relative_to(repo_path).as_posix()
        lower_name = tracked_file.name.lower()
        if any(pattern in lower_name for pattern in SECRET_FILE_PATTERNS):
            issues.append(
                Issue(
                    check="tracked-secret-file",
                    severity="high",
                    message=f"Tracked file name looks sensitive: {relative_path}",
                    file=relative_path,
                )
            )

        if not tracked_file.is_file():
            continue

        try:
            content = tracked_file.read_bytes()
        except OSError:
            continue

        if looks_binary(content) or len(content) > MAX_TEXT_FILE_SIZE:
            continue

        text = content.decode("utf-8", errors="ignore")
        for pattern in SECRET_CONTENT_PATTERNS:
            if pattern.search(text):
                issues.append(
                    Issue(
                        check="secret-content",
                        severity="high",
                        message=f"Tracked file contains a potential secret matching {pattern.pattern}",
                        file=relative_path,
                    )
                )
                break

    return issues


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit a Git repository for common security issues.")
    parser.add_argument("repo", nargs="?", default=".", help="Path to the Git repository to audit")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    repo_path = Path(os.path.abspath(args.repo))

    if not is_git_repo(repo_path):
        error = {"ok": False, "error": f"{repo_path} is not a Git repository"}
        if args.json:
            print(json.dumps(error))
        else:
            print(error["error"], file=sys.stderr)
        return 2

    issues = audit_repo(repo_path)
    payload = {
        "ok": not issues,
        "repo": str(repo_path),
        "issues": [asdict(issue) for issue in issues],
    }

    if args.json:
        print(json.dumps(payload, indent=2))
    elif issues:
        print(f"Found {len(issues)} potential security issue(s) in {repo_path}:")
        for issue in issues:
            location = f" [{issue.file}]" if issue.file else ""
            print(f"- {issue.severity}: {issue.check}{location} - {issue.message}")
    else:
        print(f"No obvious Git security issues found in {repo_path}.")

    return 1 if issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
