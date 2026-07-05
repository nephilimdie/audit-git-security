from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from audit_git_security import audit_repo, is_git_repo


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)


class AuditGitSecurityTests(unittest.TestCase):
    def make_repo(self) -> Path:
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        repo = Path(temp_dir.name)
        git(repo, "init")
        git(repo, "config", "user.name", "Test User")
        git(repo, "config", "user.email", "test@example.com")
        return repo

    def test_identifies_git_repository(self) -> None:
        repo = self.make_repo()
        self.assertTrue(is_git_repo(repo))

    def test_clean_repository_has_no_findings(self) -> None:
        repo = self.make_repo()
        (repo / "README.md").write_text("# demo\n", encoding="utf-8")
        git(repo, "add", "README.md")
        self.assertEqual(audit_repo(repo), [])

    def test_detects_insecure_http_remote(self) -> None:
        repo = self.make_repo()
        git(repo, "remote", "add", "origin", "http://example.com/repo.git")
        issues = audit_repo(repo)
        self.assertTrue(any(issue.check == "remote-url" for issue in issues))

    def test_detects_plaintext_credential_helper(self) -> None:
        repo = self.make_repo()
        git(repo, "config", "credential.helper", "store")
        issues = audit_repo(repo)
        self.assertTrue(any(issue.check == "credential-helper" for issue in issues))

    def test_detects_sensitive_tracked_files_and_contents(self) -> None:
        repo = self.make_repo()
        (repo / ".env").write_text("API_KEY=ghp_abcdefghijklmnopqrstuvwxyz123456\n", encoding="utf-8")
        git(repo, "add", ".env")
        issues = audit_repo(repo)
        checks = {issue.check for issue in issues}
        self.assertIn("tracked-secret-file", checks)
        self.assertIn("secret-content", checks)


if __name__ == "__main__":
    unittest.main()
