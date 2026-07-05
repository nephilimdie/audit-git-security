# audit-git-security

`audit-git-security` is a small CLI that audits a Git repository for a few common security problems:

- insecure `http://` remotes
- `credential.helper=store`
- tracked files with sensitive names such as `.env` or private key files
- tracked file contents that look like hard-coded secrets

## Usage

```bash
python audit_git_security.py /path/to/repo
python audit_git_security.py --json /path/to/repo
```
