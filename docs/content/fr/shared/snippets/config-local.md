---
headless: true
---

```bash
# LOCAL DEVELOPMENT ONLY, NOT FOR PRODUCTION.
export GITHUBSTS_APP_DEFAULT_APP_ID="123456"
export GITHUBSTS_APP_DEFAULT_PRIVATE_KEY="$(cat /path/to/private-key.pem)"
export GITHUBSTS_OIDC_ALLOWED_ISSUERS="https://token.actions.githubusercontent.com"
export GITHUBSTS_OIDC_REQUIRED_AUDIENCE="https://sts.example.com"
```
