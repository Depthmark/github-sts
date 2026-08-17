---
headless: true
---

```bash
docker build -t github-sts:local .
docker run -d --name github-sts-local -p 8080:8080 \
  -e GITHUBSTS_APP_DEFAULT_APP_ID \
  -e GITHUBSTS_APP_DEFAULT_PRIVATE_KEY \
  -e GITHUBSTS_OIDC_ALLOWED_ISSUERS \
  -e GITHUBSTS_OIDC_REQUIRED_AUDIENCE \
  github-sts:local
```
