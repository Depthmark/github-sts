---
title: Get Started
translationKey: get-started
weight: 1
---

Four steps from nothing to a working token exchange, in about fifteen minutes.

1. [Configure a GitHub App](configure-github-app/): create the App, set permissions, generate a private key.
2. [Install the App](install-the-app/): install it on the organization or repositories the tokens will touch.
3. [Generate a token](generate-a-token/): write a trust policy and call `/sts/exchange`.
4. [Monitor usage](../integrations/monitor-usage/): read the metrics and audit log to confirm what was issued.

The [Quickstart (local)](quickstart-local/) runs github-sts on your own machine with settings chosen for setup speed. For a real deployment, see [Deploy with Helm](../integrations/deploy-with-helm/) and [Kubernetes](../operations/kubernetes/).
