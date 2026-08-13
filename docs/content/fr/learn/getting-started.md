---
title: Démarrage rapide
description: Exécutez github-sts localement et échangez votre premier jeton OIDC contre un jeton d'installation GitHub à portée limitée.
weight: 1
translationKey: getting-started
translationStatus: pending-review
---

Ce guide vous accompagne pour exécuter github-sts localement et échanger votre premier jeton OIDC contre un jeton d'installation GitHub à portée limitée.

## Prérequis

- **Go 1.26+** (développement local) ou **Docker** (construction de conteneurs)
- Une [GitHub App](https://docs.github.com/en/apps/creating-github-apps) installée sur l'organisation ou les dépôts auxquels vous souhaitez déléguer l'accès
- L'**App ID** de la GitHub App et sa **clé privée** (PEM)
- Un jeton OIDC provenant d'un émetteur pris en charge (GitHub Actions, Azure, GCP, etc.): voir [Émetteurs OIDC]({{< relref "/learn/oidc-issuers" >}})

## 1. Configurer les identifiants

Vous pouvez fournir les identifiants via des variables d'environnement, un fichier de configuration YAML, ou un mélange des deux.

**Option A: Variables d'environnement :**

```bash
export GITHUBSTS_APP_DEFAULT_APP_ID="123456"
export GITHUBSTS_APP_DEFAULT_PRIVATE_KEY="$(cat /path/to/private-key.pem)"
```

**Option B: Fichier de configuration YAML :**

```bash
export GITHUBSTS_CONFIG_PATH=./config/github-sts.example.yaml
```

Consultez [Configuration]({{< relref "/reference/configuration" >}}) pour la référence complète.

## 2. Exécuter

### Go

```bash
go build -o github-sts ./cmd/github-sts
./github-sts
```

### Docker

```bash
docker build -t github-sts:local .
docker run -p 8080:8080 \
  -e GITHUBSTS_APP_DEFAULT_APP_ID \
  -e GITHUBSTS_APP_DEFAULT_PRIVATE_KEY \
  github-sts:local
```

## 3. Vérifier

```bash
curl http://localhost:8080/health   # {"status":"ok"}
curl http://localhost:8080/ready    # {"ready":true}
```

Si `/ready` renvoie `503`, le serveur n'a pas encore commencé à servir. Consultez les journaux du serveur.

## 4. Écrire une politique de confiance

Les politiques de confiance se trouvent **dans le dépôt cible**, à l'emplacement `.github/sts/{app}/{identity}.sts.yaml`. Pour `app=default` et `identity=ci` dans `myorg/myrepo`, cela donne :

```
myorg/myrepo/.github/sts/default/ci.sts.yaml
```

Exemple minimal pour un workflow GitHub Actions sur `main` :

```yaml
issuer: https://token.actions.githubusercontent.com
subject: repo:myorg/myrepo:ref:refs/heads/main
audience: https://sts.example.com
permissions:
  contents: read
  pull_requests: write
```

> **Important :** `audience` est obligatoire. La même valeur doit être transmise à `core.getIDToken(<audience>)` dans le workflow qui demande le jeton OIDC.

## 5. Échanger un jeton

```bash
curl -H "Authorization: Bearer $OIDC_TOKEN" \
  "http://localhost:8080/sts/exchange?scope=myorg/myrepo&app=default&identity=ci"
```

Réponse attendue :

```json
{
  "token": "ghs_xxxxxxxxxxxxxxxxxxxx",
  "scope": "myorg/myrepo",
  "app": "default",
  "identity": "ci",
  "permissions": {
    "contents": "read",
    "pull_requests": "write"
  }
}
```

Le jeton `ghs_…` renvoyé est un jeton d'installation GitHub App standard, limité exactement aux dépôts et autorisations déclarés dans la politique.

## Étapes suivantes

- [Référence API]({{< relref "/reference/api" >}}): schéma complet des requêtes/réponses, codes d'erreur, bibliothèque cliente Go
- [Configuration]({{< relref "/reference/configuration" >}}): toutes les variables YAML/d'environnement, le schéma des politiques de confiance, la portée d'organisation
- [Déploiement]({{< relref "/operations/deployment" >}}): Docker et Helm
- [Dépannage]({{< relref "/operations/troubleshooting" >}}): erreurs courantes et leur résolution
