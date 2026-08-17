---
title: Démarrage rapide (local)
translationKey: get-started-quickstart-local
environment: local
weight: 6
translationStatus: pending-review
---

Vous avez déjà une GitHub App issue de [Configurer une GitHub App](../configure-github-app/) et
[Installer l'App](../install-the-app/) ? Ceci construit et exécute l'image du conteneur sur votre
propre machine avec des réglages choisis pour la rapidité de mise en place, pas pour un usage en
production, afin d'avoir le serveur en service et vérifié en quelques minutes. Il n'existe pas
encore d'image github-sts publiée, donc cette étape en construit une localement à partir du
`Dockerfile` du dépôt.

## Prérequis

- Docker (ou un autre runtime de conteneurs compatible OCI)
- Une GitHub App que vous pouvez installer sur une organisation de test
- La clé privée de l'App au format `.pem`

## Configuration

{{< snippet "config-local" >}}

## Démarrer le serveur

{{< snippet "run-local" >}}

## Vérifier qu'il est en service

```bash
curl -s http://127.0.0.1:8080/health
# {"status":"ok"}
```

Consultez les journaux :

```bash
docker logs github-sts-local
```

Sans `GITHUBSTS_JTI_BACKEND` défini, le serveur utilise par défaut le backend JTI en mémoire, et
les journaux portent un avertissement à chaque démarrage : `in-memory JTI cache does not survive
restarts and is not shared across replicas; consider redis for production`. Cet avertissement
n'est pas du bruit : la protection contre le rejeu est réinitialisée à chaque redémarrage du
conteneur.

Une fois terminé, arrêtez et supprimez le conteneur :

```bash
docker rm -f github-sts-local
```

## Suite

Cette page ne fait que démarrer le serveur : elle n'échange pas de jeton, car cela nécessite un
véritable jeton OIDC provenant d'un fournisseur d'identité, que ce démarrage rapide n'émet pas.
Voir [Générer un jeton](../generate-a-token/) pour savoir comment demander un jeton OIDC depuis un
workflow GitHub Actions et l'échanger ici.

Ce conteneur s'exécute aussi sans TLS, sans Redis et sans autoscaling ; c'est fait pour essayer
github-sts, pas pour l'exploiter. Pour un déploiement réel, voir
[Déployer avec Helm](../../integrations/deploy-with-helm/) et
[Kubernetes](../../operations/kubernetes/).
