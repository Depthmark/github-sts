---
title: Installer l'App
description: Installez la GitHub App sur l'organisation ou les dépôts que les jetons émis doivent toucher.
weight: 3
translationKey: get-started-install-the-app
translationStatus: pending-review
---

Une GitHub App a des permissions (ce qu'elle *peut* faire) et une installation (*où* elle peut
agir). Les deux bornent les jetons que github-sts peut émettre.

## Installer sur des dépôts précis, pas sur toute l'organisation

Depuis la page de paramètres de l'App, cliquez sur **Install App**, choisissez l'organisation, puis
sélectionnez **Only select repositories** et choisissez exactement les dépôts dont vos charges de
travail ont besoin. Cela garde le rayon d'action de l'App égal à ce qui est réellement utilisé,
indépendamment de ce que dit une politique de confiance.

Choisir **All repositories** met automatiquement tout futur dépôt de l'organisation dans le
périmètre. Évitez cela sauf si c'est réellement l'intention.

## Plusieurs environnements, plusieurs installations

Si les charges de travail de staging et de production ne doivent jamais pouvoir échanger les
jetons l'une de l'autre, utilisez des GitHub Apps distinctes (et des installations distinctes) par
environnement plutôt qu'une seule App installée partout. github-sts prend en charge
[plusieurs GitHub Apps](../../reference/configuration/) dans un même déploiement précisément pour ce cas.

## Confirmer l'installation

```bash
curl -fsS -H "Authorization: Bearer $JWT" \
  https://api.github.com/app/installations | jq '.[].account.login'
```

(`$JWT` est ici un JWT d'App de courte durée signé avec la clé privée. Voir
[la documentation d'authentification de GitHub](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app)
si vous voulez le vérifier manuellement. En fonctionnement normal, github-sts effectue cette
signature à votre place.)

## Suite

[Générer un jeton](../generate-a-token/) : écrivez une politique de confiance et appelez `/sts/exchange`.
