---
title: Configurer une GitHub App
description: Créez la GitHub App que github-sts utilisera pour émettre des jetons d'installation, définissez ses permissions et générez une clé privée.
weight: 2
translationKey: get-started-configure-github-app
translationStatus: pending-review
---

github-sts émet des jetons en s'authentifiant comme une **GitHub App**, puis en demandant un jeton
d'installation limité à exactement ce qu'une politique de confiance autorise. Avant tout, cette
App doit exister.

## 1. Créer l'App

Dans l'organisation ou le compte qui possédera l'App : **Settings → Developer settings → GitHub Apps → New GitHub App**.

- **GitHub App name** : un nom identifiable, par ex. `github-sts-<environnement>`.
- **Homepage URL** : n'importe quelle URL valide. Elle n'est pas utilisée à l'exécution.
- **Webhook** : décochez **Active**. github-sts ne consomme pas de webhooks.

## 2. Définir les permissions

N'accordez que les permissions de dépôt/organisation que vos politiques de confiance émettront réellement.
Un ensemble de départ courant :

| Permission | Accès | Pourquoi |
|---|---|---|
| Contents | Lecture et écriture | Cloner, pousser, créer des releases |
| Pull requests | Lecture et écriture | Ouvrir, commenter, fusionner des PR |
| Metadata | Lecture seule | Requis par GitHub pour toutes les Apps |

> **C'est un plafond, pas une politique.** Ce que vous accordez ici borne le maximum que n'importe
> quelle politique de confiance peut émettre. Une politique ne peut pas demander une permission que
> l'App elle-même n'a pas. Commencez restreint et ajoutez des permissions quand une charge de
> travail réelle en a besoin, pas par anticipation.

## 3. Générer une clé privée

Sur la page de paramètres de l'App, sous **Private keys**, cliquez sur **Generate a private key**.
GitHub télécharge un fichier `.pem`. C'est l'unique copie, alors stockez-le dans un gestionnaire de
secrets, pas dans le dépôt.

Notez l'**App ID** affiché en haut de la même page. Vous en aurez besoin avec la clé privée.

## Suite

[Installer l'App](../install-the-app/) sur l'organisation ou les dépôts que les jetons doivent toucher.
