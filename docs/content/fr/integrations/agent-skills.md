---
title: Skills pour agents
description: Installez les skills qui permettent à un agent de code d'écrire une politique de confiance et de brancher un workflow GitHub Actions sur github-sts.
weight: 8
translationKey: agent-skills
translationStatus: pending-review
---

github-sts fournit deux skills destinés aux propriétaires de dépôts. Avec eux, un agent de code écrit une politique de confiance valide et un workflow qui échange un jeton, à partir de valeurs qu'il lit sur GitHub plutôt que de valeurs que vous recopiez à la main.

| Skill | Ce qu'il fait |
|---|---|
| `write-trust-policy` | Recherche les identifiants immuables du propriétaire et du dépôt, écrit `.github/sts/{app}/{identity}.sts.yaml` dans le dépôt cible, puis le valide avec le [schéma publié]({{< relref "/reference/policy-schema" >}}). |
| `wire-workflow` | Ajoute l'étape d'échange à un workflow, avec une version épinglée de `Depthmark/github-sts-action`, `id-token: write` sur le job uniquement, et les mêmes `audience`, `app` et `identity` que la politique. |

Les skills n'appellent jamais votre serveur github-sts et ne détiennent aucun identifiant secret. Ils lisent les métadonnées des dépôts avec la commande `gh` à laquelle vous êtes déjà connecté, et ils valident avec le schéma statique.

## Avant de commencer

Demandez trois valeurs à l'administrateur de la plateforme qui exploite github-sts. Les skills les demandent et ne les devinent pas.

1. L'URL de base du serveur, par exemple `https://sts.example.com`.
2. L'audience attendue par le serveur, qui est souvent la même URL.
3. Le nom de la GitHub App tel qu'il est configuré sur le serveur, par exemple `default`.

Il vous faut aussi la [commande `gh`](https://cli.github.com/), connectée avec un accès en lecture aux dépôts concernés.

## Installer dans Claude Code

Exécutez ces deux commandes dans Claude Code :

```text
/plugin marketplace add Depthmark/github-sts
/plugin install github-sts@depthmark
```

## Installer dans GitHub Copilot CLI

Exécutez ces deux commandes dans un terminal :

```bash
copilot plugin marketplace add Depthmark/github-sts
copilot plugin install github-sts@depthmark
```

## Installer sans plugin

Chaque skill est un simple dossier contenant un fichier `SKILL.md`, au format ouvert Agent Skills. Tout agent qui lit ce format peut en utiliser une copie. Copiez `skills/write-trust-policy` et `skills/wire-workflow` depuis une [version publiée](https://github.com/Depthmark/github-sts/releases) de github-sts vers le répertoire de skills que lit votre agent, par exemple `.claude/skills/` ou `.github/skills/` dans votre dépôt.

Un skill copié ne se met pas à jour tout seul. Copiez-le de nouveau lorsque vous mettez github-sts à niveau.

## Utiliser les skills

Ouvrez l'agent dans le dépôt qui recevra le jeton, puis décrivez l'objectif :

```text
Écris une politique de confiance github-sts pour que le workflow de release sur main puisse ouvrir des pull requests dans ce dépôt.
```

Une fois la politique écrite, demandez le workflow :

```text
Branche le workflow de release sur github-sts avec cette politique.
```

Relisez les deux fichiers avant de les fusionner. La politique de confiance prend effet dès qu'elle se trouve sur la branche par défaut du dépôt cible, et elle décide qui peut obtenir un jeton : traitez-la comme tout autre changement d'accès.

## Versions

Les skills n'ont pas de version propre. Ils sont publiés avec github-sts, et le plugin indique la version de github-sts dont il provient. Un skill et un serveur de même version s'accordent sur le schéma de politique et sur les codes d'erreur. Mettez donc le plugin à jour lorsque l'administrateur de la plateforme met le serveur à niveau.

## Ce que les skills ne couvrent pas

- **La raison d'un refus.** Un échange refusé renvoie un `code` et un `trace_id`. `wire-workflow` indique ce que vous pouvez vérifier seul pour chaque code, et l'administrateur de la plateforme trouve le reste dans le journal d'audit. Voir [Dépannage]({{< relref "/operations/troubleshooting" >}}).
- **Les exceptions entre organisations.** Un workflow d'une organisation qui demande un jeton pour une autre peut nécessiter une entrée dans le bundle d'entreprise. Voir [Politiques de confiance]({{< relref "/concepts/trust-policies" >}}).
- **Les permissions de la GitHub App.** Une politique ne peut pas accorder plus que ce que détient l'App, et seul l'administrateur de la plateforme connaît ce plafond.
