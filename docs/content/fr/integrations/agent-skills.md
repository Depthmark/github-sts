---
title: Skills pour agents
description: Installez les skills qui permettent à un agent de code d'écrire une politique de confiance, de brancher un workflow GitHub Actions sur github-sts et de publier un bundle de politique signé.
weight: 8
translationKey: agent-skills
translationStatus: pending-review
---

github-sts fournit trois skills : deux pour les propriétaires de dépôts et un pour les administrateurs de la plateforme. Avec les deux premiers, un agent de code écrit une politique de confiance valide et un workflow qui échange un jeton, à partir de valeurs qu'il lit sur GitHub plutôt que de valeurs que vous recopiez à la main. Avec le troisième, il publie un bundle de politique signé et écrit la configuration qui l'épingle.

| Skill | Ce qu'il fait |
|---|---|
| `write-trust-policy` | Recherche les identifiants immuables du propriétaire et du dépôt, écrit `.github/sts/{app}/{identity}.sts.yaml` dans le dépôt cible, puis le valide avec le [schéma publié]({{< relref "/reference/policy-schema" >}}). |
| `wire-workflow` | Ajoute l'étape d'échange à un workflow, avec une version épinglée de `Depthmark/github-sts-action`, `id-token: write` sur le job uniquement, et les mêmes `audience`, `app` et `identity` que la politique. |
| `publish-policy-bundle` | Pour les administrateurs de la plateforme. Écrit un workflow qui construit un bundle de politique, le pousse vers GitHub Container Registry et signe son digest avec une version épinglée de cosign v3, puis écrit le bloc `bundles:` épinglé par digest pour `bundle_enforcement: required`. Voir [Publier un bundle de politique](#publier-un-bundle-de-politique). |

Les skills n'appellent jamais votre serveur github-sts et ne détiennent aucun identifiant secret. Les deux skills destinés aux propriétaires de dépôts lisent les métadonnées des dépôts avec la commande `gh` à laquelle vous êtes déjà connecté, et ils valident avec le schéma statique. Le skill de bundle pousse et signe depuis un job GitHub Actions, avec le jeton et l'identité que GitHub donne à ce job.

## Avant de commencer

Pour écrire une politique de confiance ou brancher un workflow, demandez trois valeurs à l'administrateur de la plateforme qui exploite github-sts. Les skills les demandent et ne les devinent pas.

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

Chaque skill est un simple dossier contenant un fichier `SKILL.md`, au format ouvert Agent Skills. Tout agent qui lit ce format peut en utiliser une copie. Copiez les dossiers dont vous avez besoin sous `skills/` depuis une [version publiée](https://github.com/Depthmark/github-sts/releases) de github-sts vers le répertoire de skills que lit votre agent, par exemple `.claude/skills/` ou `.github/skills/` dans votre dépôt.

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

## Publier un bundle de politique

Ce skill s'adresse à l'administrateur de la plateforme qui exploite github-sts avec `bundle_enforcement: required`. Ouvrez l'agent dans le dépôt qui contient la politique Rego, puis décrivez l'objectif :

```text
Publie la révision 42 de la politique de policy/ vers ghcr.io/my-org/sts-policy et donne-moi le bloc bundles.
```

Le skill procède dans cet ordre :

1. Il vérifie que la révision déclarée dans les métadonnées Rego est égale à la révision demandée.
2. Il écrit `.github/workflows/publish-bundle.yml`, qui construit avec `opa build --revision`, pousse vers GitHub Container Registry, signe le digest sans clé et vérifie la signature avec l'identité que le broker attendra.
3. Une fois le workflow fusionné et exécuté, il lit la référence épinglée dans le résumé de l'exécution et écrit le bloc `bundles:`, avec `expected_policy_revision` et un `certificate_identity_regexp` qui ne correspond qu'à ce workflow sur cette branche.
4. Après le déploiement, il lit la sortie de `/health` que vous collez et confirme que le bundle est admis.

Le skill respecte quatre limites, et s'arrête pour vous consulter lorsqu'une étape en franchirait une :

- Il signe le digest, jamais le tag.
- Il refuse de signer avec un cosign qui n'est pas épinglé à une version v3 exacte, car le format de signature dépend de la version majeure de cosign.
- Il ne lit jamais un mot de passe de registre, un jeton ou une clé privée.
- Il n'assouplit jamais `fail_mode`, l'épinglage par digest ou le contrôle de révision pour faire admettre un bundle.

Vous pouvez aussi lui donner une ligne de journal du broker. Pour chaque `signature_error_code`, il nomme la phase qui a échoué et le correctif :

```text
Le broker journalise signature_error_code=signature_not_found pour le nouveau bundle. Qu'est-ce qui a échoué ?
```

Le skill couvre GitHub Container Registry et la signature sans clé. Pour Harbor, Nexus, Artifactory ou la signature par paire de clés, suivez [Publier des bundles signés]({{< relref "/integrations/publishing-bundles" >}}). Il n'écrit pas de Rego.

## Versions

Les skills n'ont pas de version propre. Ils sont publiés avec github-sts, et le plugin indique la version de github-sts dont il provient. Un skill et un serveur de même version s'accordent sur le schéma de politique, le format des bundles et les codes d'erreur. Mettez donc le plugin à jour lorsque l'administrateur de la plateforme met le serveur à niveau.

## Ce que les skills ne couvrent pas

- **La raison d'un refus.** Un échange refusé renvoie un `code` et un `trace_id`. `wire-workflow` indique ce que vous pouvez vérifier seul pour chaque code, et l'administrateur de la plateforme trouve le reste dans le journal d'audit. Voir [Dépannage]({{< relref "/operations/troubleshooting" >}}).
- **Les exceptions entre organisations.** Un workflow d'une organisation qui demande un jeton pour une autre peut nécessiter une entrée dans le bundle d'entreprise. Voir [Politiques de confiance]({{< relref "/concepts/trust-policies" >}}).
- **Les permissions de la GitHub App.** Une politique ne peut pas accorder plus que ce que détient l'App, et seul l'administrateur de la plateforme connaît ce plafond.
