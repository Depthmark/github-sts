---
title: Modèle de sécurité
description: Limites de confiance, privilège minimal, liaison d'audience, prévention de rejeu, portée explicite du sujet, attentes de journalisation et modèle de menace.
weight: 2
translationKey: security-model
translationStatus: pending-review
---

## Principes de conception

github-sts repose sur cinq principes de sécurité :

### 1. Zéro crédentiel stocké

github-sts ne stocke jamais de jetons OIDC, de PAT GitHub ni de crédentiels à longue durée de vie. Le seul secret qu'il détient est la clé privée de la GitHub App, montée depuis un magasin de secrets (Kubernetes Secret, Vault, cloud KMS).

### 2. Privilège minimal

Chaque échange de jeton est médié par une **politique de confiance** qui déclare exactement les autorisations que reçoit la charge de travail demandeuse. Il n'y a pas de repli par défaut qui accorderait un accès étendu ; si aucune politique ne correspond, l'échange est rejeté.

### 3. Liaison d'audience

Chaque politique de confiance doit déclarer une `audience`, et chaque jeton OIDC doit porter cette audience. Cela empêche la réutilisation de jeton inter-RP : un jeton émis pour un autre service ne peut pas être échangé auprès de github-sts.

### 4. Prévention de rejeu

Le `jti` de chaque jeton OIDC est suivi. Si le même `jti` apparaît deux fois dans la fenêtre de rejeu, la seconde requête est rejetée. Dans les déploiements multi-réplicas, utilisez Redis pour partager le cache JTI entre les instances.

### 5. Portée explicite du sujet

Les politiques de confiance font correspondre l'identité de la charge de travail via `subject` ou `subject_pattern` par rapport à la revendication OIDC `sub`. Préférez un `subject` exact (dépôt et référence) afin que la portée de la politique soit explicite. Un `subject_pattern` large correspond à n'importe quel sujet ; gardez-le aussi étroit que possible.

## Limites de confiance

```
┌─────────────────────────────────────────────────────────┐
│  Charge de travail (runner CI, fonction cloud, etc.)    │
│  - Détient un jeton OIDC                                │
│  - Non fiable : toute charge de travail peut présenter  │
│    n'importe quel jeton                                 │
└──────────────┬──────────────────────────────────────────┘
               │ Jeton OIDC (jeton Bearer)
               ▼
┌─────────────────────────────────────────────────────────┐
│  github-sts                                             │
│  - Valide la signature, l'expiration, les revendications│
│  - Charge et évalue la politique de confiance           │
│  - Émet un jeton d'installation à portée limitée        │
│  - Fiable : le STS est le point d'application de la     │
│    politique                                           │
└──────────────┬──────────────────────────────────────────┘
               │ Jeton d'installation
               ▼
┌─────────────────────────────────────────────────────────┐
│  API GitHub                                             │
│  - Accepte les jetons d'installation                    │
│  - Fiable : le jeton est cryptographiquement lié à l'App│
└─────────────────────────────────────────────────────────┘
```

## Modèle de menace

### Menaces atténuées

| Menace | Atténuation |
|---|---|
| **Rejeu de jeton** | Le cache JTI (mémoire ou Redis) rejette les valeurs `jti` dupliquées |
| **Réutilisation de jeton inter-RP** | Champ `audience` obligatoire dans chaque politique + vérification optionnelle `oidc.required_audience` au niveau du serveur |
| **Contrefaçon de jeton OIDC** | La validation JWKS vérifie la signature du jeton par rapport aux clés publiques de l'émetteur |
| **Acceptation de jeton expiré** | L'expiration JWT (`exp`) et l'émission (`iat`) sont requises et validées ; `nbf` est vérifié lorsqu'il est présent |
| **Usurpation d'émetteur** | Le `kid` doit correspondre à une clé du JWKS découvert ; l'hôte JWKS doit être l'hôte de l'émetteur ou figurer dans `trusted_jwks_hosts` |
| **Élévation de privilèges** | Les politiques de confiance définissent des autorisations exactes par charge de travail ; pas de repli global |
| **Exfiltration de secrets** | Aucun secret à longue durée stocké ; clés privées montées en lecture seule depuis des magasins de secrets |
| **Déni de service** | Limitation de débit par IP, tailles de corps de requête bornées et un cache JWKS plafonné à 100 entrées |

### Menaces non atténuées

| Menace | Raison | Contrôle recommandé |
|---|---|---|
| **Compromission de la clé privée de la GitHub App** | Si la clé privée fuit, un attaquant peut émettre des jetons arbitraires | Renouvelez les clés, utilisez des certificats à courte durée de vie, surveillez `githubsts_github_tokens_issued_total` pour les anomalies |
| **Écoute réseau** | github-sts écoute sur HTTP simple sauf si le TLS natif est activé | Terminez le TLS à l'ingress/Gateway, ou activez le TLS/mTLS natif pour les déploiements autonomes ou le re-chiffrement Gateway→backend |
| **Compromission de l'émetteur OIDC** | Si l'émetteur est compromis, il peut émettre des jetons valides | Utilisez `allowed_issuers` de façon restrictive ; surveillez `githubsts_oidc_validation_errors_total` |
| **Compromission de Redis (backend JTI)** | Un attaquant avec accès à Redis peut vider le cache JTI | Utilisez des ACL Redis, TLS et des politiques réseau |

## Liste de contrôle de déploiement sécurisé

- [ ] `oidc.allowed_issuers` est défini avec des URL d'émetteurs explicites
- [ ] `oidc.required_audience` est défini avec une valeur spécifique au déploiement
- [ ] `jti.backend` est `redis` pour les déploiements multi-réplicas
- [ ] Les clés privées de la GitHub App sont montées depuis un magasin de secrets, pas intégrées aux images
- [ ] `/health` et `/ready` sont reliés aux sondes de vivacité/préparation
- [ ] `/metrics` est collecté par Prometheus
- [ ] Le journal d'audit est transmis au SIEM
- [ ] Le TLS se termine à l'ingress/Gateway, ou le TLS/mTLS natif est activé pour les déploiements autonomes
- [ ] Les limites de débit sont configurées

## Journalisation et audit

Chaque échange de jeton produit une entrée de journal d'audit structurée contenant :

- `trace_id`: corrèle le code d'erreur de la réponse à la raison côté serveur
- `issuer`, `subject`: les revendications du jeton OIDC
- `scope`, `app`, `identity`: les paramètres de l'échange
- `jti`: l'ID JWT du jeton
- `result`: `success`, `policy_denied`, `oidc_invalid`, etc.
- `error_reason`: la raison d'un échange rejeté
- `duration_ms`: la latence de l'échange
- `user_agent`, `remote_ip`: les métadonnées de la requête

Le `trace_id` est renvoyé dans la réponse d'erreur JSON afin que les clients puissent corréler leur rejet au journal côté serveur. Les champs `error` et `code` de la réponse sont délibérément génériques ; la raison complète n'apparaît que dans les journaux.
