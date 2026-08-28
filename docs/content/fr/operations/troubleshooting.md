---
title: Dépannage
description: Diagnostics basés sur les codes d'erreur, corrélation trace_id, vérifications OIDC, vérifications de politique et étapes de récupération.
weight: 4
translationKey: troubleshooting
translationStatus: pending-review
---

Lorsqu'un échange échoue, la réponse d'erreur JSON porte deux champs utiles. `code` est le code d'erreur lisible par machine qui indique quelle couche a rejeté la requête. `trace_id` corrèle la réponse à une ligne de journal serveur qui porte la raison complète. `error` est délibérément générique ; branchez sur `code`, pas sur `error`.

```json
{ "error": "forbidden", "code": "policy_denied", "trace_id": "abc-123" }
```

```bash
# Dans les journaux serveur / kubectl logs
grep abc-123 /var/log/github-sts.log
```

## Erreurs courantes

### Déploiement

| Problème | Solution |
|---|---|
| **Échec de construction Docker** avec `go.mod requires go >= X` | Mettez à jour `FROM golang:X-alpine` dans le `Dockerfile` pour correspondre à `go.mod` |
| **Échec de la vérification de santé** | Vérifiez que `GITHUBSTS_CONFIG_PATH` est défini et que le fichier existe |

### Validation OIDC

| Problème | Solution |
|---|---|
| **L'échange renvoie `401`** | En-tête `Authorization: Bearer` manquant ou malformé. Vérifiez que le workflow a réellement demandé un jeton OIDC (permission `id-token: write`). |
| **L'échange renvoie `403`** avec `code: "oidc_invalid"` | Jeton OIDC rejeté. Vérifiez l'expiration du jeton, que `oidc.allowed_issuers` inclut l'émetteur, que `kid` est présent, et consultez les journaux serveur au `trace_id`. |
| **Hôte JWKS rejeté** dans les journaux | L'hôte `jwks_uri` de l'émetteur diffère de l'hôte de l'émetteur. Ajoutez-le à `oidc.trusted_jwks_hosts` (voir [Émetteurs OIDC]({{< relref "/oidc-issuers" >}})). |

### Audience

| Problème | Solution |
|---|---|
| **L'échange renvoie `403`** avec `code: "audience_mismatch"` | L'`aud` du jeton ne correspond pas. Vérifiez que `core.getIDToken(<audience>)` dans le workflow utilise la même valeur que le champ `audience:` de la politique (et `oidc.required_audience` si configuré côté serveur). |

### Politique

| Problème | Solution |
|---|---|
| **L'échange renvoie `403`** avec `code: "app_unknown"` | `?app=` ne correspond à aucune App configurée. Vérifiez l'orthographe ou omettez-le lorsqu'une seule App est configurée. |
| **L'échange renvoie `403`** avec `code: "policy_not_found"` | Vérifiez que la politique de confiance existe à `{base_path}/{app}/{identity}.sts.yaml` dans le dépôt cible (ou le dépôt de politiques d'organisation, selon `policy_resolution`). Un chemin de fichier incorrect ou une GitHub App sans accès en lecture au fichier de politique produit la même erreur. |
| **L'échange renvoie `403`** avec `code: "policy_denied"` | La politique existe mais l'évaluation a échoué (subject, claim_pattern). Recherchez `trace_id` dans les journaux serveur pour l'écart précis. |

### Vérification de signature de bundle

Chaque échec de signature journalise un `signature_error_code` et un
`signature_operation`. Le code nomme la phase en échec, ce qui indique s'il faut
re-signer, corriger l'accès au registre ou mettre à jour un producteur.

| `signature_error_code` | Ce qui s'est passé | Que faire |
|---|---|---|
| `signature_not_found` | Le digest résolu n'a aucun référent de bundle Sigstore standardisé | Signez le digest avec cosign v3, ou vérifiez que le digest résolu est bien celui attendu. Un bundle ne portant qu'un tag historique `sha256-<digest>.sig` aboutit ici |
| `discovery_failed` | La liste des référents a échoué : refus, limite de débit, délai dépassé ou erreur serveur | Corrigez l'accès au registre pour les identifiants de téléchargement. Ce cas n'est délibérément pas signalé comme signature absente, car le registre n'a rien indiqué |
| `unsupported_signature_format` | Un référent de signature existe mais utilise le format transitoire OCI 1.1, ou une version de bundle Sigstore que cette version ne sait pas vérifier | Re-signez avec les valeurs par défaut de cosign v3. Le bundle est signé, mais pas dans un format lu par cette version |
| `malformed_signature` | Un référent de signature existe mais n'a pu être récupéré ni analysé, ou il désigne un autre digest sujet | Re-signez le bundle. Une divergence de sujet signifie que la signature appartient à un autre contenu |
| `predicate_mismatch` | Une attestation est cryptographiquement valide mais n'est pas une signature d'image cosign | Le digest a été signé par une attestation SBOM ou de provenance plutôt qu'une signature. Utilisez `cosign sign` |
| `cryptographic_verification_failed` | La signature, l'identité du certificat, l'émetteur OIDC ou les preuves de transparence ne satisfont pas la politique de confiance | Lisez la cause encapsulée. Causes fréquentes : mauvaise clé, `certificate_identity_regexp` ne correspondant pas au workflow signataire, ou entrée Rekor manquante |
| `trust_root_unavailable` | La racine de confiance Sigstore ou la clé publique configurée n'a pu être chargée | Vérifiez l'accès sortant au miroir TUF Sigstore, ou que `public_key_ref` pointe vers un PEM lisible |

Seul le format de bundle Sigstore standardisé est vérifié. Un bundle dont la
seule signature est un tag historique `sha256-<digest>.sig` renvoie
`signature_not_found` : pour ce broker, il n'est pas signé.

### Rejeu

| Problème | Solution |
|---|---|
| **L'échange renvoie `409`** avec `code: "replay_detected"` | Le `jti` du jeton OIDC a déjà été utilisé. Obtenez un nouveau jeton. Si vous exécutez plusieurs réplicas, définissez `GITHUBSTS_JTI_BACKEND=redis`. |

### Pools d'Apps

| Problème | Solution |
|---|---|
| **L'échange renvoie `502`** avec `code: "upstream_error"` et `githubsts_app_pool_exhausted_total` en hausse pour cette App | Toutes les instances du pool de l'App ont échoué pour cette requête, pas une seule. Vérifiez individuellement les identifiants et l'installation de chaque instance : `githubsts_github_reachable{app=...,instance=...}` et les lignes de journal étiquetées `instance` autour de l'échec permettent de cibler une instance précise. |
| **Une instance n'est jamais sélectionnée (`githubsts_app_pool_selection_total{...,outcome="skipped_unreachable"}` en hausse pour elle)** | La sonde d'accessibilité signale actuellement cette instance comme en panne. Vérifiez que ses identifiants et son installation de GitHub App sont toujours valides ; une clé révoquée ou mal configurée ressemble, du point de vue du pool, à une partition réseau. |
| **`rotation.strategy: rate_limit_aware` ne change pas la sélection d'instance** | Attendu dans cette version : `rate_limit_aware` est accepté en configuration mais pas encore implémenté ; le pool se comporte comme `round_robin`. Vérifiez le journal de démarrage pour l'avertissement `rotation.strategy=rate_limit_aware is configured but this build does not yet implement...`. Voir [Configuration]({{< relref "/reference/configuration#pools-dapps-rotation-multi-instances-pour-la-limite-de-débit" >}}). |
| **Journal de démarrage : `app_id N is used by more than one logical app`** | Un avertissement, pas une erreur : les pools de deux Apps logiques partagent le même `app_id`, donc elles partagent un même quota de limite de débit GitHub. Autorisé, mais vérifiez qu'il s'agit d'une intention et non d'un bloc d'instance copié-collé par erreur. |

### Amont et audit

| Problème | Solution |
|---|---|
| **L'échange renvoie `502`** avec `code: "upstream_error"` | Échec de la récupération de politique ou de l'émission du jeton GitHub. Vérifiez la métrique `githubsts_github_reachable` et les journaux serveur au `trace_id`. |
| **Événements d'audit abandonnés** (`githubsts_audit_events_dropped_total` en hausse) | Le puits d'audit ne suit pas. Augmentez `GITHUBSTS_AUDIT_BUFFER_SIZE`, assurez-vous que le chemin du journal d'audit est accessible en écriture, ou accélérez le consommateur d'audit. |

## Déboguer un échange de bout en bout

1. **Obtenez un jeton OIDC** auprès de votre fournisseur d'identité. Dans GitHub Actions, demandez-en un avec `id-token: write` et `core.getIDToken()` :

   ```bash
   # Dans une étape de workflow qui a id-token: write
   #   const token = await core.getIDToken('https://sts.example.com')
   # Ou, hors d'un workflow, utilisez la CLI de votre fournisseur (par ex. gcloud auth print-identity-token).
   export OIDC_TOKEN="<le jeton>"
   ```

2. **Définissez `GITHUBSTS_SERVER_LOG_LEVEL=debug`** temporairement. Chaque échange journalise le pipeline de validation à ce niveau.
3. **Décodez le jeton OIDC** localement pour confirmer `iss`, `sub`, `aud` et toute revendication personnalisée :
   ```bash
   echo "$OIDC_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
   ```
4. **Lisez la politique de confiance** que le serveur charge :
   ```bash
   gh api repos/myorg/myrepo/contents/.github/sts/default/ci.sts.yaml \
     --jq .content | base64 -d
   ```
5. **Comparez les revendications à la politique ligne par ligne :**
   - `policy.issuer == token.iss` (correspondance exacte)
   - `policy.subject == token.sub` (ou la regex `subject_pattern` correspond à `token.sub`)
   - `policy.audience == token.aud` (et `oidc.required_audience` si défini)
   - Chaque regex `claim_pattern[k]` correspond à `token[k]`

## Où chercher ensuite

- [Référence API]({{< relref "/reference/api#error-responses" >}}) : tableau complet des codes d'erreur.
- [Configuration]({{< relref "/reference/configuration" >}}) : chaque réglage YAML/d'environnement.
- [Émetteurs OIDC]({{< relref "/oidc-issuers" >}}) : configuration émetteur/JWKS par fournisseur.
- [Architecture]({{< relref "/concepts/architecture#authorization-pipeline" >}}) : ordre exact des vérifications.
- Ouvrir une issue : <https://github.com/Depthmark/github-sts/issues>
