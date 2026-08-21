---
title: Tester TLS et mTLS localement
description: Guide étape par étape pour générer une PKI locale et tester HTTPS et mTLS contre une instance github-sts en cours d'exécution.
weight: 2
translationKey: tls-local-testing
translationStatus: pending-review
---

Ce guide explique comment créer une autorité de certification locale, signer un certificat serveur, démarrer github-sts en HTTPS, puis ajouter le TLS mutuel (mTLS) — le tout avec `openssl` et `curl`. Aucune vraie credentials GitHub App n'est nécessaire pour vérifier la couche TLS ; l'endpoint `/health` répond sans authentification.

## Prérequis

- `openssl` (toute version moderne — 1.1.1 ou 3.x)
- `curl` 7.77+ (pour le support SNI et `--cert`/`--key`)
- Toolchain Go (`go run ./cmd/github-sts`) **ou** Docker

## 1. Générer la PKI locale

Exécutez toutes les commandes depuis la racine du dépôt. Tous les fichiers sont placés dans un répertoire `certs/` à ne pas commiter.

```bash
mkdir -p certs

# --- Autorité de certification ---
openssl genrsa -out certs/ca.key 4096
openssl req -new -x509 -key certs/ca.key -out certs/ca.crt -days 365 \
  -subj "/CN=github-sts-local-ca"

# --- Certificat serveur (doit inclure SAN pour les clients TLS modernes) ---
openssl genrsa -out certs/server.key 2048
openssl req -new -key certs/server.key -out certs/server.csr \
  -subj "/CN=localhost"
openssl x509 -req -in certs/server.csr \
  -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
  -out certs/server.crt -days 365 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")

# --- Clé RSA pour la config App github-sts (n'importe quelle clé RSA valide) ---
openssl genrsa -out certs/app.key 2048
```

> `<(printf ...)` est la substitution de processus bash/zsh. Si votre shell ne la supporte pas, écrivez la ligne SAN dans un fichier temporaire et passez-le avec `-extfile /tmp/san.ext`.

## 2. Configuration minimale

Créez `certs/config-tls.yaml` :

```yaml
server:
  port: 8443
  tls:
    cert_file: ./certs/server.crt
    key_file: ./certs/server.key

apps:
  local-test:
    app_id: 1
    private_key_path: ./certs/app.key

oidc:
  allowed_issuers:
    - https://token.actions.githubusercontent.com

audit:
  file_enabled: false   # le chemin par défaut /var/log/github-sts/audit.json n'existe pas localement
```

> `app_id: 1` et la clé RSA sont des valeurs de substitution. Elles satisfont la validation de la config mais ne sont jamais utilisées quand vous n'accédez qu'à `/health`.

## 3. Démarrer le serveur et tester HTTPS

```bash
GITHUBSTS_CONFIG_PATH=certs/config-tls.yaml go run ./cmd/github-sts
```

Le journal de démarrage confirme que TLS est actif :

```
level=INFO msg="server ready" addr="0.0.0.0:8443" tls=true
```

Dans un second terminal, vérifiez HTTPS avec votre CA :

```bash
curl --cacert certs/ca.crt https://localhost:8443/health
# {"status":"ok"}

curl --cacert certs/ca.crt https://localhost:8443/ready
# {"status":"ready"}
```

Vérifiez que le serveur rejette les connexions qui ne font pas confiance à votre CA :

```bash
curl https://localhost:8443/health
# curl: (60) SSL certificate problem: unable to get local issuer certificate
```

## 4. Ajouter mTLS

### Générer un certificat client

```bash
openssl genrsa -out certs/client.key 2048
openssl req -new -key certs/client.key -out certs/client.csr \
  -subj "/CN=test-client"
openssl x509 -req -in certs/client.csr \
  -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
  -out certs/client.crt -days 365
```

### Activer mTLS dans la config

Ajoutez `client_ca_file` à `certs/config-tls.yaml` :

```yaml
server:
  port: 8443
  tls:
    cert_file: ./certs/server.crt
    key_file: ./certs/server.key
    client_ca_file: ./certs/ca.crt   # faire confiance à la même CA pour les certs clients
```

Redémarrez le serveur.

### Test : certificat client présent (doit réussir)

```bash
curl --cacert certs/ca.crt \
     --cert certs/client.crt \
     --key certs/client.key \
     https://localhost:8443/health
# {"status":"ok"}
```

### Test : certificat client absent (doit être rejeté au niveau TLS)

```bash
curl --cacert certs/ca.crt https://localhost:8443/health
# curl: (35) error:... alert handshake failure
```

La connexion est terminée pendant la poignée de main TLS — avant qu'aucun HTTP ne soit échangé.

## 5. Tester le rechargement à chaud (optionnel)

Définissez `reload_interval` dans la config et notez le numéro de série du certificat actuellement servi :

```yaml
server:
  tls:
    cert_file: ./certs/server.crt
    key_file: ./certs/server.key
    reload_interval: 5s
```

```bash
# Enregistrer le numéro de série actuel
openssl s_client -connect localhost:8443 -CAfile certs/ca.crt </dev/null 2>/dev/null \
  | openssl x509 -noout -serial
# serial=01
```

Émettez un nouveau certificat serveur vers le même fichier (le fichier de série CA `certs/ca.srl` s'incrémente automatiquement) :

```bash
openssl x509 -req -in certs/server.csr \
  -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
  -out certs/server.crt -days 365 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")
```

Attendez le prochain tick de sondage (jusqu'à `reload_interval`). Le journal du serveur affichera :

```
level=INFO msg="tls cert reloaded"
```

Confirmez que le nouveau certificat est servi :

```bash
openssl s_client -connect localhost:8443 -CAfile certs/ca.crt </dev/null 2>/dev/null \
  | openssl x509 -noout -serial
# serial=02
```

Aucune connexion n'a été interrompue et aucun redémarrage n'a été nécessaire.

## Nettoyage

```bash
rm -rf certs/
```

Le répertoire `certs/` contient votre clé privée CA. Traitez-la comme un secret : ne la commitez pas et supprimez-la quand vous avez terminé les tests.
