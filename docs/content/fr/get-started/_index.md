---
title: Démarrage
translationKey: get-started
weight: 1
translationStatus: pending-review
---

Quatre étapes pour passer de rien à un premier échange de jeton fonctionnel, en environ quinze minutes.

1. [Configurer une GitHub App](configure-github-app/) : créez l'App, définissez ses permissions, générez une clé privée.
2. [Installer l'App](install-the-app/) : installez-la sur l'organisation ou les dépôts que les jetons doivent toucher.
3. [Générer un jeton](generate-a-token/) : écrivez une politique de confiance et appelez `/sts/exchange`.
4. [Surveiller l'utilisation](../integrations/monitor-usage/) : consultez les métriques et le journal d'audit pour confirmer ce qui a été émis.

Le [démarrage rapide (local)](quickstart-local/) exécute github-sts sur votre propre machine avec des réglages choisis pour la rapidité de mise en place. Pour un déploiement réel, voir [le démarrage rapide du chart Helm]({{< relref "/integrations/helm-chart/quickstart" >}}) et [Kubernetes](../operations/kubernetes/).
