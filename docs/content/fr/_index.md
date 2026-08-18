---
title: github-sts
description: Échangez des jetons OIDC pour des jetons d'installation GitHub temporaires et limités. Sans PAT. Sans secrets persistants.
translationKey: home
translationStatus: pending-review
---

<section class="gg-hero">
  <div class="gg-hero__badges">
    <span class="gg-badge gg-badge--security">Go</span>
    <span class="gg-badge gg-badge--core">OIDC</span>
    <span class="gg-badge gg-badge--suite">Zero-Trust</span>
  </div>
  <h1 class="gg-hero__title">Des jetons GitHub temporaires.<br>Aucun secret stocké.</h1>
  <p class="gg-hero__subtitle">Échangez un jeton OIDC contre un jeton d'installation GitHub limité et temporaire. Sans PAT, sans identifiants persistants à faire tourner ou à divulguer.</p>
  <div class="gg-hero__actions">
    <a class="gg-btn gg-btn--primary" href="get-started/quickstart-local/">Démarrer en 15 minutes →</a>
    <a class="gg-btn gg-btn--secondary" href="https://github.com/Depthmark/github-sts">Voir sur GitHub</a>
  </div>
  <p class="gg-hero__shields">
    <a href="https://github.com/Depthmark/github-sts/blob/main/LICENSE"><img src="https://img.shields.io/github/license/Depthmark/github-sts?style=flat-square" alt="Licence"></a>
    <a href="https://pkg.go.dev/github.com/depthmark/github-sts"><img src="https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go"></a>
    <a href="https://scorecard.dev/viewer/?uri=github.com/Depthmark/github-sts"><img src="https://api.scorecard.dev/projects/github.com/Depthmark/github-sts/badge" alt="Score OpenSSF"></a>
  </p>
</section>

<section class="gg-section gg-section--band">
  <div class="gg-eyebrow">Démarrage</div>
  <h2 class="gg-section__title">De zéro à votre premier échange de jeton</h2>
  <div class="gg-steps">
    <div class="gg-step">
      <div class="gg-step__num">1</div>
      <div class="gg-step__title">Configurer une GitHub App</div>
      <div class="gg-step__desc">Créez l'App, définissez ses permissions, générez une clé privée.</div>
    </div>
    <div class="gg-step">
      <div class="gg-step__num">2</div>
      <div class="gg-step__title">Installer l'App</div>
      <div class="gg-step__desc">Installez-la sur l'organisation ou les dépôts que le jeton doit toucher.</div>
    </div>
    <div class="gg-step">
      <div class="gg-step__num">3</div>
      <div class="gg-step__title">Générer un jeton</div>
      <div class="gg-step__desc">Écrivez une politique de confiance, appelez <code>/sts/exchange</code> avec un jeton OIDC.</div>
    </div>
    <div class="gg-step">
      <div class="gg-step__num">4</div>
      <div class="gg-step__title">Surveiller l'utilisation</div>
      <div class="gg-step__desc">Consultez les métriques Prometheus et le journal d'audit des échanges.</div>
    </div>
  </div>
</section>

<section class="gg-section">
  <h2 class="gg-section__title">Pourquoi github-sts</h2>
  <div class="gg-features">
    <div class="gg-feature">
      <div class="gg-feature__tag gg-feature__tag--core">Zero-trust</div>
      <div class="gg-feature__title">Fédération OIDC</div>
      <div class="gg-feature__desc">Aucune donnée d'identification stockée, identité vérifiée par validation JWT OIDC.</div>
    </div>
    <div class="gg-feature">
      <div class="gg-feature__tag gg-feature__tag--security">Privilège minimal</div>
      <div class="gg-feature__title">Portée basée sur les politiques</div>
      <div class="gg-feature__desc">Des politiques de confiance YAML définissent des autorisations exactes par identité de charge de travail.</div>
    </div>
    <div class="gg-feature">
      <div class="gg-feature__tag gg-feature__tag--suite">Multi-app</div>
      <div class="gg-feature__title">Plusieurs GitHub Apps</div>
      <div class="gg-feature__desc">Aiguillez différentes charges de travail via différentes GitHub Apps.</div>
    </div>
  </div>
</section>

<footer class="gg-landing__footer">
  <span>© 2026 Depthmark · Licence MIT</span>
  <span>Fait partie de la famille Depthmark GitHub Governance</span>
</footer>
