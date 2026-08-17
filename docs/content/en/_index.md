---
title: github-sts
description: Exchange OIDC tokens for short-lived, scoped GitHub installation tokens. No PATs. No long-lived secrets.
translationKey: home
---

<section class="gg-hero">
  <div class="gg-hero__badges">
    <span class="gg-badge gg-badge--security">Go</span>
    <span class="gg-badge gg-badge--core">OIDC</span>
    <span class="gg-badge gg-badge--suite">Zero-Trust</span>
  </div>
  <h1 class="gg-hero__title">Short-lived GitHub tokens.<br>No stored secrets.</h1>
  <p class="gg-hero__subtitle">Exchange an OIDC token for a scoped, short-lived GitHub installation token. No PATs, no long-lived credentials to rotate or leak.</p>
  <div class="gg-hero__actions">
    <a class="gg-btn gg-btn--primary" href="get-started/quickstart-local/">Kickstart in 15 minutes →</a>
    <a class="gg-btn gg-btn--secondary" href="https://github.com/Depthmark/github-sts">View on GitHub</a>
  </div>
  <p class="gg-hero__shields">
    <a href="https://github.com/Depthmark/github-sts/blob/main/LICENSE"><img src="https://img.shields.io/github/license/Depthmark/github-sts?style=flat-square" alt="License"></a>
    <a href="https://pkg.go.dev/github.com/depthmark/github-sts"><img src="https://img.shields.io/badge/Go-1.26+-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go"></a>
    <a href="https://scorecard.dev/viewer/?uri=github.com/Depthmark/github-sts"><img src="https://api.scorecard.dev/projects/github.com/Depthmark/github-sts/badge" alt="OpenSSF Scorecard"></a>
  </p>
</section>

<section class="gg-section gg-section--band">
  <div class="gg-eyebrow">Get started</div>
  <h2 class="gg-section__title">From zero to your first token exchange</h2>
  <div class="gg-steps">
    <div class="gg-step">
      <div class="gg-step__num">1</div>
      <div class="gg-step__title">Configure a GitHub App</div>
      <div class="gg-step__desc">Create the App, set permissions, generate a private key.</div>
    </div>
    <div class="gg-step">
      <div class="gg-step__num">2</div>
      <div class="gg-step__title">Install the App</div>
      <div class="gg-step__desc">Install on the org or repos the token should ever touch.</div>
    </div>
    <div class="gg-step">
      <div class="gg-step__num">3</div>
      <div class="gg-step__title">Generate a token</div>
      <div class="gg-step__desc">Write a trust policy, call <code>/sts/exchange</code> with an OIDC token.</div>
    </div>
    <div class="gg-step">
      <div class="gg-step__num">4</div>
      <div class="gg-step__title">Monitor usage</div>
      <div class="gg-step__desc">Watch Prometheus metrics and audit logs for exchanges.</div>
    </div>
  </div>
</section>

<section class="gg-section">
  <h2 class="gg-section__title">Why github-sts</h2>
  <div class="gg-features">
    <div class="gg-feature">
      <div class="gg-feature__tag gg-feature__tag--core">Zero-trust</div>
      <div class="gg-feature__title">OIDC Federation</div>
      <div class="gg-feature__desc">No stored credentials, identity verified via OIDC JWT validation.</div>
    </div>
    <div class="gg-feature">
      <div class="gg-feature__tag gg-feature__tag--security">Least-privilege</div>
      <div class="gg-feature__title">Policy-based Scoping</div>
      <div class="gg-feature__desc">YAML trust policies define exact permissions per workload identity.</div>
    </div>
    <div class="gg-feature">
      <div class="gg-feature__tag gg-feature__tag--suite">Multi-app</div>
      <div class="gg-feature__title">Multiple GitHub Apps</div>
      <div class="gg-feature__desc">Route different workloads through different GitHub Apps.</div>
    </div>
  </div>
</section>

<footer class="gg-landing__footer">
  <span>© 2026 Depthmark · MIT License</span>
  <span>Part of the Depthmark GitHub Governance family</span>
</footer>
