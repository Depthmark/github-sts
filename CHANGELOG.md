# Changelog

## [0.1.2](https://github.com/Depthmark/github-sts/compare/v0.1.1...v0.1.2) (2026-09-12)


### ✨ Features

* add child span for tracing token exchange ([#88](https://github.com/Depthmark/github-sts/issues/88)) ([b167290](https://github.com/Depthmark/github-sts/commit/b167290dc9ad7fc66da7caeff8e4cebdd14667be))


### 📦 Dependencies

* **deps:** bump actions/deploy-pages from 5.0.0 to 5.0.1 in the github-actions-dependencies group ([#87](https://github.com/Depthmark/github-sts/issues/87)) ([d3a4288](https://github.com/Depthmark/github-sts/commit/d3a4288d02ec82f3e9691ac869eaed95b102df9b))
* **deps:** bump chainguard/go from `ebb11e4` to `9168db8` in the docker-dependencies group ([#85](https://github.com/Depthmark/github-sts/issues/85)) ([a26f4c9](https://github.com/Depthmark/github-sts/commit/a26f4c9acf98e3f45f9ae3eaedb0148cfc36ce93))
* **deps:** bump the golang-dependencies group across 1 directory with 12 updates ([#90](https://github.com/Depthmark/github-sts/issues/90)) ([cf3a826](https://github.com/Depthmark/github-sts/commit/cf3a826f0be402f3c6984f9ca9d8c2e0cec7a0e3))

## [0.1.1](https://github.com/Depthmark/github-sts/compare/v0.1.0...v0.1.1) (2026-09-07)


### ⚠ BREAKING CHANGES

* add otel endpoint streaming support ([#77](https://github.com/Depthmark/github-sts/issues/77))

### ✨ Features

* add artifacthub.io link with metadata ([#80](https://github.com/Depthmark/github-sts/issues/80)) ([92eb04c](https://github.com/Depthmark/github-sts/commit/92eb04c21dac6d0e344fe08a12ca61c9bf3e5da0))
* add auth on the health endpoint ([#59](https://github.com/Depthmark/github-sts/issues/59)) ([6b6c898](https://github.com/Depthmark/github-sts/commit/6b6c8983e6fbf4d0fb3105f01bfde36700017853))
* add auth on the prometheus endpoint ([#56](https://github.com/Depthmark/github-sts/issues/56)) ([d698ce1](https://github.com/Depthmark/github-sts/commit/d698ce1714d36293b7dded817f4685ebb11a23e4))
* add codeql workflow ([#44](https://github.com/Depthmark/github-sts/issues/44)) ([6200998](https://github.com/Depthmark/github-sts/commit/62009980a87a7be22de70322aa4ae0ac4cc620d8))
* add expires_in in response payload during the token generation ([#68](https://github.com/Depthmark/github-sts/issues/68)) ([2f68f6d](https://github.com/Depthmark/github-sts/commit/2f68f6d236e40f74abf2b69f85e1b363583f58c5))
* add github-page documentation ([#38](https://github.com/Depthmark/github-sts/issues/38)) ([d54aaed](https://github.com/Depthmark/github-sts/commit/d54aaed0b2d7738c0cb7cce71a2e306260852469))
* add oidc issuer and kid restriction ([b5f568f](https://github.com/Depthmark/github-sts/commit/b5f568fc0e10b4493ce3c6c93946d829d0e3c0cd))
* add otel endpoint streaming support ([#77](https://github.com/Depthmark/github-sts/issues/77)) ([400a422](https://github.com/Depthmark/github-sts/commit/400a4225ced7ce2646d35d2f51978d5ad6db4ddd))
* add releasing of the go pkg ([#81](https://github.com/Depthmark/github-sts/issues/81)) ([4f608ab](https://github.com/Depthmark/github-sts/commit/4f608ab280bf92784eaad7a4bb56fe663f1040ed))
* add schema validation endpoint for the created identities ([#73](https://github.com/Depthmark/github-sts/issues/73)) ([549a745](https://github.com/Depthmark/github-sts/commit/549a745f672c71a391f09c91fc451d19959d08a1))
* add support for audience validation on the broker ([#20](https://github.com/Depthmark/github-sts/issues/20)) ([992ecb5](https://github.com/Depthmark/github-sts/commit/992ecb5d32aeddfbfe8ead2653f5dbf8bcce3034))
* add the capability to request less permissive token ([#72](https://github.com/Depthmark/github-sts/issues/72)) ([3292e4c](https://github.com/Depthmark/github-sts/commit/3292e4c30e82b64e3b573c70ef5ddac454261386))
* add TLS support and mTLS support on the application level, inst… ([#48](https://github.com/Depthmark/github-sts/issues/48)) ([deb1da3](https://github.com/Depthmark/github-sts/commit/deb1da36830b6e92aa0588ce7cd7fc4a14ba1f04))
* improve layout of the GitHub Page ([#49](https://github.com/Depthmark/github-sts/issues/49)) ([2844390](https://github.com/Depthmark/github-sts/commit/2844390680b8dbc480ab1ac5574f62890b7c155a))
* initial commit for the release of github-sts ([16b4a26](https://github.com/Depthmark/github-sts/commit/16b4a26fd13f6a31b68472d5d26175b24591aec7))
* initial commit for the release of github-sts ([034fe9d](https://github.com/Depthmark/github-sts/commit/034fe9d17e73aba8d076f6057850aa3e0e5ef647))
* load id policy from org level for repo scope ([#12](https://github.com/Depthmark/github-sts/issues/12)) ([0220557](https://github.com/Depthmark/github-sts/commit/02205576ce04fad4755527061c469527baf72237))
* performance optimization to improve JWT and GitHub API calls ([02900a2](https://github.com/Depthmark/github-sts/commit/02900a2f895de93d035cdbd5a63a69a3b4d8230e))
* performance optimization to improve JWT and GitHub API calls ([6bfd64d](https://github.com/Depthmark/github-sts/commit/6bfd64d3fe7a842832360f350556bd77e43308d6))
* record trust policy provenance in audit events ([#71](https://github.com/Depthmark/github-sts/issues/71)) ([91cec90](https://github.com/Depthmark/github-sts/commit/91cec9012649d32827c6baea923afb0a776d3eb0))
* support multiple instances of an app ([#52](https://github.com/Depthmark/github-sts/issues/52)) ([b450f00](https://github.com/Depthmark/github-sts/commit/b450f000c533f111e439401b74f0e57cf7d26bdd))
* support policies enforcement on identities ([#28](https://github.com/Depthmark/github-sts/issues/28)) ([93a93c0](https://github.com/Depthmark/github-sts/commit/93a93c0c5821d9e8d7a4cd84eaeb5b97162e7c3b))
* use latest cosign version v3+ for bundle validation ([#65](https://github.com/Depthmark/github-sts/issues/65)) ([a938c5c](https://github.com/Depthmark/github-sts/commit/a938c5c009d93c0eb32a75fa40b7242f0339cb50))


### 🐛 Bug Fixes

* add missing golang install for github page deployment ([#40](https://github.com/Depthmark/github-sts/issues/40)) ([5a94230](https://github.com/Depthmark/github-sts/commit/5a94230a8cdd20b3c771584f8a1fd530b7fa5acc))
* image not rendering in the README ([#46](https://github.com/Depthmark/github-sts/issues/46)) ([9a5d542](https://github.com/Depthmark/github-sts/commit/9a5d5422817de63bf7359fa2b8c960b5bb128f67))
* one app impact an other ([9b76f87](https://github.com/Depthmark/github-sts/commit/9b76f87286a28134e10506e45081efe4c209f2dd))
* order of codeql and go inssetups ([#45](https://github.com/Depthmark/github-sts/issues/45)) ([2286de3](https://github.com/Depthmark/github-sts/commit/2286de37cd2016045676ce32c5b836131f7cf20b))
* otlp version ([#79](https://github.com/Depthmark/github-sts/issues/79)) ([b77fed3](https://github.com/Depthmark/github-sts/commit/b77fed31e5f85ee6e553d125be40920d2dde6072))
* release please manifest and changelog ([#64](https://github.com/Depthmark/github-sts/issues/64)) ([20ecc96](https://github.com/Depthmark/github-sts/commit/20ecc96fefd549e1f7dc81f751e95dab12b80e32))
* remove labels collissions between application and kubernetes sta… ([#70](https://github.com/Depthmark/github-sts/issues/70)) ([d6a89f4](https://github.com/Depthmark/github-sts/commit/d6a89f47d18389313a8c84ffe768d4429095d0ad))
* remove permissions in workflows from top level ([#47](https://github.com/Depthmark/github-sts/issues/47)) ([cddb301](https://github.com/Depthmark/github-sts/commit/cddb3016960447732255dda3e7f39ea7a24ae328))


### 📦 Dependencies

* **deps:** bump actions/labeler from 6.0.1 to 6.1.0 in the github-actions-dependencies group ([#25](https://github.com/Depthmark/github-sts/issues/25)) ([60271a8](https://github.com/Depthmark/github-sts/commit/60271a8506a235f71e604745636703ee300e8236))
* **deps:** bump actions/labeler from 6.1.0 to 6.2.0 in the github-actions-dependencies group ([#31](https://github.com/Depthmark/github-sts/issues/31)) ([f922a7b](https://github.com/Depthmark/github-sts/commit/f922a7b5098e7d22f7f6b02aa4aa3213d4473890))
* **deps:** bump actions/labeler from 6.2.0 to 7.0.0 in the github-actions-dependencies group ([#35](https://github.com/Depthmark/github-sts/issues/35)) ([a2fd393](https://github.com/Depthmark/github-sts/commit/a2fd393f12c0ba34133ae4c9ee52ffcdda98fd39))
* **deps:** bump chainguard/go from `1510daf` to `ece9523` in the docker-dependencies group ([#24](https://github.com/Depthmark/github-sts/issues/24)) ([a68f0d8](https://github.com/Depthmark/github-sts/commit/a68f0d859c6a67bcc2107f2a8b0377b093b96135))
* **deps:** bump chainguard/static from `24dd7ff` to `f68e3a8` in the docker-dependencies group ([#53](https://github.com/Depthmark/github-sts/issues/53)) ([63c35f3](https://github.com/Depthmark/github-sts/commit/63c35f364c326e68b9dd0ff7cc54006f479b0dca))
* **deps:** bump chainguard/static from `399c8cb` to `24dd7ff` in the docker-dependencies group ([#36](https://github.com/Depthmark/github-sts/issues/36)) ([2e217ea](https://github.com/Depthmark/github-sts/commit/2e217eaa6a66ac33d46c3396ee68052a7e6919de))
* **deps:** bump github.com/redis/go-redis/v9 ([614a4b4](https://github.com/Depthmark/github-sts/commit/614a4b456bf9a4f34c71b5f262368fa26f9e6810))
* **deps:** bump github.com/redis/go-redis/v9 from 9.18.0 to 9.19.0 in the golang-dependencies group ([6d233c3](https://github.com/Depthmark/github-sts/commit/6d233c317b7842a67dcc94fa3284715e2cb829dd))
* **deps:** bump github.com/sigstore/sigstore-go from 1.2.0 to 1.2.1 ([#55](https://github.com/Depthmark/github-sts/issues/55)) ([b74d0e5](https://github.com/Depthmark/github-sts/commit/b74d0e56c47f5dc8fc5a2b95b27187d40d94017c))
* **deps:** bump google.golang.org/grpc from 1.82.1 to 1.83.1 ([#78](https://github.com/Depthmark/github-sts/issues/78)) ([bd4c45f](https://github.com/Depthmark/github-sts/commit/bd4c45fd8852e666762ac4a18090e8547983e8eb))
* **deps:** bump googleapis/release-please-action ([99cc935](https://github.com/Depthmark/github-sts/commit/99cc93593fc5e1a1e8c46c281ebc615ffdd5cbc4))
* **deps:** bump googleapis/release-please-action from 4.4.1 to 5.0.0 in the github-actions-dependencies group ([e6e793a](https://github.com/Depthmark/github-sts/commit/e6e793a82b7ff91f298c6f1f80611de16b926dcf))
* **deps:** bump the docker-dependencies group across 1 directory with 2 updates ([#30](https://github.com/Depthmark/github-sts/issues/30)) ([cffeb5b](https://github.com/Depthmark/github-sts/commit/cffeb5b89bbfbfa065851688c85fe757b83288d8))
* **deps:** bump the docker-dependencies group with 2 updates ([#33](https://github.com/Depthmark/github-sts/issues/33)) ([7995e35](https://github.com/Depthmark/github-sts/commit/7995e3572c61904ae9012ce96f440fabfc37b7bf))
* **deps:** bump the docker-dependencies group with 2 updates ([#74](https://github.com/Depthmark/github-sts/issues/74)) ([87924a8](https://github.com/Depthmark/github-sts/commit/87924a8d2353285a947b02b35f0668b4e4e799c3))
* **deps:** bump the github-actions-dependencies group across 1 directory with 2 updates ([73312bf](https://github.com/Depthmark/github-sts/commit/73312bf3691c398880b0fe0038d6e64beeeaf796))
* **deps:** bump the github-actions-dependencies group across 1 directory with 2 updates ([7d4fd13](https://github.com/Depthmark/github-sts/commit/7d4fd139dac7f18abd54e0677ea101cc8c71b572))
* **deps:** bump the github-actions-dependencies group with 2 updates ([#76](https://github.com/Depthmark/github-sts/issues/76)) ([cd4ff89](https://github.com/Depthmark/github-sts/commit/cd4ff89d0872f43147434b6a6f74a1e26cdf852a))
* **deps:** bump the github-actions-dependencies group with 3 updates ([99bc20d](https://github.com/Depthmark/github-sts/commit/99bc20dadd4ab9df75455d788779ea6a3435d47d))
* **deps:** bump the github-actions-dependencies group with 3 updates ([ec33241](https://github.com/Depthmark/github-sts/commit/ec33241a4f3390cd2152b3ebd8e51bf4fc7f09f3))
* **deps:** bump the github-actions-dependencies group with 4 updates ([3508e84](https://github.com/Depthmark/github-sts/commit/3508e8497bc78c9e475d78b2049795aed15d298b))
* **deps:** bump the github-actions-dependencies group with 4 updates ([f5900c1](https://github.com/Depthmark/github-sts/commit/f5900c126eb66548c7e1e48be277819f631a3058))
* **deps:** bump the github-actions-dependencies group with 4 updates ([#61](https://github.com/Depthmark/github-sts/issues/61)) ([78069e3](https://github.com/Depthmark/github-sts/commit/78069e3b0c3798eb0e944e35c59f350207d44a41))
* **deps:** bump the github-actions-dependencies group with 6 updates ([#54](https://github.com/Depthmark/github-sts/issues/54)) ([0d30154](https://github.com/Depthmark/github-sts/commit/0d30154c307e3f92169a6945a182c45d147b01ce))
* **deps:** bump the golang-dependencies group across 1 directory with 3 updates ([#32](https://github.com/Depthmark/github-sts/issues/32)) ([47f007b](https://github.com/Depthmark/github-sts/commit/47f007b21629813f66bb9dea5c40cc9d4bf282b9))
* **deps:** bump the golang-dependencies group across 1 directory with 4 updates ([#75](https://github.com/Depthmark/github-sts/issues/75)) ([817b7e4](https://github.com/Depthmark/github-sts/commit/817b7e47f4088d3e35fcba02e8a62e54da6a7f68))
* **deps:** bump the golang-dependencies group across 1 directory with 7 updates ([#50](https://github.com/Depthmark/github-sts/issues/50)) ([aa16e0d](https://github.com/Depthmark/github-sts/commit/aa16e0d687048a6e6d2346a4ac03e28271444265))

## [0.1.0](https://github.com/Depthmark/github-sts/compare/v0.0.4...v0.1.0) (2026-09-07)


### ⚠ BREAKING CHANGES

* add otel endpoint streaming support ([#77](https://github.com/Depthmark/github-sts/issues/77))

### Features

* add artifacthub.io link with metadata ([#80](https://github.com/Depthmark/github-sts/issues/80)) ([92eb04c](https://github.com/Depthmark/github-sts/commit/92eb04c21dac6d0e344fe08a12ca61c9bf3e5da0))
* add auth on the health endpoint ([#59](https://github.com/Depthmark/github-sts/issues/59)) ([6b6c898](https://github.com/Depthmark/github-sts/commit/6b6c8983e6fbf4d0fb3105f01bfde36700017853))
* add auth on the prometheus endpoint ([#56](https://github.com/Depthmark/github-sts/issues/56)) ([d698ce1](https://github.com/Depthmark/github-sts/commit/d698ce1714d36293b7dded817f4685ebb11a23e4))
* add expires_in in response payload during the token generation ([#68](https://github.com/Depthmark/github-sts/issues/68)) ([2f68f6d](https://github.com/Depthmark/github-sts/commit/2f68f6d236e40f74abf2b69f85e1b363583f58c5))
* add otel endpoint streaming support ([#77](https://github.com/Depthmark/github-sts/issues/77)) ([400a422](https://github.com/Depthmark/github-sts/commit/400a4225ced7ce2646d35d2f51978d5ad6db4ddd))
* add releasing of the go pkg ([#81](https://github.com/Depthmark/github-sts/issues/81)) ([4f608ab](https://github.com/Depthmark/github-sts/commit/4f608ab280bf92784eaad7a4bb56fe663f1040ed))
* add schema validation endpoint for the created identities ([#73](https://github.com/Depthmark/github-sts/issues/73)) ([549a745](https://github.com/Depthmark/github-sts/commit/549a745f672c71a391f09c91fc451d19959d08a1))
* add the capability to request less permissive token ([#72](https://github.com/Depthmark/github-sts/issues/72)) ([3292e4c](https://github.com/Depthmark/github-sts/commit/3292e4c30e82b64e3b573c70ef5ddac454261386))
* record trust policy provenance in audit events ([#71](https://github.com/Depthmark/github-sts/issues/71)) ([91cec90](https://github.com/Depthmark/github-sts/commit/91cec9012649d32827c6baea923afb0a776d3eb0))
* support multiple instances of an app ([#52](https://github.com/Depthmark/github-sts/issues/52)) ([b450f00](https://github.com/Depthmark/github-sts/commit/b450f000c533f111e439401b74f0e57cf7d26bdd))
* use latest cosign version v3+ for bundle validation ([#65](https://github.com/Depthmark/github-sts/issues/65)) ([a938c5c](https://github.com/Depthmark/github-sts/commit/a938c5c009d93c0eb32a75fa40b7242f0339cb50))


### Bug Fixes

* otlp version ([#79](https://github.com/Depthmark/github-sts/issues/79)) ([b77fed3](https://github.com/Depthmark/github-sts/commit/b77fed31e5f85ee6e553d125be40920d2dde6072))
* release please manifest and changelog ([#64](https://github.com/Depthmark/github-sts/issues/64)) ([20ecc96](https://github.com/Depthmark/github-sts/commit/20ecc96fefd549e1f7dc81f751e95dab12b80e32))
* remove labels collissions between application and kubernetes sta… ([#70](https://github.com/Depthmark/github-sts/issues/70)) ([d6a89f4](https://github.com/Depthmark/github-sts/commit/d6a89f47d18389313a8c84ffe768d4429095d0ad))

## [0.0.4](https://github.com/Depthmark/github-sts/compare/v0.0.3...v0.0.4) (2026-08-21)


### Features

* add codeql workflow ([#44](https://github.com/Depthmark/github-sts/issues/44)) ([6200998](https://github.com/Depthmark/github-sts/commit/62009980a87a7be22de70322aa4ae0ac4cc620d8))
* add github-page documentation ([#38](https://github.com/Depthmark/github-sts/issues/38)) ([d54aaed](https://github.com/Depthmark/github-sts/commit/d54aaed0b2d7738c0cb7cce71a2e306260852469))
* add TLS support and mTLS support on the application level, inst… ([#48](https://github.com/Depthmark/github-sts/issues/48)) ([deb1da3](https://github.com/Depthmark/github-sts/commit/deb1da36830b6e92aa0588ce7cd7fc4a14ba1f04))
* improve layout of the GitHub Page ([#49](https://github.com/Depthmark/github-sts/issues/49)) ([2844390](https://github.com/Depthmark/github-sts/commit/2844390680b8dbc480ab1ac5574f62890b7c155a))
* support policies enforcement on identities ([#28](https://github.com/Depthmark/github-sts/issues/28)) ([93a93c0](https://github.com/Depthmark/github-sts/commit/93a93c0c5821d9e8d7a4cd84eaeb5b97162e7c3b))


### Bug Fixes

* add missing golang install for github page deployment ([#40](https://github.com/Depthmark/github-sts/issues/40)) ([5a94230](https://github.com/Depthmark/github-sts/commit/5a94230a8cdd20b3c771584f8a1fd530b7fa5acc))
* image not rendering in the README ([#46](https://github.com/Depthmark/github-sts/issues/46)) ([9a5d542](https://github.com/Depthmark/github-sts/commit/9a5d5422817de63bf7359fa2b8c960b5bb128f67))
* order of codeql and go inssetups ([#45](https://github.com/Depthmark/github-sts/issues/45)) ([2286de3](https://github.com/Depthmark/github-sts/commit/2286de37cd2016045676ce32c5b836131f7cf20b))
* remove permissions in workflows from top level ([#47](https://github.com/Depthmark/github-sts/issues/47)) ([cddb301](https://github.com/Depthmark/github-sts/commit/cddb3016960447732255dda3e7f39ea7a24ae328))

## [0.0.3](https://github.com/Depthmark/github-sts/compare/v0.0.2...v0.0.3) (2026-05-02)


### Features

* add oidc issuer and kid restriction ([b5f568f](https://github.com/Depthmark/github-sts/commit/b5f568fc0e10b4493ce3c6c93946d829d0e3c0cd))
* add support for audience validation on the broker ([#20](https://github.com/Depthmark/github-sts/issues/20)) ([992ecb5](https://github.com/Depthmark/github-sts/commit/992ecb5d32aeddfbfe8ead2653f5dbf8bcce3034))
* load id policy from org level for repo scope ([#12](https://github.com/Depthmark/github-sts/issues/12)) ([0220557](https://github.com/Depthmark/github-sts/commit/02205576ce04fad4755527061c469527baf72237))
* performance optimization to improve JWT and GitHub API calls ([02900a2](https://github.com/Depthmark/github-sts/commit/02900a2f895de93d035cdbd5a63a69a3b4d8230e))
* performance optimization to improve JWT and GitHub API calls ([6bfd64d](https://github.com/Depthmark/github-sts/commit/6bfd64d3fe7a842832360f350556bd77e43308d6))

## [0.0.2](https://github.com/Depthmark/github-sts/compare/v0.0.1...v0.0.2) (2026-04-01)


### Features

* initial commit for the release of github-sts ([16b4a26](https://github.com/Depthmark/github-sts/commit/16b4a26fd13f6a31b68472d5d26175b24591aec7))
* initial commit for the release of github-sts ([034fe9d](https://github.com/Depthmark/github-sts/commit/034fe9d17e73aba8d076f6057850aa3e0e5ef647))


### Bug Fixes

* one app impact an other ([9b76f87](https://github.com/Depthmark/github-sts/commit/9b76f87286a28134e10506e45081efe4c209f2dd))

## Changelog
