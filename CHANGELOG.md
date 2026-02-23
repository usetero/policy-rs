# Changelog

## [1.4.11](https://github.com/usetero/policy-rs/compare/v1.4.10...v1.4.11) (2026-02-23)


### Bug Fixes

* alphanumeric order ([#65](https://github.com/usetero/policy-rs/issues/65)) ([362ae63](https://github.com/usetero/policy-rs/commit/362ae6379d29f35e6a249de4edc267e5aba16103))
* alphanumeric sort on snapshot compilation ([#64](https://github.com/usetero/policy-rs/issues/64)) ([e6dd0ba](https://github.com/usetero/policy-rs/commit/e6dd0ba118dea0ce71168c5c5117ddffacd07174))
* implement all sampling logic ([#62](https://github.com/usetero/policy-rs/issues/62)) ([583f1a4](https://github.com/usetero/policy-rs/commit/583f1a45f543cbb96d1959dfabfd64c4384ba484))

## [1.4.10](https://github.com/usetero/policy-rs/compare/v1.4.9...v1.4.10) (2026-02-20)


### Bug Fixes

* add missing aliases ([#60](https://github.com/usetero/policy-rs/issues/60)) ([2ba206e](https://github.com/usetero/policy-rs/commit/2ba206e2d0bb3e707da085aae6c5d9965c52b834))

## [1.4.9](https://github.com/usetero/policy-rs/compare/v1.4.8...v1.4.9) (2026-02-20)


### Bug Fixes

* prevent out of bounds for percentage sampling ([#57](https://github.com/usetero/policy-rs/issues/57)) ([bccd8f2](https://github.com/usetero/policy-rs/commit/bccd8f2a2154332ac5c8a8505c123bdf4ee65363))
* support missing fields and parsing rules ([#59](https://github.com/usetero/policy-rs/issues/59)) ([588ce92](https://github.com/usetero/policy-rs/commit/588ce929ac292b4791d5bd39b6f45e15abe26320))

## [1.4.8](https://github.com/usetero/policy-rs/compare/v1.4.7...v1.4.8) (2026-02-20)


### Bug Fixes

* sampling should use otel when a trace sample key is set ([#55](https://github.com/usetero/policy-rs/issues/55)) ([bbbd90e](https://github.com/usetero/policy-rs/commit/bbbd90ef5090682d0142f1120fbbdca75c7559a3))

## [1.4.7](https://github.com/usetero/policy-rs/compare/v1.4.6...v1.4.7) (2026-02-18)


### Bug Fixes

* record misses correctly ([#53](https://github.com/usetero/policy-rs/issues/53)) ([bc88cac](https://github.com/usetero/policy-rs/commit/bc88cacea5d2d601c6f07c649fb1b82397f7c99c))

## [1.4.6](https://github.com/usetero/policy-rs/compare/v1.4.5...v1.4.6) (2026-02-18)


### Bug Fixes

* noop when field not present ([#50](https://github.com/usetero/policy-rs/issues/50)) ([4d01379](https://github.com/usetero/policy-rs/commit/4d013792ccf52352df3159affafed5343c8b5403))

## [1.4.5](https://github.com/usetero/policy-rs/compare/v1.4.4...v1.4.5) (2026-02-18)


### Bug Fixes

* add file support for transforms ([#47](https://github.com/usetero/policy-rs/issues/47)) ([8e02b0f](https://github.com/usetero/policy-rs/commit/8e02b0f39053423c0611463e9cad1320ea7a3114))

## [1.4.4](https://github.com/usetero/policy-rs/compare/v1.4.3...v1.4.4) (2026-02-18)


### Bug Fixes

* json should use proto formatting ([#46](https://github.com/usetero/policy-rs/issues/46)) ([81f7d7d](https://github.com/usetero/policy-rs/commit/81f7d7d28e1b2b5b412ff1c932b1c15aa43c9bd8))
* policy rs httpprovider does not report stats back to server ([#44](https://github.com/usetero/policy-rs/issues/44)) ([4383c21](https://github.com/usetero/policy-rs/commit/4383c2163fca978515d023affb10c04e0b2024a3))

## [1.4.3](https://github.com/usetero/policy-rs/compare/v1.4.2...v1.4.3) (2026-02-17)


### Bug Fixes

* load should be per-provider and for testing ([#42](https://github.com/usetero/policy-rs/issues/42)) ([2b0450f](https://github.com/usetero/policy-rs/commit/2b0450feae6c6f1cb3d0dcf78ecdce6eebdb91a2))

## [1.4.2](https://github.com/usetero/policy-rs/compare/v1.4.1...v1.4.2) (2026-02-16)


### Bug Fixes

* assume matcher for enum values ([#40](https://github.com/usetero/policy-rs/issues/40)) ([82822c5](https://github.com/usetero/policy-rs/commit/82822c58edecdddd11d2109fb007b317745eb277))

## [1.4.1](https://github.com/usetero/policy-rs/compare/v1.4.0...v1.4.1) (2026-02-16)


### Bug Fixes

* accept both formats ([#39](https://github.com/usetero/policy-rs/issues/39)) ([f378ffe](https://github.com/usetero/policy-rs/commit/f378ffe9bab2088c71f9fbc87f135d23d16c4dbc))
* migrate policy rs json parser to proto based format ([#37](https://github.com/usetero/policy-rs/issues/37)) ([9eb5e4b](https://github.com/usetero/policy-rs/commit/9eb5e4b1140f1e06b7a11a3f5741a21e299b92ad))

## [1.4.0](https://github.com/usetero/policy-rs/compare/v1.3.0...v1.4.0) (2026-02-11)


### Features

* metric support ([#33](https://github.com/usetero/policy-rs/issues/33)) ([cb3e41e](https://github.com/usetero/policy-rs/commit/cb3e41e5b4edf3c488096e88f51fb279bb41bc10))
* tracing support ([#36](https://github.com/usetero/policy-rs/issues/36)) ([b6c7c44](https://github.com/usetero/policy-rs/commit/b6c7c4450e17e8eead1bdfa175193265ba2bbae3))


### Bug Fixes

* use the otel spec samplerate ([#35](https://github.com/usetero/policy-rs/issues/35)) ([50c76d8](https://github.com/usetero/policy-rs/commit/50c76d8518e0cd8348736ae6ddf02cb545b5eade))

## [1.3.0](https://github.com/usetero/policy-rs/compare/v1.2.0...v1.3.0) (2026-01-30)


### Features

* upgrade to policy spec 1.2.0 ([#29](https://github.com/usetero/policy-rs/issues/29)) ([ea28749](https://github.com/usetero/policy-rs/commit/ea28749cc35612132aff7dac3145122ec5b29626))


### Bug Fixes

* add back protos ([#32](https://github.com/usetero/policy-rs/issues/32)) ([5d8c5a8](https://github.com/usetero/policy-rs/commit/5d8c5a8ee5806aa44780eb865cfc44674f5230a9))
* ci validate ([#31](https://github.com/usetero/policy-rs/issues/31)) ([9995ceb](https://github.com/usetero/policy-rs/commit/9995ceb63fc810a097db2ab71927549eb84375fd))

## [1.2.0](https://github.com/usetero/policy-rs/compare/v1.1.3...v1.2.0) (2026-01-22)


### Features

* use owned references for more flexibility ([#27](https://github.com/usetero/policy-rs/issues/27)) ([7336b2c](https://github.com/usetero/policy-rs/commit/7336b2c1ec36b2dce3a661053385b751a3ef58a7))


### Bug Fixes

* ci cd installation ([#14](https://github.com/usetero/policy-rs/issues/14)) ([ea856c8](https://github.com/usetero/policy-rs/commit/ea856c84701dd1b9cf2f5aea9c14d20358ac2fb1))

## [1.1.3](https://github.com/usetero/policy-rs/compare/v1.1.2...v1.1.3) (2026-01-13)


### Bug Fixes

* provider methods should be async and non-blocking ([#24](https://github.com/usetero/policy-rs/issues/24)) ([87c51ce](https://github.com/usetero/policy-rs/commit/87c51ce29e1a9769a26f352105b7e0652bdd0a61))

## [1.1.2](https://github.com/usetero/policy-rs/compare/v1.1.1...v1.1.2) (2026-01-13)


### Bug Fixes

* remove libssl dep ([#22](https://github.com/usetero/policy-rs/issues/22)) ([b7423e4](https://github.com/usetero/policy-rs/commit/b7423e4c342b78d0cce469b2330714a4c9bf5d63))

## [1.1.1](https://github.com/usetero/policy-rs/compare/v1.1.0...v1.1.1) (2026-01-12)


### Bug Fixes

* type on arm64 failed build ([#20](https://github.com/usetero/policy-rs/issues/20)) ([73b83cb](https://github.com/usetero/policy-rs/commit/73b83cb26c20829b3d43eca4a7fa55b85a25eb75))

## [1.1.0](https://github.com/usetero/policy-rs/compare/v1.0.5...v1.1.0) (2026-01-09)


### Features

* publish a config file format to be used elsewhere ([#18](https://github.com/usetero/policy-rs/issues/18)) ([351eb66](https://github.com/usetero/policy-rs/commit/351eb66a302b8c5c90f356f83fbd838e5a663206))

## [1.0.5](https://github.com/usetero/policy-rs/compare/v1.0.4...v1.0.5) (2026-01-09)


### Bug Fixes

* update to use trusted auth ([#16](https://github.com/usetero/policy-rs/issues/16)) ([dfa7647](https://github.com/usetero/policy-rs/commit/dfa76477c1ddf4d8c4d15d3b28ce52f2319241d4))

## [1.0.4](https://github.com/usetero/policy-rs/compare/v1.0.3...v1.0.4) (2026-01-09)


### Bug Fixes

* ci cd installation ([#14](https://github.com/usetero/policy-rs/issues/14)) ([7baa643](https://github.com/usetero/policy-rs/commit/7baa643f57f3d5135f97166a8299807f727f1352))
* use different vectorscan bindings ([#12](https://github.com/usetero/policy-rs/issues/12)) ([273636d](https://github.com/usetero/policy-rs/commit/273636d55e9ab85df9af85745c146b004a89fdf9))

## [1.0.3](https://github.com/usetero/policy-rs/compare/v1.0.2...v1.0.3) (2025-12-29)


### Bug Fixes

* use rust releases in release-please ([#10](https://github.com/usetero/policy-rs/issues/10)) ([2f103e8](https://github.com/usetero/policy-rs/commit/2f103e84e45cdef302ffbdc1a016c8530c48f4a0))

## 1.0.0 (2025-12-29)


### Features

* add in http and grpc providers ([#5](https://github.com/usetero/policy-rs/issues/5)) ([2fb6b0b](https://github.com/usetero/policy-rs/commit/2fb6b0b88f9b67cba29a062376d3006e1bf2b99e))
* add support for transforms ([#4](https://github.com/usetero/policy-rs/issues/4)) ([22cf6e8](https://github.com/usetero/policy-rs/commit/22cf6e899f57eab700eade1f0a81a88ba1f4aaa4))
* init repo ([#1](https://github.com/usetero/policy-rs/issues/1)) ([6e190f7](https://github.com/usetero/policy-rs/commit/6e190f77b0270e0ca7696886424170358edd679f))
* instantiate module with a file policy provider ([#3](https://github.com/usetero/policy-rs/issues/3)) ([418c20b](https://github.com/usetero/policy-rs/commit/418c20b122c6882aa1b6bd480b0f2877d296fb66))
* publish module workflow ([#6](https://github.com/usetero/policy-rs/issues/6)) ([84f7fdc](https://github.com/usetero/policy-rs/commit/84f7fdc53358ffad2d1a6542cd8a04453028eb9e))


### Bug Fixes

* add ci setup task ([#7](https://github.com/usetero/policy-rs/issues/7)) ([9d7b7d0](https://github.com/usetero/policy-rs/commit/9d7b7d0ea332e9e2aba958cdaecfbed549bf8340))
* install protoc ([#8](https://github.com/usetero/policy-rs/issues/8)) ([c7a5899](https://github.com/usetero/policy-rs/commit/c7a589917e54fba5c10b058f7953316894469d03))
