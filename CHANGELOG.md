# Changelog

## [6.0.1](https://github.com/npm/metavuln-calculator/compare/v6.0.0...v6.0.1) (2023-08-14)

### Dependencies

* [`907daf1`](https://github.com/npm/metavuln-calculator/commit/907daf1390e835245cb9f00b9436169964c80876) [#93](https://github.com/npm/metavuln-calculator/pull/93) bump pacote from 15.2.0 to 16.0.0

## [6.0.0](https://github.com/npm/metavuln-calculator/compare/v5.0.1...v6.0.0) (2023-08-14)

### ⚠️ BREAKING CHANGES

* support for node 14 has been removed

### Bug Fixes

* [`0e95702`](https://github.com/npm/metavuln-calculator/commit/0e957021b882a930f4fae5653ee0bbaa434018d1) [#94](https://github.com/npm/metavuln-calculator/pull/94) drop node14 support (@lukekarrys)

## [5.0.1](https://github.com/npm/metavuln-calculator/compare/v5.0.0...v5.0.1) (2023-04-12)

### Bug Fixes

* [`d89da3f`](https://github.com/npm/metavuln-calculator/commit/d89da3fdeddd3aa8c6255ccf86741dda9dbaed59) [#85](https://github.com/npm/metavuln-calculator/pull/85) support packument without versions (#85) (@vigan-abd)

## [5.0.0](https://github.com/npm/metavuln-calculator/compare/v4.0.0...v5.0.0) (2022-10-13)

### ⚠️ BREAKING CHANGES

* this module no longer attempts to change file ownership automatically

### Dependencies

* [`56c1950`](https://github.com/npm/metavuln-calculator/commit/56c19503e3211fbc046d2c7c556f6b5b2ad04e38) [#69](https://github.com/npm/metavuln-calculator/pull/69) bump cacache from 16.1.3 to 17.0.0 (#69)
* [`e31f928`](https://github.com/npm/metavuln-calculator/commit/e31f9284962b165500e9d2aa4a577b954205cc57) [#70](https://github.com/npm/metavuln-calculator/pull/70) bump pacote from 14.0.0 to 15.0.0 (#70)
* [`2154d72`](https://github.com/npm/metavuln-calculator/commit/2154d72b0c881be7c3ca68bd1fe1b89c1f865831) [#67](https://github.com/npm/metavuln-calculator/pull/67) bump json-parse-even-better-errors from 2.3.1 to 3.0.0

## [4.0.0](https://github.com/npm/metavuln-calculator/compare/v4.0.0-pre.0...v4.0.0) (2022-10-05)

### Dependencies

* [`cfadd1b`](https://github.com/npm/metavuln-calculator/commit/cfadd1b203b99e364ba24326b3350236268bb3fa) [#63](https://github.com/npm/metavuln-calculator/pull/63) remove pacote@14 prerelease ranges (#63)

## [4.0.0-pre.0](https://github.com/npm/metavuln-calculator/compare/v3.1.1...v4.0.0-pre.0) (2022-09-23)

### ⚠️ BREAKING CHANGES

* `@npmcli/metavuln-calculator` is now compatible with the following semver range for node: `^14.17.0 || ^16.13.0 || >=18.0.0`

### Features

* [`a20ebd2`](https://github.com/npm/metavuln-calculator/commit/a20ebd2f3713f7909a8f92e4239bf2ab8dda9756) [#55](https://github.com/npm/metavuln-calculator/pull/55) postinstall for dependabot template-oss PR (@lukekarrys)

### Dependencies

* [`cfb8511`](https://github.com/npm/metavuln-calculator/commit/cfb8511a7ed3cb0b8cdec1617583b098150f87b9) [#57](https://github.com/npm/metavuln-calculator/pull/57) pacote@14||14.pre

## [3.1.1](https://github.com/npm/metavuln-calculator/compare/v3.1.0...v3.1.1) (2022-06-29)


### Bug Fixes

* don't throw on invalid semver versions ([#43](https://github.com/npm/metavuln-calculator/issues/43)) ([7c9f14c](https://github.com/npm/metavuln-calculator/commit/7c9f14cc48037186b76b7e483188a8f7dc9f603f))

## [3.1.0](https://github.com/npm/metavuln-calculator/compare/v3.0.1...v3.1.0) (2022-04-04)


### Features

* include cwe and cvss ([#34](https://github.com/npm/metavuln-calculator/issues/34)) ([5286f6b](https://github.com/npm/metavuln-calculator/commit/5286f6b9281312628baa8a4ea898da7a0ca2e394))

### [3.0.1](https://www.github.com/npm/metavuln-calculator/compare/v3.0.0...v3.0.1) (2022-03-14)


### Dependencies

* bump cacache from 15.3.0 to 16.0.0 ([#25](https://www.github.com/npm/metavuln-calculator/issues/25)) ([6493a7e](https://www.github.com/npm/metavuln-calculator/commit/6493a7e5a5e9d28ab44b57f5c33a5e63e959c5b4))
* update pacote requirement from ^13.0.1 to ^13.0.2 ([#20](https://www.github.com/npm/metavuln-calculator/issues/20)) ([94654bf](https://www.github.com/npm/metavuln-calculator/commit/94654bfcaa754a0065f671f6dc9fd4c0bf2c247f))
* update pacote requirement from ^13.0.2 to ^13.0.3 ([#23](https://www.github.com/npm/metavuln-calculator/issues/23)) ([5be49ab](https://www.github.com/npm/metavuln-calculator/commit/5be49ab411bc1dc04af16bda801e3de70785e016))

## [3.0.0](https://www.github.com/npm/metavuln-calculator/compare/v2.0.0...v3.0.0) (2022-02-16)


### ⚠ BREAKING CHANGES

* the options passed directly to pacote now take a `silent` option instead of `log.loglevel`

### Dependencies

* bump pacote from 12.0.3 to 13.0.1 ([#17](https://www.github.com/npm/metavuln-calculator/issues/17)) ([b295177](https://www.github.com/npm/metavuln-calculator/commit/b295177dfa7dbaf68abb58340b4b0e29529be9ee))
* update cacache requirement from ^15.0.5 to ^15.3.0 ([#15](https://www.github.com/npm/metavuln-calculator/issues/15)) ([1cd2f0a](https://www.github.com/npm/metavuln-calculator/commit/1cd2f0a113a776a981f2046310e13ca6a560e4cf))
* update semver requirement from ^7.3.2 to ^7.3.5 ([#14](https://www.github.com/npm/metavuln-calculator/issues/14)) ([314da9b](https://www.github.com/npm/metavuln-calculator/commit/314da9b625f1f7e9bb32104dae3727656678224f))
