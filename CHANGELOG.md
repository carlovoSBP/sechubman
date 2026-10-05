# Changelog

## [2.0.0](https://github.com/carlovoSBP/sechubman/compare/v1.1.1...v2.0.0) (2026-10-05)


### ⚠ BREAKING CHANGES

* sechubman.aws_lambda_handler.lambda_handler no longer exists. This was the real Lambda handler shipped in sechubman 1.1.0-1.1.1 (not a shim at the time); a Lambda still configured with that exact handler path must be updated to sechubman.aws_lambda.scheduled.lambda_handler, which has identical behaviour.

### Features

* add events, trigger and worker Lambda handlers ([5e335d3](https://github.com/carlovoSBP/sechubman/commit/5e335d3cf7e9aaf171a9dbfe115e2e868d2e7095))
* load rules from S3 or a local file for Lambda use ([f1ea37a](https://github.com/carlovoSBP/sechubman/commit/f1ea37a267450b7deb3c7d68546db9ad4d0c7a62))
* remove the aws_lambda_handler backwards-compatibility shim ([64af7cb](https://github.com/carlovoSBP/sechubman/commit/64af7cb8b4d10e3a32eda8889c39f3e015868345))
* report match count from Manager.match_and_update ([bf2cd56](https://github.com/carlovoSBP/sechubman/commit/bf2cd56cdce3222959ef8947c63f7e1c611b0f65))


### Bug Fixes

* guard the pyyaml import behind a clear error message ([4a444a7](https://github.com/carlovoSBP/sechubman/commit/4a444a7f470356c425cb7f25f41da0ca6126cc3b))
* include the page number in the "no findings matched" log line ([a335482](https://github.com/carlovoSBP/sechubman/commit/a335482c64c4a60b69a5151baf0f7538a685f095))
* let a rule switch NoteTextConfig back to plaintext under a jsonUpdate default ([da1962e](https://github.com/carlovoSBP/sechubman/commit/da1962e23bcb1764a9341847173ed09de8ff81a1))
* move pyyaml to correct dependency group ([b32f9e2](https://github.com/carlovoSBP/sechubman/commit/b32f9e252bcd0bf15be346ceff3581f096ddaba5))
* paginate through all findings in Rule.get_and_update ([a772266](https://github.com/carlovoSBP/sechubman/commit/a7722661e74045d95946be410704d7366ae39aa6))


### Documentation

* document Lambda deployment and migration from awsfindingsmanagerlib ([d810490](https://github.com/carlovoSBP/sechubman/commit/d8104908979431077689c67fa31251c98e76e9bb))
* fix ExtraFeatures placement in the ManagerConfig example ([b97b00a](https://github.com/carlovoSBP/sechubman/commit/b97b00ad52f2ceb350068fab46317cae58a55a10))

## [1.1.1](https://github.com/carlovoSBP/sechubman/compare/v1.1.0...v1.1.1) (2026-04-24)


### Bug Fixes

* correct tag passing to gh release ([9c0afc8](https://github.com/carlovoSBP/sechubman/commit/9c0afc8b08773ee8878e4a6a4acd865c659e3b83))

## [1.1.0](https://github.com/carlovoSBP/sechubman/compare/v1.0.1...v1.1.0) (2026-04-24)


### Features

* make lib executable in lambda ([489b9ce](https://github.com/carlovoSBP/sechubman/commit/489b9ce1c970e085dead39dae387a96b21cef965))

## [1.0.1](https://github.com/carlovoSBP/sechubman/compare/v1.0.0...v1.0.1) (2026-04-22)


### Bug Fixes

* bump boto3&gt;=1.42.93 ([d6ca120](https://github.com/carlovoSBP/sechubman/commit/d6ca1203ee0d85d1d139a4690febba58ee8496c6))

## [1.0.0](https://github.com/carlovoSBP/sechubman/compare/v0.2.0...v1.0.0) (2026-04-20)


### ⚠ BREAKING CHANGES

* validate input eagerly on rule creation
* expect a boto3 client at rule creation

### Features

* add quick note feature ([a585699](https://github.com/carlovoSBP/sechubman/commit/a585699242bb9448de1373569d2c218b1921dc87))
* batch json update calls ([e529af6](https://github.com/carlovoSBP/sechubman/commit/e529af6e1ac757d681e2a64f6fc53cbf77430692))
* condense rule files with a lot of repetition via a rule creation manager ([1846907](https://github.com/carlovoSBP/sechubman/commit/18469072eeef89c2e64f40bb37232e75662fcf03))
* expand special cases for boto argument to finding member matching ([9c8bd3f](https://github.com/carlovoSBP/sechubman/commit/9c8bd3f143d790d8faf3c014075a066daef6c406))
* expect a boto3 client at rule creation ([2217bbb](https://github.com/carlovoSBP/sechubman/commit/2217bbbd33ce785937dfccc0210c9b569f80088b))
* extend string matches in findings offline to lists of strings in findings ([53e924b](https://github.com/carlovoSBP/sechubman/commit/53e924b4d111929c9f7073bc8ccbba6e536ddb85))
* extend string matches in findings offline with negative filters ([e4afa19](https://github.com/carlovoSBP/sechubman/commit/e4afa19817c714f0cbb0a1200cebcaf8d2ccccc2))
* extend test fixtures on top level string part matches in findings offline ([a22019e](https://github.com/carlovoSBP/sechubman/commit/a22019e8420c51cd849ef4d419d5c1b6df6ef770))
* filter findings offline on top-level map fields ([12b986b](https://github.com/carlovoSBP/sechubman/commit/12b986bb456b9912c0e78785c4944151e3325537))
* filter findings offline on top-level number fields ([3da99d6](https://github.com/carlovoSBP/sechubman/commit/3da99d6fc2d243589dfe42a512f10d319220c28e))
* filter findings offline with different filter name than json path ([f04d77f](https://github.com/carlovoSBP/sechubman/commit/f04d77fc16a189a564fed537d9d1605bc88441bf))
* filter string-valued fields offline on regex ([ae0b186](https://github.com/carlovoSBP/sechubman/commit/ae0b18669483918900c1f354c7fdcff9ecaf77a2))
* match on date filters ([efef111](https://github.com/carlovoSBP/sechubman/commit/efef111b4350c5e4c750b9b0b825ddf142fe5309))
* match rules on top level string parts in findings offline ([87d5b2c](https://github.com/carlovoSBP/sechubman/commit/87d5b2cd53a02fb9cd874f9d4213d3d38175f84c))
* match rules on top level strings in findings offline ([e35ab4d](https://github.com/carlovoSBP/sechubman/commit/e35ab4da9266ba2745ff201b41d895cc0d81c59c))
* refactor common validation logic to utils ([d1f62c1](https://github.com/carlovoSBP/sechubman/commit/d1f62c104600817458728d5d24060cc2a613d4d1))
* return whether rule fully succeeded in apply ([9b8cb5d](https://github.com/carlovoSBP/sechubman/commit/9b8cb5db153d7050ba54d2e442b0aae1ec5407f1))
* support all resource filtering offline ([1480d11](https://github.com/carlovoSBP/sechubman/commit/1480d1141115d8e1eca0a4195c3fe13ab8afbadd))
* support ResourceAwsEc2InstanceIpV4Addresses resource filtering offline ([7e83d5f](https://github.com/carlovoSBP/sechubman/commit/7e83d5fa1b5a5447cfa35129840e274d66239de9))
* test all rule fixtures for valid markup ([0c7bfbb](https://github.com/carlovoSBP/sechubman/commit/0c7bfbb37efe2d059a0f96da62a95999b0f5f8db))
* update finding note as json if enabled ([b7ed438](https://github.com/carlovoSBP/sechubman/commit/b7ed43889b2c65271129fbb3f8a48b46efbc3bb8))
* validate input eagerly on rule creation ([394341b](https://github.com/carlovoSBP/sechubman/commit/394341b6f4d29ad07ec44b30fa8b452357796d1b))
* validate regex string filter names with boto ([a580ca7](https://github.com/carlovoSBP/sechubman/commit/a580ca7417e28bdc8985bd902b1cf0de267fe63f))


### Bug Fixes

* support only original get_findings api ([dc9f495](https://github.com/carlovoSBP/sechubman/commit/dc9f495ad9f2d1a71e8b550ea67d5b730cf9c185))
* validate against refernce util ([986cdd3](https://github.com/carlovoSBP/sechubman/commit/986cdd32f4747cb566599916a1d4d64b66388ff5))

## [0.2.0](https://github.com/carlovoSBP/sechubman/compare/v0.1.0...v0.2.0) (2025-12-09)


### Features

* apply rules in aws security hub ([151408b](https://github.com/carlovoSBP/sechubman/commit/151408bbe87bb86c2bd31942cd572e257cff7e77))
* create rules for finding management ([d35f372](https://github.com/carlovoSBP/sechubman/commit/d35f372a53f04b0c71218fa4ed4d16452b59660b))
* initialize clients lazily ([ec6bcd6](https://github.com/carlovoSBP/sechubman/commit/ec6bcd6245141b0473dad084b312415ba34e096a))
* validate filters to get findings from AWS Security Hub ([45fa486](https://github.com/carlovoSBP/sechubman/commit/45fa486afacf47f713cfcbbea61e2d1234d0ba64))
* validate updates to findings from AWS Security Hub ([a6b8750](https://github.com/carlovoSBP/sechubman/commit/a6b87504b1d3a67076000acff274eddc36ad9e89))


### Bug Fixes

* add aws region var to test env ([44f1875](https://github.com/carlovoSBP/sechubman/commit/44f187595336bf0502c56a027462d9dd4bf3692f))

## 0.1.0 (2025-12-04)


### Features

* release initial version ([e0a375b](https://github.com/carlovoSBP/sechubman/commit/e0a375b34489054111a308fc285736aec50f2d80))
