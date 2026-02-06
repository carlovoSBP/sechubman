# Changelog

## [1.0.0](https://github.com/carlovoSBP/sechubman/compare/v0.2.0...v1.0.0) (2026-02-06)


### ⚠ BREAKING CHANGES

* validate input eagerly on rule creation
* expect a boto3 client at rule creation

### Features

* expect a boto3 client at rule creation ([2217bbb](https://github.com/carlovoSBP/sechubman/commit/2217bbbd33ce785937dfccc0210c9b569f80088b))
* extend string matches in findings offline to lists of strings in findings ([53e924b](https://github.com/carlovoSBP/sechubman/commit/53e924b4d111929c9f7073bc8ccbba6e536ddb85))
* extend string matches in findings offline with negative filters ([e4afa19](https://github.com/carlovoSBP/sechubman/commit/e4afa19817c714f0cbb0a1200cebcaf8d2ccccc2))
* extend test fixtures on top level string part matches in findings offline ([a22019e](https://github.com/carlovoSBP/sechubman/commit/a22019e8420c51cd849ef4d419d5c1b6df6ef770))
* filter findings offline on top-level map fields ([12b986b](https://github.com/carlovoSBP/sechubman/commit/12b986bb456b9912c0e78785c4944151e3325537))
* filter findings offline on top-level number fields ([3da99d6](https://github.com/carlovoSBP/sechubman/commit/3da99d6fc2d243589dfe42a512f10d319220c28e))
* filter findings offline with different filter name than json path ([f04d77f](https://github.com/carlovoSBP/sechubman/commit/f04d77fc16a189a564fed537d9d1605bc88441bf))
* match on date filters ([efef111](https://github.com/carlovoSBP/sechubman/commit/efef111b4350c5e4c750b9b0b825ddf142fe5309))
* match rules on top level string parts in findings offline ([87d5b2c](https://github.com/carlovoSBP/sechubman/commit/87d5b2cd53a02fb9cd874f9d4213d3d38175f84c))
* match rules on top level strings in findings offline ([e35ab4d](https://github.com/carlovoSBP/sechubman/commit/e35ab4da9266ba2745ff201b41d895cc0d81c59c))
* refactor common validation logic to utils ([d1f62c1](https://github.com/carlovoSBP/sechubman/commit/d1f62c104600817458728d5d24060cc2a613d4d1))
* return whether rule fully succeeded in apply ([9b8cb5d](https://github.com/carlovoSBP/sechubman/commit/9b8cb5db153d7050ba54d2e442b0aae1ec5407f1))
* test all rule fixtures for valid markup ([0c7bfbb](https://github.com/carlovoSBP/sechubman/commit/0c7bfbb37efe2d059a0f96da62a95999b0f5f8db))
* validate input eagerly on rule creation ([394341b](https://github.com/carlovoSBP/sechubman/commit/394341b6f4d29ad07ec44b30fa8b452357796d1b))


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
