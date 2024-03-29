# Contribution guidelines

## Contributor License Agreement

Contributions to this project must be accompanied by a Contributor License
Agreement. You (or your employer) retain the copyright to your contribution;
this simply gives us permission to use and redistribute your contributions as
part of the project.

## Style

### C++ coding style

In general, please use clang-format to format code, and follow clang-tidy tips.

Most of the code style is derived from
the [Google C++ style guidelines](https://google.github.io/styleguide/cppguide.html)
, except:

* Exceptions are allowed and encouraged where appropriate.
* Header guards should use `#pragma once`.

### Other tips

* Git commit message should be meaningful, we suggest
  imperative [keywords](https://github.com/joelparkerhenderson/git_commit_message#summary-keywords)
* Developer must write unit-test (line coverage must be greater than 80%), tests
  should be deterministic
* Read awesome [Abseil Tips](https://abseil.io/tips/)

## Change log

Please keep updating changes to the staging area of [change log](CHANGELOGS.md)

Changelog should contain:

- all public API changes, including new features, breaking changes and
  deprecations.
- notable internal changes, like performance improvement.
