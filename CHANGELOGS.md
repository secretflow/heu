# CHANGELOGS

## [Unreleased]

## [0.1.0]

- Add new api phe.plaintext_bound() and phe.encrypt_with_audit()
- Remove dependency on libstdc++ (use static link instead)
- Add docs

## [0.0.6]

- phe.encryptor.encrypt_raw() and phe.decryptor.decrypt_raw() support high
  precision integers
- phe.Plaintext supports conversion to and from arbitrary precision python
  integers
- Improve the security of paillier

## [0.0.5]

- Z-Paillier: Implement CRT & Montgomery & Cache table optimization
- Add benchmark for CRT & cache table
- Translate doc to English

## [0.0.4]

- Implement Paillier03 optimization and encryption is 2x faster than before.
  Ref https://www.brics.dk/DS/03/9/BRICS-DS-03-9.pdf
- Improve compatibility with macOS

## [0.0.3]

- Implement an efficient PHE library and provide easy-to-use C++, Python
  interfaces
