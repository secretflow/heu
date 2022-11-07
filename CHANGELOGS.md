# CHANGELOGS

- HEU supports a variety of big integer arithmetic libraries now
- [Break change] When creating an Encoder instance, you need to pass in schema
  information, because different schemas may be based on completely different
  integer operation libraries.

## [0.2.0]

- Add to_bytes api
- Make MPInt.RandomExactBits() faster

## [0.1.2]

- Add hnp.random api
- The hnp.Shape class supports iteration/pickling/slicing operations now

## [0.1.1]

- [Break change] The encoder was divided into two types: IntegerEncoder and
  FloatEncoder
- Add two new encoder type: phe.BigintEncoder and phe.BatchEncoder
- Python lib: add numpy-like APIs, most of which have been implemented in a
  parallelized way
- C++ lib: add support for matrix operations

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
