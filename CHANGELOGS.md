# CHANGELOGS

> Instrument:
>
> - Add `[Feature]` prefix for new features
> - Add `[Bugfix]` prefix for bug fixes
> - Add `[API]` prefix for API changes

## [Unreleased]

- [Feature] Add ClustarFPGA to HEU
- [Optimize] Optimize vectorized spi in mat mul
- [Feature] New apis are added to make algorithms pass in optimized vectorized spi mat mul
- [Add] Add test case Mul in NpBenchmarks

## [0.4.4]

- [Feature] Add EC ElGamal cryptosystem

## [0.4.3]

- [Feature] New api: TreePredictWithIndices support prediction with non-complete
  trees.
- [Feature] New api: Add range check for OU on decryption to block plaintext
  overflow attack
- [Bugfix] Code improve: Make tree pred with indices safer and faster.
- [other] Update libtommath to head version

## [0.4.2]

- [Feature] Modify api: FeatureWiseBucketSum now support cumulative sum option.
- [Feature] Modify public key to string message.

## [0.4.1]

- [Feature] New api: PMatrix/CMatrix add FeatureWiseBucketSum api for better
  performance
- [Feature] New api: pylib extension add TreePredict api for performance
- [Optimize] Optimize CI.

## [0.4.0]

- [Feature] Add Okamoto–Uchiyama cryptosystem
- [Feature] New api: PMatrix/CMatrix add BatchSelectSum api for better
  performance
- [Docs] Add docs to help users choose algorithms
- [Break change] Split BatchEncoder into BatchIntegerEncoder and
  BatchFloatEncoder. Please see upgrade guide doc for details.

## [0.3.2]

- [Optimize] MPInt serialize is 81x faster and deserialize is 53x faster.
- [Feature] Add benchmark for numpy api
- [Feature/experimental] Add a new PHE algorithm implementation - IPCL. IPCL has
  very good performance on Intel AVX512-IFMA cpu instruction set and/or Intel
  QAT accelerator

## [0.3.1]

- add pickle support for XXXEncoderParams class
- add IsZero/IsPositive/IsNegative to Plaintext SPI

## [0.3.0]

- HEU supports a variety of big integer arithmetic libraries now
- PHE algorithms: Add vectorized SPI support
- add phe.parse_schema_type() to parse string to phe.SchemaType
- [Break change] When creating an Encoder instance, you need to pass in schema
  information, because different schemas may be based on completely different
  integer operation libraries. Please see upgrade guide doc for details.

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
