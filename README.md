# HEU

[![CircleCI](https://dl.circleci.com/status-badge/img/gh/secretflow/heu/tree/main.svg?style=svg)](https://dl.circleci.com/status-badge/redirect/gh/secretflow/heu/tree/main)
![PyPI version](https://img.shields.io/pypi/v/sf-heu)

[中文](README_cn.md)

HEU (Homomorphic Encryption processing Unit) is a user-friendly and high-performance homomorphic
encryption library that supports multiple types and scalable hardware acceleration.

## document

https://www.secretflow.org.cn/docs/heu/

## Repo status

Homomorphic encryption algorithms are mainly divided into two categories: partially homomorphic
encryption (PHE) and fully homomorphic encryption (FHE). Currently, HEU supports most PHE
algorithms, while FHE is still under development and will take some time.

Supported algorithms:

- Additive homomorphic encryption
    - Paillier (recommended)
    - Okamoto–Uchiyama (recommended)
    - EC ElGamal
    - Damgard-Jurik
    - Damgard-Geisler-Krøigaard (DGK)
- Fully homomorphic encryption
    - Under development and is the current focus of work.

Each algorithm includes a variety of different implementations, and some implementations support
hardware accelerators. For more details, please refer to
the [Document](https://www.secretflow.org.cn/docs/heu/latest/zh-Hans/getting_started/algo_choice )


### Layout

```text
.
├── .circleci  # CI/CD configuration files for circleci
├── .github    # Configuration files for GitHub
├── docs       # HEU documentation in Sphinx format
├── heu        # All the implementation code for HEU
│   ├── algorithms     # Holds the implementations of all algorithms
│   ├── experimental   # Contains some standalone experimental code
│   ├── library        # Implements the application layer functionality of the HE Library
│   │   ├── algorithms # Legacy algorithms not yet migrated to SPI (this directory will be deprecated after migration)
│   │   ├── benchmark  # Contains benchmarking code
│   │   ├── numpy      # Implements a set of Numpy-like interfaces
│   │   └── phe        # PHE Dispatcher implementation (to be deprecated, with replaced by SPI)
│   ├── pylib          # Python bindings
│   └── spi            # Defines the HEU software and hardware access layer interface (SPI)
│       ├── he         # Contains HE SPI and related Sketches
│       └── poly       # Defines polynomial interfaces and related Sketches
└── third_party        # Contains third-party libraries required for compilation; libraries will be automatically downloaded during build

```

HEU is currently transitioning from the old Dispatcher architecture to an SPI-based framework. The
main modules and their code path mappings for both architectures are as follows:

Dispatcher-based architecture:

```text
     Python APIs (Python binding)
          PATH: heu/pylib
                  │
                  ├───────────────────┐
                  │                   ▼
                  │    Tensor Lib with Numpy-like API
                  │        PATH: heu/library/numpy
                  │                   │
                  │     ┌─────────────┘
                  │     │
                  ▼     ▼
     PHE Dispatcher & PHE C++ API
        PATH: heu/library/phe
                  │
                  │
                  ▼
 Various PHE algorithm implementations
     PATH: heu/library/algorithms
```

SPI-based architecture:

```text
    Python APIs (Python binding)
         PATH: heu/pylib
                 │
                 ├───────────────────┐
                 │                   ▼
                 │    Tensor Lib with Numpy-like API
                 │           PATH: heu/numpy
                 │                   │
                 │ ┌─────────────────┘
                 │ │
                 ▼ ▼
         HE SPI (C++ APIs)
         PATH: heu/spi/he
                 │
                 │
                 ▼
 Various HE algorithm implementations
        PATH: heu/algorithms
```

For a more detailed introduction to SPI, please [click here](heu/spi/README.md)

### 2024 Work Plan

Architecture Transition Milestones:

- [x] HE SPI: Designed a unified interface that supports all PHE/FHE algorithms.
- [ ] Implementation of SPI Sketches. (in progress)
- [ ] Migration of existing algorithms to SPI.
- [ ] Automated testing framework for PHE/FHE algorithms.
- [ ] Transition of Tensor Lib's underlying layer from Dispatcher to SPI.
- [ ] Transition of PyLib's underlying layer from Dispatcher to SPI.

FHE Milestones:

- [ ] Integration of Microsoft SEAL
- [ ] Integration of OpenFHE.
- [ ] Support for GPU-accelerated CKKS algorithm.
- [ ] Provides FHE interfaces in Tensor Lib.
- [ ] Provides FHE interfaces in PyLib.

## Compile and install

### Environmental requirements

- CPU
    - x86_64: minimum required AVX instruction set
    - AArch64: ARMv8
- OS
    - Ubuntu 18.04+
    - Centos 7
    - macOS 11.1+ (macOS Big Sur+)<sup>1</sup>
- Python
    - Python 3.8+
 
1. Due to CI resource limitation, macOS x64 prebuild binary will no longer available since next release.

### Install via Pip

```shell
pip install sf-heu
```

### Install from source

The following command will automatically compile and install HEU into the default Python
environment:

```shell
git clone git@github.com:secretflow/heu.git
cd heu
sh build_wheel_entrypoint.sh

```

### Run unit tests (optional)





```shell
# just compile, do not run any UT (optional)
bazel build heu/...

# compile and run all UTs
bazel test heu/...
```

## Contribution Guidelines

SecretFlow is an open and inclusive community, and we welcome any kind of contribution. If you want
to improve HEU, please refer to [Contribution Guide](CONTRIBUTING.md)
