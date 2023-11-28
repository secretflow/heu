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

## Compile and install

### Environmental requirements

- CPU
    - x86_64: minimum required AVX instruction set
    - AArch64: ARMv8
- OS
    - Ubuntu 18.04+
    - Centos 7
    - macOS 11.1+ (macOS Big Sur+)
- Python
    - Python 3.8+

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
