# HEU

[![CircleCI](https://dl.circleci.com/status-badge/img/gh/secretflow/heu/tree/main.svg?style=svg)](https://dl.circleci.com/status-badge/redirect/gh/secretflow/heu/tree/main)

Homomorphic Encryption processing Unit (HEU) is a subproject of Secretflow that
implements high-performance homomorphic encryption algorithms.

The purpose of HEU is to lower the threshold for the use of homomorphic
encryption, so that users can use homomorphic encryption algorithms to build
privacy-preserving applications without professional cryptography knowledge.

## Documentation

https://www.secretflow.org.cn/docs/heu/

## Background

This project consists of two parts:

HE Library (currently implemented): This project can be used as a
high-performance and complete homomorphic encryption library, which integrates
almost all homomorphic encryption algorithms in the industry. At the same time,
HEU encapsulates each algorithm and provides a uniform interface. You can switch
between different HE algorithms at any time without modifying business code.

HE device (in work): As a component of Secretflow, HEU abstracts the homomorphic
encryption algorithms into a programmable device, making it easy for users to
flexibly build applications using the homomorphic encryption technology without
professional knowledge. HEU (device) aims to build a complete computing solution
through HE, that is, based on HE, any type of computing can be completed.
Compared with PPU, HEU's computation is purely local without any network
communication, so HEU and PPU are complementary

Depending on the computing power, HEU has 4 working modes:

| working mode          | Supported calculation types               | Number of calculations | HE algorithms  | Calculating speed  | Ciphertext size     |
|-----------------------|-------------------------------------------|------------------------|----------------|--------------------|---------------------|
| PHEU                  | addition                                  | Unlimited              | Paillier, OU   | Fast               | Small               |
| LHEU                  | addition, multiplication                  | Limited                | BGV, CKKS      | Fast (packed mode) | Least (packed mode) |
| FHEU (low precision)  | addition, mux, LUT                        | Unlimited              | TFHE (Torus)   | Fastest            | Large               |
| FHEU (high precision) | addition, multiplication, comparison, mux | Unlimited              | TFHE (Bitwise) | Very slow          | Largest             |

## Repo status

PHE has been basically developed, LHE and FHE are under development

## Build & UnitTest

Build all


```shell
# build all
bazel build heu/...

# test all (optional)
bazel test heu/...
```

Build python lib

```shell
# build and install python library
sh build_wheel_entrypoint.sh
```
