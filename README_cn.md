# HEU

[![CircleCI](https://dl.circleci.com/status-badge/img/gh/secretflow/heu/tree/main.svg?style=svg)](https://dl.circleci.com/status-badge/redirect/gh/secretflow/heu/tree/main)
![PyPI version](https://img.shields.io/pypi/v/sf-heu)

HEU（Homomorphic Encryption processing Unit）是一个低门槛、高性能的同态加密库，支持多类型、可扩展的硬件加速生态。

## 文档

https://www.secretflow.org.cn/docs/heu/

## 开发状态

同态加密算法主要分为半同态（PHE）和全同态（FHE）两大类，目前 HEU 已支持大部分 PHE 算法，而 FHE 仍需要一段时间的开发

支持的算法：

- 加法同态加密
    - Paillier （推荐）
    - Okamoto–Uchiyama （推荐）
    - EC ElGamal
    - Damgard-Jurik
    - Damgard-Geisler-Krøigaard (DGK)
- 全同态加密
    - 正在开发中，并且是当前 HEU 的工作重心

其中每一类算法又包含多种不同的实现，部分实现支持硬件加速器，详见[文档](https://www.secretflow.org.cn/docs/heu/latest/zh-Hans/getting_started/algo_choice)

## 编译和安装

### 环境要求

- CPU
    - x86_64: 至少支持 AVX 指令集
    - AArch64: ARMv8
- OS
    - Ubuntu 18.04+
    - Centos 7
    - macOS 11.1+ (macOS Big Sur+)
- Python
    - Python 3.8+

### 通过 Pip 安装

```shell
pip install sf-heu
```

### 从源码安装

以下命令将自动编译并安装 HEU 到默认 Python 环境：

```shell
git clone git@github.com:secretflow/heu.git
cd heu
sh build_wheel_entrypoint.sh

```

### 运行单元测试（可选）





```shell
# just compile, do not run any UT (optional)
bazel build heu/...

# compile and run all UTs
bazel test heu/...
```

## 贡献指南

隐语是一个非常包容和开放的社区，我们欢迎任何形式的贡献，如果您想要改进
HEU，请参考[贡献指南](CONTRIBUTING.md)
