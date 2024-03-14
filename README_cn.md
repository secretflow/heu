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

### 目录结构

```text
.
├── .circleci  # 存放 circleci 的 CI/CD 配置文件
├── .github    # 存放 github 配置文件
├── docs       # 存放 HEU 文档，sphinx 格式
├── heu        # 存放 HEU 所有实现代码
│   ├── algorithms     # 存放所有算法实现，包括 PHE 和 FHE
│   ├── experimental   # 存放一些独立的实验性代码
│   ├── library        # HE Library 应用层功能实现
│   │   ├── algorithms # 未迁移至 SPI 下的存量算法，迁移完成后该目录废弃
│   │   ├── benchmark  # 存放基准测试代码
│   │   ├── numpy      # 实现一套 Numpy-like 接口
│   │   └── phe        # PHE Dispatcher 实现（即将废弃，功能由 SPI 代替）
│   ├── pylib          # 实现 Python binding
│   └── spi            # 定义 HEU 软硬件接入层接口（SPI）
│       ├── he         # 存放 HE SPI，以及相关的 Sketches
│       └── poly       # 定义多项式接口，以及相关的 Sketches
└── third_party        # 存放编译所需的第三方库链接，库本身会在编译时自动下载
```

目前 HEU 正在从老的 Dispatcher 架构切换成基于 SPI 的架构，两套架构主要的模块及其代码路径的映射关系如下：

基于 Dispatcher 的架构：

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

基于 SPI 的架构：

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

关于 SPI 更详细的介绍请 [点击此处](heu/spi/README.md)

### 2024 工作计划

架构切换里程碑：

- [x] HE SPI：设计一套大一统接口，同时支持所有的 PHE/FHE 算法
- [ ] 实现 SPI Sketches (in progress)
- [ ] 存量算法迁移至 SPI (in progress)
- [ ] HE 算法自动化测试框架 (in progress)
- [ ] Tensor Lib 底层从 Dispatcher 切到 SPI
- [ ] PyLib 底层从 Dispatcher 切到 SPI

FHE 里程碑

- [ ] 集成 SEAL，提供 BFV/BGV/CKKS 算法功能
- [ ] 集成 OpenFHE
- [ ] 支持 GPU 加速的 CKKS 算法
- [ ] Tensor Lib 开放 FHE 接口
- [ ] PyLib 开放 FHE 接口


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
