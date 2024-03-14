# SPI 简介

## 什么是 SPI

SPI(Service Provider Interface) 是 HEU 面向下层软硬件设置的一层功能扩展接口。通过
SPI，上层应用可以与下层的具体实现解耦。

下图展示了 SPI 在局部架构中的位置

```
┌─────────────────────────────────┐
│          HE Based APPs          │
├─────────────────────────────────┤
│              SPI                │
└─────────────────────────────────┘
┌───────────┐ ┌───────────┐
│           │ │           │
│   LIB 1   │ │   LIB 2   │ ......
│           │ │           │
└───────────┘ └───────────┘
```

### 名词解释

* SPI：Service Provider Interface，服务提供接口
* LIB：功能包。SPI 中每一种具体实现称为一个 Lib，同一个 SPI 下挂的 Lib 功能一般类似，当上层 App
  发起调用时，SPI 可自动选择最合适的 Lib

## SPI 的使用场景

SPI 是围绕 HEU 高性能、可扩展的目标打造的一套技术框架，初期只在 HEU 中有应用，目前随着第三代 SPI
架构的推出，SPI 设计基本基本成熟，并在隐语其他模块中也有应用。未来，构建在 SPI 之上的隐语将会更加开放、灵活。

概率来说，SPI 适用以下这些场景：

1. 硬件加速场景。硬件加速器可以封装成一个 Lib 接入 SPI，一经接入立即对上层所有算法适配
2. 集成第三方库的场景。出于某些原因隐语需要依赖第三方库，但接入的同时又需要保持较低的耦合性，可以使用
   SPI 方案
3. 开源协议污染场景。对于一些带有 GPL 等传染性协议的三方库，使用 SPI 运行时加载库文件的能力可以有效屏蔽协议不兼容问题（规划中的能力）
4. 存在多个同类型库的场景。例如 HEU 实现了多种 PHE 算法，SPI 可以更好的组织、管理这些算法

使用 SPI 的优势有：

1. 解耦功能实现者和调用者，SPI 为底层 Lib 抽象出一层统一的接口，上层 APP 可以无缝在 Lib 之间切换
2. 降低 Lib 接入难度。对于传统架构，硬件加速器开发者或者 Lib 开发者想要把产品接入隐语非常困难，需要有从上到下的理解，使用
   SPI 模式后底层开发者只需要对接 SPI，无需关注上层应用
3. 更好性能。SPI 支持变量堆上、栈上传递、自动处理标量/向量化调用，尽可能避免接口层的性能损耗，最大化发挥
   Lib 性能
4. 更快编译。Lib 代码修改后，上层依赖代码无需重编译，仅需重新 Link，在一定程度上提升研发效率

## HE SPI

HE SPI 是基于第三代 SPI 技术专门为 HE 方向设计的一套接口，其特点是同时支持
PHE、Wordwise-FHE/LHE，Bitwise-FHE/LHE，支持 Multi-level 接入。

所谓 Multi-level SPI，是指 HEU 提供了两个接入层：

* HE SPI，HE 算法整体接入层，如果第三方软/硬件实现了完整的 HE 算法，适合在此层接入
* Polynomial+NTT SPI，一个较为底层的接入口，开放了多项式环计算和 NTT 转换的加速器接入口

```
  ┌──────────────────────────────────────────────────────────────┐
  │                        HE Based APPs                         │
  ├──────────────────────────────────────────────────────────────┤
  │                  HE SPI (PHE + LHE + FHE)                    │
  ├──────────────────────────────┬─┬──────────────┬──────────────┤
  │             HEU              │ │  Third-party │  Third-party │
  │           Built-in           │ │Software based│Hardware based│
  │    RNS Based HE Algorithms   │ │     Libs     │     Libs     │
  ├──────────────────────────────┤ └──────────────┴──────────────┘
  │    Polynomial SPI (uint64)   │
  └──────────────────────────────┘
                   ┌─────────────┐
                   │   NTT SPI   │
                   └─────────────┘
```

FHE 算法非常复杂，如果直接接入 HE SPI 有难度，则可以考虑 Polynomial+NTT SPI，后者只要求实现基本的多项式环运算和
NTT 运算即可接入 HEU，难度降低很多，并且亦可对整体起到不错的加速效果。


## SPI 的工作方式

SPI 并不只是一层接口，上文提到的每一种 SPI 其实都是一个“模块”，每一个 SPI 模块主要由以下几部分组成：

1. SPI interface for user：SPI 对用户侧的接口，也就是用户看到的接口
2. Multi-level sketches：对用户侧接口的多级预实现，对于一些较为简单，功能固定的接口 Sketch
   可提供一个默认实现，这样每个 Lib 就不需要重复实现，简化 Lib 接入负担
3. SPI interface for lib：Lib 侧的接口，这一层接口不固定，不同 Sketch 对用户侧接口的实现方式不一样，因此
   Lib 侧看到的接口也不一样，取决于 Lib 从哪一个 Sketch 继承。Lib 接入时只需选择一个最合适的
   Sketch，实现该 Sketch 要求的接口即可。
4. SPI Factory：SPI 工厂用于创建 Lib 实例。Lib 运行需要的初始化参数、配置均由 SPI Factory注入

```
                  S P I   M o d u l e
                  ┌────────────────────────────────────────┐
                  │         SPI interface for user         │
                  ├────────────────────────────────────────┤
┌────────────┐    │                                        │
│            │    │    Composed of multi-level sketches    │
│   S P I    │    │                                        │
│  Factory   │    ├────────────────────────────────────────┤
│            │    │         SPI interface for lib          │
└─────┬──────┘    └────────────────────────────────────────┘
      │Create     ┌───────────┐ ┌───────────┐
      │Instance   │           │ │           │
      └──────────►│   LIB 1   │ │   LIB 2   │ ......
                  │           │ │           │
                  └───────────┘ └───────────┘
```

SPI 的代码组织和使用示意：

```c++
class HeSpi; // SPI 用户侧接口

class HeSpiVectorSketch : public HeSpi; // Sketch: 对用户接口的预实现

class HeGpuLib : public HeSpiVectorSketch; // 第三方 Lib，从 Sketch 继承

// 用户创建 Lib 实例
std::unique_ptr<HeSpi> hekit = HeSpiFactory::Instance()->Create(/* FHE Args...*/);
heKit->XXXX(); // 使用
```
