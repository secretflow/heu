# Sketch 说明

`sketches/` 目录存放 HE SPI 接口的预实现，根据预实现的方式不同 Sketch 分为两大类：

- Scalar Sketch：为支持标量调用的 Lib 实现一些通用的功能
    - 特点是：一次调用只传入一个参数，但是调用频率非常高，一般为多线程并发调用
    - 适合基于 CPU 实现的 Lib

- Vector Sketch：为支持向量化调用的 Lib 实现一些通用的功能
    - 特点：批量式调用，一次函数调用即可处理一批数据
    - 适合基于加速硬件实现的 Lib，例如 GPU 等，可以最大化发挥硬件的并发性能

对于 Lib 开发者来说，您可以选择从 Sketch 继承子类来实现您的功能，比直接从 SPI 接口继承开发会简单很多

Sketch 实现以下功能：

- 将函数参数 Item 转换成 Lib 自定义的类型
- 将上层的调用模式转换成 Lib 支持的调用模式
    - Scalar Sketch：无论上层为标量/向量调用，一律转换成标量调用模式
    - Vector Sketch：无论上层为标量/向量调用，一律转换成向量调用模式
- 对于一些简单的功能，Sketch 提供默认实现

# 目录组织结构

Sketch 为 SPI 接口的预实现，实现不同 Lib 的公共部分逻辑，跟进逻辑抽象层级的不同，Sketch 目录的组织结构如下：

```text
                                             ─┐
                    HE SPI                    │ SPI
                       ▲                     ─┘
                       │
                       │                     ─┐
                    Common                    │
                       ▲                      │
                       │                      │ Sketches
           ┌───────────┴───────────┐          │
           │                       │          │ Implement common logic
        Scalar                   Vector       │ of different libraries
         ▲  ▲                     ▲  ▲        │
     ┌───┘  │                 ┌───┘  │        │
     │      │                 │      │        │
 ScalarPhe  │             VectorPhe  │       ─┘
     ▲      │                 ▲      │
     │      │                 │      │       ─┐
    PHE    FHE               PHE    FHE       │ Various Libs
    Libs   Libs              Libs   Libs     ─┘
```

各 Sketch 的解释如下：

| Sketch 名称 | 路径           | 说明                   |
|-----------|--------------|----------------------|
| Common    | ./common     | 实现与具体 Lib 无关的公共功能    |
| Scalar    | ./scalar     | 将上层调用全部转换成标量调用       |
| ScalarPhe | ./scalar/phe | 专为标量化的加法同态加密库实现的公共功能 |
| Vector    | ./vector     | 将上层调用全部转换成向量调用       |
| VectorPhe | ./vector/phe | 专为向量化的加法同态加密库实现的公共功能 |
