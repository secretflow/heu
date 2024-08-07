该目录存放所有 HEU 支持的算法，包括 PHE、FHE。

新贡献的算法请放到 incubator/ 目录下

算法由 SPI 调用，关于 SPI 的介绍，请参考 [/heu/spi](/heu/spi) 目录

```
                 ┌─────────────────────────────────┐
                 │          HE Based APPs          │
 The /heu/spi    ├─────────────────────────────────┤
 folder     ---> │              SPI                │
                 └─────────────────────────────────┘
                 ┌───────────┐ ┌───────────┐
                 │           │ │           │
 This folder --> │   LIB 1   │ │   LIB 2   │ ......
                 │           │ │           │
                 └───────────┘ └───────────┘
```

`algorithm` 或者 `algorithms/incubator` 路径下每个文件夹即为一个 Lib，每个 Lib 实现了一个或多个 HE 算法，算法可以由软件实现，也可以基于硬件加速器实现。

例如：
- `paillier_zahlen` Lib 名称为 paillier_zahlen，实现了 Paillier 算法
- `ou` Lib 名称为 ou，实现了同名的 OU 算法

如果同一个算法被多个 Lib 实现，用户可以强制指定使用某个 Lib 中的某个算法，也可以让 SPI 自动选择 Lib，SPI 将根据运行时软硬件配置和 Lib 性能估算自动选择最合适的 Lib
