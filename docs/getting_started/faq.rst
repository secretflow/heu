常见问题
==============


安装部署相关
-------------


HEU 支持 Mac 吗？
""""""""""""""""""""""""""""""""
支持，HEU 同时支持基于 Intel 和 Apple Silicon CPU 的 macOS。


Pip 找不到安装包
"""""""""""""""""""""""""""""""""
请依次检查安装环境是否满足要求：

#. 检查 `Pypi <https://pypi.org/project/sf-heu>`__ 上面是否存在与您的 Python 环境匹配的 sf-heu 包
#. Pip 版本 22.0+
#. 操作系统版本是否满足要求，详见 :doc:`安装文档<./installation>`


HEU 是否支持其它的 Python 版本？
"""""""""""""""""""""""""""""""""
支持。为了节约 Pypi 仓库存储空间，dev 版本仅发布基于 Python 3.8 的二进制包，beta 及以上的版本将会发布所有 Python 版本的二进制包。对于 dev 版本，您也可以自助 :doc:`从源码编译<./installation>` 所需的 Python 版本的二进制包



功能咨询
-------------

HEU 支持哪些半同态算法？
""""""""""""""""""""""""""""""""""""""""""
Paillier、Okamoto–Uchiyama、EC ElGamal、Damgard-Jurik、DGK，其中部分算法还实现了硬件加速的版本，详见 :doc:`算法选择<./algo_choice>`。


HEU 当前提供哪些功能，FHE 支持吗？
""""""""""""""""""""""""""""""""""""""""""
HEU 是一个业界领先的 PHE Library，支持加解密、明密文加减法、密文-明文乘法等计算，并提供 C++、Python 两种 API，您可以把 HEU 当做一个纯的 Library 来使用，也可以通过 `Secretflow <https://github.com/secretflow/secretflow>`__ 编程框架将 HEU 当做一个密态计算设备使用。

FHE 功能的支持在路上，届时将额外支持密文乘法、密文比较等操作，敬请关注。


请问HEU支持硬件加速的详细说明在哪？
""""""""""""""""""""""""""""""""""""""""""
- 如果您是使用者：HEU 是否使用硬件加速是由 SchemaType 参数决定的，比如 HEU 目前接入了 Intel IPCL 库，支持 avx512ifma 以及 QAT 加速，在机器上已经安装相应硬件，且创建`HeKit`对象时`SchemaType`选择`IPCL`，那么 IPCL 支持的硬件加速能力即可启用，关于详细的算法能力可参考 :doc:`此处<./algo_choice>`。
- 如果您是开发者：假如您有一些硬件加速卡想让隐语兼容，可参考这个接入文档：https://www.secretflow.org.cn/docs/heu/zh_CN/development/phe_dev.html


FPaillier 和 ZPaillier 代表了什么？
""""""""""""""""""""""""""""""""""""""""""
Q：SchemaType.FPaillier 和 SchemaType.ZPaillier分别代表什么含义？提供这两个选择是否存在什么需要trade-off的东西？
`Github Issue <https://github.com/secretflow/secretflow/issues/139>`__

A：这两个是 Paillier 算法的不同实现。在 C++ API 层面，FPaillier 与 ZPaillier 有一些不同，FPaillier 对标 Python-Paillier， 相当于把 Python-Paillier 的逻辑用C++翻译了一遍，其特点是算法层面支持浮点数加密，原理是把 scale 比特数作为明文打包在密文中，密态运算阶段算法会自行对齐、更新 scale 值，其它未做过多优化。而 ZPaillier 是我们实现的一个高度优化的 Paillier 版本，只支持整数加密，性能比 FPaillier 高很多。目前 Python API 并没有暴露浮点运算接口，因此 FPaillier 的功能不能得到全部发挥，故不推荐使用，任何情况下都应该选择 ZPaillier。


heu 是否有类似 spu runtime config 的 enable_action_trace 开关？
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
`Github Issue <https://github.com/secretflow/heu/issues/11>`__

HEU 目前还没有引入编译器层，也没有引入 IR，因此没有 trace 开关，如果您对 HEU 感兴趣，可以参考 :doc:`快速入门<quick_start>`，并结合 `HEU 代码 <https://github.com/secretflow/heu/blob/beta/heu/library/phe/phe.h>`__ 看下，整体不复杂



接口使用
-------------


如果想执行浮点数加解密，有什么推荐的方式么？
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
`Github Issue <https://github.com/secretflow/secretflow/issues/139>`__

加密浮点数需要借助 Encoder，请参考 :doc:`快速入门<quick_start>` 和 :doc:`矩阵运算<numpy>` 中关于 Encoder 的介绍。


能否提供一个HEU运算的例子
""""""""""""""""""""""""""""""""""""""""""
`Github Issue <https://github.com/secretflow/secretflow/issues/54>`__

取决于您如何使用 HEU, HEU 有两层含义，第一他是 secretflow 中的一个 device，第二他本身也是一个同态加密的 library：

- 当做 Library 使用，即独立于 Secretflow 单独使用 HEU，请参考 :doc:`快速入门<quick_start>`
- 当做 device 使用：Secretflow 对 HEU Library 做了一些简单的封装，抽象成了 Device，Device 初始化主要需要指定：i) HEU 逻辑设备由哪几个参与方组成，每个参与方的角色是什么？是 evaluator 还是 sk_keeper。ii) HEU 内部运行的 HE 算法和参数是什么。 iii) HEU 与其它 Device 交互所需要的信息，例如 SPU 用的 scale 是什么。 HEU Device 的文档目前相对欠缺，我们后面会补充，当前有一个基于 `HEU + SPU 的 LR 实现(即 HESS-LR) <https://github.com/secretflow/secretflow/blob/main/secretflow/ml/linear/hess_sgd/model.py>`__，您可以参考 HESS-LR 获取 HEU Device 的用法。
