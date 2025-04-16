升级指南
================

.. raw:: html

    <style>
        .red {color:#CC6600}
        .blue {color:#6C8EBF}
    </style>

.. role:: red
.. role:: blue


HEU 0.3.x → 0.4.x
------------------

API 变更
^^^^^^^^^^^^^^^^^^^

HEU 0.4 版本将 ``phe.BatchEncoder`` 拆分成了2个：``phe.BatchIntegerEncoder`` 和 ``phe.BatchFloatEncoder``。

HEU 0.3 中的 ``phe.BatchEncoder`` 并不支持编码浮点数，为了让 BatchEncoder 支持浮点数编码，HEU 0.4 新增了 ``phe.BatchFloatEncoder``，同时为了命名上的清晰性，我们将老旧的 ``phe.BatchEncoder`` 改名成了 ``phe.BatchIntegerEncoder``

用户代码怎么改
^^^^^^^^^^^^^^^^^^^

您可以将老代码中的 BatchEncoder 查找替换为 BatchIntegerEncoder 即可，两者功能等价。


HEU 0.2.x → 0.3.x
------------------

背景解释
^^^^^^^^^^^^^^^^^^

HEU 0.2 版本与大整数运算库 Libtommath 强绑定，要求所有算法算法必须基于 Libtommath 开发，这就限制了算法的发展空间，为了支持更多种类的算法，HEU 0.3 版本对底层架构做了较大升级，将 Libtommath 与 HE 算法完全解耦，不再约定算法底层的实现细节，从而使得算法开发者有更大的发挥空间。

:red:`Before`：0.2.x 的加解密流程

Encoder 先把原始数据类型转换成 LibTommath 中的 MPInt 对象（即 Plaintext），再由不同 HE 算法将 MPInt Plaintext 转换成相应的 Ciphertext。

.. image:: _img/0_2_flow.png
   :align: center

:blue:`After`：0.3.x 的加解密流程

Encoder 直接把原始数据类型转换成算法对应的 Plaintext，不同算法定义的 Plaintext 底层允许有完全不同的数据结构。

.. image:: _img/0_3_flow.png
   :align: center

Encoder 为了生成正确的 Plaintext，需要额外引入 Schema 信息：

.. image:: _img/0_3_encoder.png
   :align: center

API 变更
^^^^^^^^^^^^^^^^^^^

主要变化在于创建 Plaintext 需要传入 Schema 信息

Scalar 操作

.. code-block:: python3
   :linenos:

   from heu import phe
   kit = phe.setup(phe.SchemaType.ZPaillier, 2048)

   # Create plaintext object via encoder (recommend)
   # Create encoder:
   # Before: edr = phe.BigintEncoder()
   # Now:
   edr = phe.BigintEncoder(kit.get_schema())
   # Or:
   edr = kit.bigint_encoder()
   pt = edr.encode(123456789)

   # Create plaintext object directly
   # Before: phe.Plaintext(123)
   # Now:
   phe.Plaintext(kit.get_schema(), 123)

矩阵操作

.. code-block:: python3
   :linenos:

   from heu import numpy as hnp
   from heu import phe
   kit = hnp.setup(phe.SchemaType.ZPaillier, 2048)

   # Create plaintext matrix (solution 1)
   # Before: pt = hnp.array([1, 2, 3])
   # Now:
   pt = kit.array([1, 2, 3])

   # Create plaintext matrix (solution 2)
   # Before: pt = hnp.array([1, 2, 3], phe.IntegerEncoder())
   # Now:
   pt = hnp.array([1, 2, 3], kit.integer_encoder(scale=100))
   # Or:
   pt = hnp.array([1, 2, 3], phe.IntegerEncoder(kit.get_schema(), scale=100))
   # Or:
   pt = kit.array([1, 2, 3], phe.IntegerEncoderParams(scale=100))

用户代码怎么改
^^^^^^^^^^^^^^^^^^^

如果编译报错，请将 schema 参数传入即可，例如这一行编译报错：``phe.BigintEncoder()``，改为 ``phe.BigintEncoder(kit.get_schema())`` 即可，具体参考上一节 **API 变更** 内容。
