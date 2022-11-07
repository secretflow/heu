矩阵运算
=================

HEU 提供了矩阵化运算接口，其功能主要位于 ``heu.numpy`` 模块。

.. tip:: ``heu.numpy`` 大部分接口都使用并行计算的方式实现，其性能比纯 Python 实现的矩阵运算库高得多


初始化
-----------

.. note::
   运行本文示例代码之前请先通过以下方式 import 相关模块

   .. code-block:: python3

      from heu import numpy as hnp
      from heu import phe


``heu.numpy`` 环境初始化的方法与 ``heu.phe`` 类似：

.. code-block:: python3
   :linenos:

   kit = hnp.setup(phe.SchemaType.ZPaillier, 2048)
   encryptor = kit.encryptor()
   decryptor = kit.decryptor()
   evaluator = kit.evaluator()

另外，由于 ``heu.numpy`` 模块仅仅是 ``heu.phe`` 模块的装饰器，如果您已经有 phe kit 对象，则可以通过 phe kit 对象快速构造 hnp kit 对象，此时同态加密的密钥不会重新生成：

.. code-block:: python3
   :linenos:

   phe_kit = phe.setup(phe.SchemaType.ZPaillier, 2048)
   kit = hnp.HeKit(phe_kit)


在典型的使用场景下，HEU 的使用方由 **sk_keeper** 和 **evaluator** 组成，**sk_keeper** 生成 key pair 后会把公钥传给 **evaluator**，以便 **evaluator** 执行后续运算。

以下是一段多方场景下的环境初始化示例：

.. code-block:: python3
   :linenos:

   import cloudpickle as pickle

   # sk_keeper (client)
   ckit = hnp.setup(phe.SchemaType.ZPaillier, 2048)
   pk_buffer = pickle.dumps(ckit.public_key())

   # ... send pk_buffer through network ...

   # evaluator (server)
   skit = hnp.setup(pickle.loads(pk_buffer))
   evaluator = skit.evaluator()


I/O
--------------

环境准备好之后，下面介绍 heu.numpy 如何处理 Python 中的数据。矩阵在 Python 中有多种表示方式，例如嵌套的 List，嵌套的 Tuple 以及 numpy.ndarray，HEU 把所有 Python 中原始的数据类型称为 Cleartext（原文）。参考 :doc:`快速入门 <./quick_start>`，而 HEU 内部仅有 hnp.PlaintextArray 和 hnp.CiphertextArray 两种类型，分别存储明文矩阵和密文矩阵，Python 中的原始数据类型需要先转换为 hnp.PlaintextArray 后才能被 hnp.numpy 模块进一步处理。

本节介绍如何使用 ``heu.numpy`` 模块将数据在原文（cleartext）与明文（plaintext）之间做转换。


输入
^^^^^^^^^^^

与 ``heu.phe`` 一样，原文（cleartext）到明文（plaintext）之间的转换依赖编码器，``heu.numpy`` 与 ``heu.phe`` 共用相同的编码器。同时，``heu.numpy`` 模块提供了 ``.array()`` 接口用于识别并转换 Cleartext 矩阵。


.. code-block:: python3
   :linenos:

   # Init from nested lists
   harr = kit.array([[1, 2, 3], [4, 5, 6]], phe.IntegerEncoderParams())
   print(harr)
   # [[1000000 2000000 3000000]
   #  [4000000 5000000 6000000]]

   # Init using default encoder (phe.BigintEncoder())
   harr = kit.array([[1, 2, 3], [4, 5, 6]])
   print(harr)
   # [[1 2 3]
   #  [4 5 6]]

   # Init from numpy.ndarray
   import numpy as np
   harr = kit.array(np.arange(10).reshape(2, 5))
   print(harr)
   # [[0 1 2 3 4]
   #  [5 6 7 8 9]]

.. note:: **phe.IntegerEncoder**、**phe.FloatEncoder**、**phe.BatchEncoder** 默认并行编码原文矩阵，而 **phe.BigintEncoder** 受限于全局解释器锁（GIL）的存在尚不支持并行编码。

.. tip:: **phe.IntegerEncoder**、**phe.FloatEncoder** 本质上就是把原始数据乘了一个 scale，如果我自己把原文乘上一个 scale 再转换成 hnp.PlaintextArray 行吗？

   答案是可以，但性能会低一些。HEU 会尽可能地做并行化，而自己在 Python 端做 scale 的话一定是串行的。另外，受限于形式，**hnp.array()** 必须要指定一个 encoder，如果原文本来就是整数或者您已经做了 scale，您可以向 **hnp.array()** 传入一个 scale=1 的 encoder，或者直接使用默认的 ``BigintEncoder``

   .. code-block:: python3

      # create an encoder with scale=1
      edr = phe.IntegerEncoder(phe.SchemaType.ZPaillier, 1)
      hnp.array(np.arange(100), edr)

      # or create a encoder using an equivalent form
      kit.array(np.arange(100), phe.IntegerEncoderParams(1))

      # or just use default encoder
      kit.array(np.arange(100))


辅助函数
^^^^^^^^^^^

HEU 提供了一些辅助函数用以快速创建 hnp.PlaintextArray 对象。

.. code-block:: python3
   :linenos:

   # generate a random matrix with shape 10x10 in interval [-100, 100)
   min = phe.Plaintext(phe.SchemaType.ZPaillier, -100)
   max = phe.Plaintext(phe.SchemaType.ZPaillier, 100)
   hnp.random.randint(min, max, (10, 10))
   # generate a random matrix with shape 2x2 where each element is 2048 bits long
   hnp.random.randbits(phe.SchemaType.ZPaillier, 2048, (2, 2))


输出
^^^^^^^^^^^

**hnp.PlaintextArray** 提供了 **to_numpy()** 接口用于将明文转换成原文，同理，转换的过程依赖编码器。

.. note:: 编码器同时拥有编码和解码功能，一般来说， **to_numpy()** 需要传入与 **hnp.array()** 相同的编码器对象，否则可能导致解码后的原文不正确

.. code-block:: python3
   :linenos:

   edr = phe.FloatEncoder(phe.SchemaType.ZPaillier)
   harr = hnp.array([1.1, 2.1], edr)
   nparr = harr.to_numpy(edr)
   print(nparr) # [1.1 2.1]
   print(type(nparr)) # <class 'numpy.ndarray'>

与 **hnp.array()** 一样，如果 **to_numpy()** 不指定编码器，则默认使用 ``BigintEncoder``。


加解密和运算
-------------

基本操作
^^^^^^^^^^^^^

**encryptor** 和 **decryptor** 分别提供了加密和解密接口，**evaluator** 提供了明文、密文运算的能力，用法如下：

.. code-block:: python3
   :linenos:

   # encrypt
   ct_arr = encryptor.encrypt(kit.array([1, 2, 3, 4]))
   # decrypt
   pt_arr = decryptor.decrypt(ct_arr)
   # evaluate
   c2 = evaluator.add(ct_arr, pt_arr)
   c2 = evaluator.sub(ct_arr, pt_arr)
   c2 = evaluator.mul(ct_arr, pt_arr)
   c2 = evaluator.matmul(ct_arr, pt_arr)
   print(decryptor.decrypt(c2)) # [[30]]

.. warning:: 同态加密的密文无法做 truncation，因此如果 plaintext/ciphertext 是经过 scale 的，则乘法会导致 scale 变成两倍，这时可以用以下两种方式解决：

   #. 保证乘法的其中一个乘数的 scale 为 1

      .. code-block:: python3

         arr1 = kit.array([1.4], phe.FloatEncoderParams())
         arr2 = kit.array([2])
         print(evaluator.mul(arr1, arr2).to_numpy(edr))  # [2.8]

   #. 在结果转为明文或原文后手动除以 scale

      .. code-block:: python3

         scale = 100
         edr = phe.FloatEncoder(phe.SchemaType.ZPaillier, scale)
         res = evaluator.mul(hnp.array([1.4], edr), hnp.array([2.5], edr))
         print(res.to_numpy(edr) / scale)  # [3.5]
         # or
         print(res.to_numpy(kit.float_encoder(scale**2)))  # [3.5]


切片
^^^^^^^^^^^

**hnp.PlaintextArray** 和 **hnp.CiphertextArray** 支持切片，示例如下：

.. code-block:: python3
   :linenos:

   # 1d array
   arr = kit.array([1, 2, 3, 4, 5, 6, 7])
   arr[1]
   arr[-1]
   arr[1:5]  # Slice elements from index 1 to index 5
   arr[4:]  # Slice elements from index 4 to the end of the array
   arr[:4]  # Slice elements from the beginning to index 4 (not included)
   arr[-3:-1]  # Slice from the index 3 from the end to index 1 from the end
   arr[1:5:2]
   arr[::2]
   arr[[1,2,3]]

   # 2d array
   nparr = np.arange(49).reshape((7, 7))
   harr = kit.array(nparr)

   harr[5:1, 1]
   harr[4:, [1, 2, 2, 3]]
   harr[:4, (5,)]
   harr[-3:-1, (1, 3)]
   harr[1:5:2, -1]
   harr[::2, [-7, 5]]
   harr[[1, 2, 3]]
   harr[1]
   harr[:]

hnp 的切片 key 支持 scalar，sequence，slice 类型，其中 sequence 是 list，tuple 等类型的统称。如果 key 是 scalar，则切片在该维度上降维，如果 key 是 sequence 和 slice，则切片保留维度，举例来说：

- harr[sequence/slice, sequence/slice]: 结果为 matrix
- harr[sequence/slice, scalar] or harr[scalar, sequence/slice]: 结果为 vector
- harr[scalar, scalar]: 结果为 scalar


.. warning:: hnp 切片的用法与 numpy 类似，但并不完全一样，以下是结果不一致的地方

   .. code-block:: python3
      :linenos:

      # case 1
      narr = np.arange(49).reshape((7, 7))
      harr = kit.array(narr)

      harr[[1, 2], [0, -1]]  # returns a 2x2 matrix
      narr[[1, 2], [0, -1]]  # returns a 2-len vector

      # case 2
      narr = np.array([0, 1, 2, 3, 4, 5, 6, 7])
      harr = kit.array(narr)
      harr[(0,)]  # got 1d array: [0]
      narr[(0,)]  # got scalar: 0

