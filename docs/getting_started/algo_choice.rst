算法选择
======================

HEU 提供了多种 PHE 算法，本文档描述每种算法的特性，有助于您选择合适的算法。

.. note::
   初始化 HEU 时需要指定 SchemaType 参数，例如：

   .. code-block:: Python

      from heu import phe
      kit = phe.setup(phe.SchemaType.ZPaillier, 2048)

本文档指示如何选择 phe.SchemaType 参数。


算法总览
--------------------

.. list-table::
   :header-rows: 1

   * - SchemaType
     - 算法簇
     - 简要描述
     - 综合推荐度
   * - ZPaillier
     - Paillier
     - 高度优化的 Paillier 算法，适合在所有平台下使用
     - ★★★★★
   * - FPaillier
     - Paillier
     - 性能很低，推荐用 ZPaillier 代替
     - ★
   * - IPCL
     - Paillier
     - Intel 贡献的 Paillier 实现，支持 AVX512-IFMA 指令集和 Intel QAT 硬件加速，目前还在逐步完善中
     - ★★★
   * - OU
     - Okamoto-Uchiyama
     - 功能与 Paillier 一致，且性能更高，密文膨胀度更低，但安全性略低，请见下文详细描述
     - ★★★★★
   * - EC ElGamal
     - ElGamal
     - 基于椭圆曲线的 ElGamal 算法，性能和密文膨胀率比 Paillier、OU 都好，缺点是解密比较慢，且值域空间很小，一旦超过大小解密将失败
     - ★★★★
   * - Mock
     - None
     - 不加密，仅可用于测试或 Debug 目的，严禁在线上使用
     - ★

说明：综合推荐度根据算法性能、安全性、适用面、稳定程度等等因素综合给出，并随着算法迭代升级动态变化。


Paillier
--------------------

算法理论介绍
^^^^^^^^^^^^^^^^^^^^

Paillier 算法由 Pascal Paillier 在 1999 年提出，参见：`算法详情 <https://en.wikipedia.org/wiki/Paillier_cryptosystem>`__

.. list-table:: Paillier 算法信息

   * - 算法类型
     - 加法同态加密
   * - 安全性
     - IND-CPA 安全，语义安全（Semantic Security）
   * - 困难假设
     - | 判定性复合剩余假设
       | decisional composite residuosity assumption (DCRA)
   * - 安全强度（Security Strength）
     - | 2048 位密钥长度等于或略低于 112 bits 安全强度
       | 3072 位密钥长度等于或略低于 128 bits 安全强度

.. admonition:: Decisional composite residuosity assumption

   DCRA states that given a composite N and an integer z, it is hard to decide whether z is an :math:`N`-residue modulo :math:`N^2` (whether there exists a y such that :math:`z \equiv y^N \bmod N^2`)

**关于安全强度**

目前未有直接的文献表明 DCRA 密钥长度与安全比特位数之间的关联，一般认为的难度 DCRA <= FACTORING（因数分解）<= DLP in :math:`\mathbb{Z}^*_N` [#]_，在 DLP（离散对数难题）中，2048 group size 对应 112 bits，3072 group size 对应 128 bits [#]_，因此 Paillier 的安全强度等效或略低于这个数值。

.. [#] European Network of Excellence in Cryptology II. https://www.ecrypt.eu.org/ecrypt2/documents/D.MAYA.6.pdf
.. [#] https://www.keylength.com/en/4/


算法实现: ZPaillier
^^^^^^^^^^^^^^^^^^^^

ZPaillier 中的 Z 与数学中表示整数的 :math:`\mathbb{Z}` 含义相同，即实现了一套支持整数运算的 Paillier 算法。

.. list-table:: ZPaillier 特性速查

   * - SchemaType 参数名称
     - phe.SchemaType.ZPaillier
   * - 实现算法
     - Paillier
   * - 稳定性
     - 稳定
   * - 支持的平台
     - Linux，macOS（Intel & Arm）
   * - 是否依赖特定硬件
     - 不依赖
   * - 是否支持硬件加速
     - 不支持
   * - 相对性能
     - 高

.. tip:: HEU 对 ZPaillier 做了大量优化，ZPaillier 是一套性能较高的 Paillier 算法实现，且不依赖特定硬件，全平台使用，当您不知道如何选择算法时，可以默认使用 ZPaillier

实现基于的 Paper：

- Jurik, M. (2003). Extensions to the paillier cryptosystem with applications to cryptological protocols. Brics, August. http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.4.2396&amp;rep=rep1&amp;type=pdf

算法实现: FPaillier
^^^^^^^^^^^^^^^^^^^^

FPaillier 中的 F 表示浮点数 :math:`\mathbb{F}`，Paillier 算法本身只支持整数，FPaillier 对Paillier 做了扩展，使其可以支持浮点数。

.. list-table:: FPaillier 特性速查

   * - SchemaType 参数名称
     - phe.SchemaType.FPaillier
   * - 实现算法
     - Paillier
   * - 稳定性
     - 稳定
   * - 支持的平台
     - Linux，macOS（Intel & Arm）
   * - 是否依赖特定硬件
     - 不依赖
   * - 是否支持硬件加速
     - 不支持
   * - 相对性能
     - 低

.. note:: FPaillier 的算法原理与 `Python-Paillier <https://github.com/data61/python-paillier>`_ 库类似

FPaillier 支持浮点数的原理是将输入数据表示成 int_rep 形式：``scalar = int_rep * (BASE ** exponent)``

.. code-block:: Python
   :caption: int_rep 和 exponent 计算示意
   :linenos:

   # math.frexp() returns the mantissa and exponent of x, as pair (m, e). m is a float and e is an int, such that x = m * 2.**e.
   bin_flt_exponent = math.frexp(scalar)[1]
   # The least significant bit has value 2 ** bin_lsb_exponent
   bin_lsb_exponent = bin_flt_exponent - cls.FLOAT_MANTISSA_BITS # FLOAT_MANTISSA_BITS = 53

   exponent = bin_lsb_exponent # math.floor(bin_lsb_exponent / cls.LOG2_BASE)
   int_rep = round(fractions.Fraction(scalar) * fractions.Fraction(cls.BASE) ** -exponent)

**加密**

Scalar 加密时只加密 int_rep 的值，exponent 明文存储，请注意安全风险。

**同态运算**

先对齐 exponent，将 exponent 较大的数的 exponent 降低到较小的 exponent（new_exp），即 ``int_rep =  int_rep * (base**(exponent-new_exp))``，再执行同态运算。

.. tip:: FPaillier 的浮点数运算接口并没有在 Python 层暴露，在 Python 端 FPaillier 提供的接口与 ZPaillier 一致。若要使用 FPaillier 浮点功能，必须通过 C++ 接口调用，详细参考 `FPaillier 单测 <https://github.com/secretflow/heu/blob/main/heu/library/algorithms/paillier_float/paillier_test.cc>`_


算法实现: IPCL
^^^^^^^^^^^^^^^^^^^^

IPCL 全称 Intel Paillier Cryptosystem Library，是 Intel 贡献的一种 Paillier 算法实现，其特点是支持 AVX512-IFMA 指令集和 Intel QAT 硬件加速器加速。

.. list-table:: IPCL 特性速查

   * - SchemaType 参数名称
     - phe.SchemaType.IPCL
   * - 实现算法
     - Paillier
   * - 稳定性
     - **实验性质，仅供测试和评估目的，还在持续完善中**
   * - 支持的平台
     - Linux，macOS（Intel）
   * - 是否依赖特定硬件
     - 不依赖
   * - 是否支持硬件加速
     - 支持 AVX512-IFMA 指令集和/或 Intel QAT 加速器
   * - 相对性能
     - 高

实现基于的代码库：

- `pailliercryptolib <https://github.com/intel/pailliercryptolib>`_


Okamoto-Uchiyama
-----------------------------

算法理论介绍
^^^^^^^^^^^^^^^^^^^^

Okamoto-Uchiyama 算法由 Tatsuaki Okamoto 和 Shigenori Uchiyama 在 1998 年提出，参见：`算法详情 <https://en.wikipedia.org/wiki/Okamoto%E2%80%93Uchiyama_cryptosystem>`__

.. list-table:: Okamoto-Uchiyama 算法信息

   * - 算法类型
     - 加法同态加密
   * - 安全性
     - IND-CPA 安全，语义安全（Semantic Security）
   * - 困难假设
     - **p**-subgroup assumption
   * - 安全强度（Security Strength）
     - | 存在争议，相同的密钥长度下 OU 的强度比特与 Paillier 相同或略低，见下文解释

.. admonition:: **p**-subgroup assumption

   It is difficult to determine whether an element x in :math:`({\mathbb Z}/n{\mathbb Z})^{*}` is in the subgroup of order p


**关于安全强度**

Paillier 的 :math:`n=pq`，而 OU 的 :math:`n=p^2q`，当 n 长度相同时两者安全强度是否相同，存在不同的观点。OU 的原始论文 [#]_ 认为目前最快的因式分解算法是 Field sieve method，这种算法的复杂度只和 n 相关，因此只要对齐 n 就可以得到相同的安全强度。

但也有一些 Paper 认为 OU 的 n 需要比 Paillier 多 500~600 比特两者安全性才相等 [#]_，甚至还有文章 [#]_ 说 n 的分解只与 p 相关。因此如果您特别在意安全性，请适当加大 OU 密钥长度。

.. [#] Okamoto, T., & Uchiyama, S. (1998). A new public-key cryptosystem as secure as factoring. Lecture Notes in Computer Science (Including Subseries Lecture Notes in Artificial Intelligence and Lecture Notes in Bioinformatics), 1403, 308-318. https://doi.org/10.1007/BFb0054135
.. [#] Boneh, D., Durfee, G., Howgrave-Graham, N. (1999). Factoring N = p r q for Large r . In: Wiener, M. (eds) Advances in Cryptology — CRYPTO’ 99. CRYPTO 1999. Lecture Notes in Computer Science, vol 1666. Springer, Berlin, Heidelberg. https://doi.org/10.1007/3-540-48405-1_21
.. [#] https://crypto.stanford.edu/cs359c/17sp/projects/NathanManoharBenFisch.pdf


OU 与 Paillier 比较
"""""""""""""""""""""

OU 的优点：

#. 相同的使用场景下，OU 的计算性能远高于 Paillier。
#. 相同的使用场景下，OU 的密文大小只有 Paillier 的一半。假设密钥长度为 N，则 Paillier 的密文大小为 2N 比特，而 OU 密文为 N 比特。
#. OU 的安全性与 Paillier 相同，两者都达到了 IND-CPA 安全，且都不满足 IND-CCA 安全。

OU 的缺点：

#. OU 在学术上的知名度不如 Paillier。
#. OU 的明文值域空间不明确。假设密钥长度为 N，则 Paillier 的明文值域空间为 :math:`Z_N`，而 OU 的明文值域空间为 :math:`Z_p`，其中 p 是 private key 中的参数，因此 OU 的值域空间不是公开的。
#. 虽然理论上两者都不满足 IND-CCA 安全定义，但在实际 IND-CCA 场景下 OU 存在已知攻击，而 Paillier 暂未发现有效攻击。


风险提示
"""""""""""""""""""""

虽然 OU 与 Paillier 在学术上的安全级别相同，两者都满足 IND-CPA 安全，且都达不到 IND-CCA 安全，但实际情况是 OU 已经被发现有高效的攻击手段，而 Paillier 尚未发现有效攻击。

OU 明文空间溢出攻击
''''''''''''''''''''''
OU 的明文空间为 :math:`Z_p`，即 OU 的密文解密以后存在 mod p 的效果。如果允许攻击者加密一个大于 p 的明文，则容易反推出 p，导致私钥泄漏，具体原理如下：

#. 攻击者选择一个比 p 大的明文：:math:`m_1 > p`，进行加密，并且能够得到解密结果 :math:`m_2`。
#. 显然：:math:`m_1 > p, m_2 < p`，并且：:math:`m_1 \equiv m_2 \bmod p`。
#. 通过计算最大公约数 :math:`gcd(m_1 - m_2, n)` 即可得到 p。

OU 在实现时一般做了限制，不允许直接加密大于 p 的明文，但是由于 OU 支持密态加法和明密文乘法，上述溢出攻击仍旧是可能的：

#. 攻击者选择一个接近但是小于 :math:`p` 的明文 m 加密得到 c
#. 对该密文 c 执行 t 次密文加法（或一次明密文乘法）满足 :math:`m * t > p`，然后解密得到 :math:`m'`
#. 攻击者获取 :math:`m'`，利用同余关系即可获取私钥 :math:`p`

.. warning:: 在使用 OU 算法时，请务必判断上层应用环境中该攻击是否成立，如果成立，请立刻使用下文的防御方法来检测和阻断攻击，确保上层应用可以规避这种攻击。


攻击防御
''''''''''''''''''''''''

上述攻击成立的关键有两点，一是攻击者需要能构造出一个大于 p 的密文，二是攻击者需要能获取解密的结果，两者缺一不可，这是一个典型的选择密文攻击（CCA）场景，实际使用 OU 时，应当 **避免在 CCA 成立的场景下使用 OU**。

对于一些简单的场景，比如 Alice、Bob 两方计算，假设 Alice 有私钥，Bob 为恶意参与方，计算的过程为 Alice 将数据加密后发给 Bob 计算，Bob 把计算结果返回给 Alice，此时，即使 Bob 构造了恶意的密文 c，但是 Bob 拿不到 c 对应的解密结果，Bob 的攻击会造成计算错误，但是密钥不会泄露。

在一些复杂的隐私计算场景中，下一轮的交互取决于上一轮交互的结果，CCA 场景成立也许是不可避免的，但并非说明 OU 就一定无法使用，如果 Alice 有有效的手段阻断攻击，OU 仍旧可以选用。让我们再来回顾一下攻击的过程：Bob 构造的密文 c 对应明文 m，Alice 解密后得到 :math:`m'=m \bmod p`，实际的问题是，:math:`m'` 有可能非常大，远超一般业务中使用的 int64 所能表达的范围，因为 Bob 想要构造一个 **略大于** p 的密文是非常困难的，p 一般非常大，key size 为 2048 时 p 大约为 682bits，Bob 盲猜一个数 m 满足 :math:`m' < 2^{64}`，其概率小于 :math:`2^{-(682-64)}`，即盲猜的 m 的高 618bits 与 p exactly same，这个概率是可以忽略不计的，因此可以认为 :math:`m'` 仍旧是一个大数，当 Alice 解密发现明文不在合理值域范围时，可以拒绝 Bob 的结果，从而阻止 Bob 的攻击。


算法实现: OU
^^^^^^^^^^^^^^^^^^^^

OU 实现了 Okamoto-Uchiyama 算法，其功能与 ZPaillier 一致，且性能更高，很多时候可以成为 ZPaillier 的替代品，但 OU 存在一个已知攻击，详见上文关于安全性的论述，使用时需评估该攻击造成的影响。

.. list-table:: OU 特性速查

   * - SchemaType 参数名称
     - phe.SchemaType.OU
   * - 实现算法
     - Okamoto-Uchiyama
   * - 稳定性
     - 稳定
   * - 支持的平台
     - Linux，macOS（Intel & Arm）
   * - 是否依赖特定硬件
     - 不依赖
   * - 是否支持硬件加速
     - 不支持
   * - 相对性能
     - 高


实现基于的 Paper：

- Coron, J. S., Naccache, D., & Paillier, P. (1999). Accelerating Okamoto-Uchiyama public-key cryptosystem. Electronics Letters, 35(4), 291–292. https://doi.org/10.1049/el:19990229


ElGamal
--------------------

算法理论介绍
^^^^^^^^^^^^^^^^^^^^

ElGamal 是一个基于 Diffie–Hellman 密钥交换的非对称加密算法，由 Taher Elgamal 在 1985 年提出 [#]_。原始的 ElGamal 具有乘法同态性质，其同态性来自于密文块 :math:`mh^r`。

在之后的 Generalized ElGamal 算法中，整个密码体制被定义在循环群 G 上，其加密的安全性也取决于 G 上离散对数问题的困难性，为此，用于构建 Generalized ElGamal 的循环群 G 必须满足以下两项要求：

#. 高效性：G 上的计算必须非常快速
#. 安全性：求解 G 上的离散对数问题(DLP)非常困难

以下是一些满足上述要求的具体的 G 的例子：

#. The multiplicative group :math:`\mathbb{Z}^*_p` of the integers modulo a prime :math:`p`.
#. The multiplicative group :math:`\mathbb{F}^*_{2^m}` of the finite field :math:`\mathbb{F}_{2^m}` of characteristic two.
#. The group of points on an elliptic curve over a finite field.
#. The multiplicative group :math:`\mathbb{F}^*_q` of the finite field :math:`\mathbb{F}_q`, where :math:`q=p^m` and p is a prime.
#. The group of units :math:`\mathbb{Z}^*_n`, where n is a composite integer.
#. The jacobian of a hyperelliptic curve defined over a finite field
#. The class group of an imaginary quadratic number field.

为了获得加法同态特性，以及兼顾计算上的高效性，我们选择了 3 将椭圆曲线上的点群（EC Group）作为 ElGamal 底层的 G，因此 HEU 中的 ElGamal 也称为 EC ElGamal。

.. list-table:: ElGamal 算法信息

   * - 算法类型
     - 同态特性取决于底层循环群 G 的定义，根据 G 的不同 Elgamal 可能为加法同态、乘法同态或没有同态特性。
   * - 安全性
     - 取决于 G 上离散对数问题（DLP）的困难性
   * - 困难假设
     - 离散对数难题 DLP
   * - 安全强度（Security Strength）
     - 取决于 G

若循环群选定为椭圆曲线点群（EC Group），则算法信息如下：

.. list-table:: EC ElGamal 算法信息

   * - 算法类型
     - 取决于明文到 EC Group 的映射方式，如果映射妥当，则 EC ElGamal 满足加法同态特性
   * - 安全性
     - 取决于椭圆曲线离散对数问题（ECDLP）的困难性
   * - 困难假设
     - 椭圆曲线离散对数难题 ECDLP
   * - 安全强度（Security Strength）
     - 取决于具体选择的曲线，`此处 <http://safecurves.cr.yp.to/rho.html>`__ 列出了一部分曲线的安全强度

.. [#] ElGamal, T. (1985). A Public Key Cryptosystem and a Signature Scheme Based on Discrete Logarithms. Lecture Notes in Computer Science (Including Subseries Lecture Notes in Artificial Intelligence and Lecture Notes in Bioinformatics), 196 LNCS(4), 10–18. https://doi.org/10.1007/3-540-39568-7_2


算法实现: EC ElGamal
^^^^^^^^^^^^^^^^^^^^^^^^^^

HEU 实现了 EC ElGamal 算法，这是一种定义在椭圆曲线点群（EC Group）上的 ElGamal 算法，相比其他循环群 G，EC Group 的计算效率更高，使得 EC ElGamal 最终性能表现非常优秀。

另一方面，为了维持加法同态特性，EC ElGamal 将明文映射到 EC Group 的方式为：:math:`m'=mG`，其中 :math:`m` 是明文，:math:`m'` 是映射后的明文，即椭圆曲线上的一个点，G 是 EC Group 的生成元。这是一个典型的单向函数（one-way function），EC ElGamal 解密之后得到 :math:`m'` 想要反向计算出真正的明文 :math:`m` 是非常困难的，没有直接求解算法，以至于 EC ElGamal 解密非常慢，这是 EC ElGamal 的缺点。


.. list-table:: EC ElGamal 特性速查

   * - SchemaType 参数名称
     - phe.SchemaType.ElGamal
   * - 实现算法
     - ElGamal
   * - 同态特性
     - 加法同态加密
   * - 稳定性
     - 仅供非生产环境使用
   * - 支持的平台
     - Linux，macOS
   * - 是否依赖特定硬件
     - 不依赖
   * - 是否支持硬件加速
     - 取决于曲线种类的选择。（注：目前所有曲线都不支持硬件加速）
   * - 相对性能
     - 高

EC ElGamal 底层椭圆曲线计算基于 `Yacl ECC SPI <https://github.com/secretflow/yacl/tree/main/yacl/crypto/base/ecc>`__。


算法性能
--------------------

HEU 提供了一个 Benchmark 用以测试每个算法的性能，若要运行 Benchmark 请先 clone HEU 代码库，然后在项目根目录下执行：

.. code-block:: shell

   # 测试算法在 scalar 运算场景下的性能
   # Test the performance of algorithms in scalar computing scenarios
   bazel run -c opt heu/library/benchmark:phe -- --schema=zpaillier

   # 测试算法在矩阵运算场景下的性能
   # Test the performance of algorithms in matrix operation scenarios
   bazel run -c opt heu/library/benchmark:np -- --schema=zpaillier

注：通过更换上述命令中的 schema 参数可以运行不同算法的 Benchmark。第一次运行 Benchmark 会自动触发代码编译。


参考性能
^^^^^^^^^^^^^^^^^^^^

以下是部分算法的参考性能，不涉及加速硬件。配置参数：

- CPU Intel(R) Xeon(R) Gold 5218 CPU @ 2.30GHz
- Key size = 2048

表格的项表示单线程1万次计算的总时间，单位 ms。

.. csv-table::
   :header: SchemaType,加密,密文+密文,密文+明文,密文*明文,解密

   OU,278,18.1,52.5,529,2458
   ZPaillier,8141,70.9,192,1960,86984
   FPaillier,151187,230,150529,1692,150580

再次提醒，即使算法的 Key size 相同，他们的安全强度未必一致，OU 的安全性可能弱于 Paillier，详见 `Okamoto-Uchiyama`_ 算法理论介绍章节。


.. note:: 本页面的英文文档较为陈旧，您愿意翻译吗？感谢您对隐语社区做出的贡献！
