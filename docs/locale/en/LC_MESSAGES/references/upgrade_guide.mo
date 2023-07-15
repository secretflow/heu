��          �               �   (   �   (     
   ?  M   J  �   �  �   A  |  �     T  =   b     �     �     �  w  �  1   ?  1   q     �  d   �  �     �   �  �  �     �
  Q   �
           .  
   @   :blue:`After`：0.3.x 的加解密流程 :red:`Before`：0.2.x 的加解密流程 API 变更 Encoder 为了生成正确的 Plaintext，需要额外引入 Schema 信息： Encoder 先把原始数据类型转换成 LibTommath 中的 MPInt 对象（即 Plaintext），再由不同 HE 算法将 MPInt Plaintext 转换成相应的 Ciphertext。 Encoder 直接把原始数据类型转换成算法对应的 Plaintext，不同算法定义的 Plaintext 底层允许有完全不同的数据结构。 HEU 0.2 版本与大整数运算库 Libtommath 强绑定，要求所有算法算法必须基于 Libtommath 开发，这就限制了算法的发展空间，为了支持更多种类的算法，HEU 0.3 版本对底层架构做了较大升级，将 Libtommath 与 HE 算法完全解耦，不再约定算法底层的实现细节，从而使得算法开发者有更大的发挥空间。 Scalar 操作 主要变化在于创建 Plaintext 需要传入 Schema 信息 升级指南 矩阵操作 背景解释 Project-Id-Version: HEU 
Report-Msgid-Bugs-To: 
POT-Creation-Date: 2023-02-02 20:55+0800
PO-Revision-Date: YEAR-MO-DA HO:MI+ZONE
Last-Translator: FULL NAME <EMAIL@ADDRESS>
Language: en
Language-Team: en <LL@li.org>
Plural-Forms: nplurals=2; plural=(n != 1);
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 8bit
Generated-By: Babel 2.10.3
 :blue:`After`：The enc/dec flow of version 0.3.x :red:`Before`：The enc/dec flow of version 0.2.x API changes In order to generate correct Plaintexts, the Encoder needs to pass in additional Schema information: The Encoder first converts the original data type into an MPInt object (i.e. Plaintext) based on LibTommath, and then converts the MPInt plaintext into the corresponding Ciphertext by different HE algorithms. The Encoder directly converts the original data type into the Plaintext corresponding to the HE algorithm. The underlying plaintext defined by different algorithms allows to have completely different data structures. HEU version 0.2 is strongly coupled with the large integer arithmetic library Libtommath, that means all algorithms must be developed based on Libtommath, which limits the development space of algorithms. In order to support more types of HE algorithms, HEU version 0.3 has made a major upgrade to the underlying architecture. Libtommath and HE algorithms are decoupled completely, and the underlying implementation of the algorithms are no longer limited, so that algorithm developers have more room to play. Scalar operations The main change is that creating Plaintext requires passing in Schema information Upgrade Guide matrix operations Background 