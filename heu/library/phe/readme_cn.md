PHE package 实现了多种加法同态加密算法，包括：

- Paillier_float：支持浮点运算的 Paillier 算法
- Paillier_zahlen：整数上的 paillier 算法，性能比 Paillier_float 更高
- Mock：仅仅 mock 了 phe api，内部使用明文计算，不是正真的 HE 算法，仅用于测试
