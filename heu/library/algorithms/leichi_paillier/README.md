# 使用方法

## 简介
```
Leichi 隐私计算加速板卡是北极熊芯在隐私计算场景下的第一款高性能产品,针对于隐私计算加密场景中的复杂模运算进行加速。在协议级别上支持 Paillier、RSA 等,在算子级别上支持模乘、模幂、模逆、模加和卷积,最大密文位宽为4096比特。主要适用场景:Paillier、 RSA、联邦学习、机器学习等。

leichi_paillier 默认关闭;
```
## HEU编译

bazel build heu/...
```
bazel test heu/... --test_output=all --cache_test_results=no

使用  leichi_paillier
```
bazel test heu/... --test_output=all --cache_test_results=no   --define enable_leichi=true


## leichi_paillier相关单元测试

使用 leichi_paillier
```
bazel test --test_output=all --cache_test_results=no heu/library/algorithms/leichi_paillier:encryptor_test --define enable_leichi=true
bazel test --test_output=all --cache_test_results=no heu/library/algorithms/leichi_paillier:key_generator_test --define enable_leichi=true

```
## Benchmark测试

使用 leichi_paillier
```
scalar 场景性能测试
```
bazel run -c opt heu/library/benchmark:phe -- --schema=Leichi --define enable_leichi=true

vector 场景性能测试
```
bazel run -c opt heu/library/benchmark:np -- --schema=Leichi --define enable_leichi=true