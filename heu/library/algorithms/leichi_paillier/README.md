# 使用方法

## 简介
```
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