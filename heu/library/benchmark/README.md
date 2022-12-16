# How to run benchmark

# Run benchmark for all algorithms

测试算法在 scalar 运算场景下的性能

Test the performance of algorithms in scalar computing scenarios

```shell
bazel run -c opt heu/library/benchmark:phe
```

测试算法在矩阵运算场景下的性能

Test the performance of algorithms in matrix operation scenarios

```shell
bazel run -c opt heu/library/benchmark:np
```


# Run benchmark for specified algorithm

`--schema` 参数可以指定要跑的算法，例如：

The `--schema` parameter can specify the algorithm to run, for example:

```shell
bazel run -c opt heu/library/benchmark:phe -- --schema=paillier
bazel run -c opt heu/library/benchmark:np -- --schema=paillier
```

另外，`--schema` 参数支持正则匹配算法名称，例如 `paillier.+` 可以匹配全部 paillier 体系的算法。

In addition, the `--schema` parameter supports regex matching, for example `paillier.+` can match all the algorithms of paillier system.


# Run benchmark with different key size

您可以通过 `--key_size` 参数调整 phe 所用的密钥长度。

You can adjust the key size used by phe algorithms with the `--key_size` parameter.

```shell
bazel run -c opt heu/library/benchmark:phe -- --schema=paillier --key_size=3072
bazel run -c opt heu/library/benchmark:np -- --schema=paillier --key_size=3072
```
