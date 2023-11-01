# 基于 Nvidia CGBN 的 Paillier 算法实现

## 使用须知

1. 该算法为 Paillier 算法的实验性实现，请勿用于生产环境
2. 该算法的性能不佳，请改进此算法
3. 该算法底层依赖 [Nvidia CGBN](https://github.com/NVlabs/CGBN) 第三方库，CGBN 属于 NVlabs
   的产品，目前已经停止维护，请慎用

## 如何使用

paillier_gpu 算法默认关闭，请用以下方式启用：

运行单元测试：

```
bazel test --config=gpu //heu/...
```

编译带 paillier_gpu 的 pip 包：

```
ENABLE_GPU= python setup.py bdist_wheel
```

生成的 whl 包位于 `dist` 目录下，您可以使用 `pip install dist/sf_heu-*.whl`
命令安装使用


# Implementation of Paillier algorithm based on Nvidia CGBN

## Terms and conditions

1. This algorithm is an experimental implementation of the Paillier algorithm and should not be used
   in production environments.
2. The performance of this algorithm is poor, please improve this algorithm
3. This algorithm relies on the third-party library [Nvidia CGBN](https://github.com/NVlabs/CGBN).
   CGBN is a product of NVlabs and is no longer maintained. Please use it with caution.

## How to use

The paillier_gpu algorithm is turned off by default, please enable it in the following way:

Run unit tests:

```
bazel test --config=gpu //heu/...
```

Compile the pip package with paillier_gpu:

```
ENABLE_GPU= python setup.py bdist_wheel
```

The generated `.whl` package can be found in the `dist/` directory. You can install and use it by
running command `pip install dist/sf_heu-*.whl`.
