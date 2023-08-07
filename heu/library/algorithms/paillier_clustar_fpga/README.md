# 使用方法

## 简介

```
paillier_clustar_fpga 默认关闭, 在 command line 设置 enable_clustar_fpga=true 开启 paillier_clustar_fpga;
```

## HEU全量编译

默认关闭 paillier_clustar_fpga

```
bazel build heu/...
```

打开 paillier_clustar_fpga

```
bazel build heu/... --define enable_clustar_fpga=true
```

## Paillier_Clustar_FPGA相关单元测试

默认关闭

```
bazel test --test_output=all --cache_test_results=no heu/library/algorithms/paillier_clustar_fpga:plaintext_test

bazel test --test_output=all --cache_test_results=no heu/library/algorithms/paillier_clustar_fpga:key_gen_test

bazel test --test_output=all --cache_test_results=no heu/library/algorithms/paillier_clustar_fpga:ciphertext_test

bazel test --test_output=all --cache_test_results=no heu/library/algorithms/paillier_clustar_fpga:enc_dec_test

bazel test --test_output=all --cache_test_results=no heu/library/algorithms/paillier_clustar_fpga:evaluator_test
```

打开 paillier_clustar_fpga

```
bazel test --test_output=all --cache_test_results=no heu/library/algorithms/paillier_clustar_fpga:plaintext_test --define enable_clustar_fpga=true

bazel test --test_output=all --cache_test_results=no heu/library/algorithms/paillier_clustar_fpga:key_gen_test --define enable_clustar_fpga=true

bazel test --test_output=all --cache_test_results=no heu/library/algorithms/paillier_clustar_fpga:ciphertext_test --define enable_clustar_fpga=true

bazel test --test_output=all --cache_test_results=no heu/library/algorithms/paillier_clustar_fpga:enc_dec_test --define enable_clustar_fpga=true

bazel test --test_output=all --cache_test_results=no heu/library/algorithms/paillier_clustar_fpga:evaluator_test --define enable_clustar_fpga=true
```

## HEU官方单测

默认关闭

```
bazel test --test_output=all --cache_test_results=no heu/...
```

打开 paillier_clustar_fpga

```
bazel test --test_output=all --cache_test_results=no heu/... --define enable_clustar_fpga=true
```

## Benchmark测试

无 paillier_clustar_fpga

```
bazel run -c opt heu/library/benchmark:np -- --schema=ZPaillier
bazel run -c opt heu/library/benchmark:np -- --schema=FPaillier
bazel run -c opt heu/library/benchmark:np -- --schema=IPCL
```

使用 paillier_clustar_fpga

```
bazel run -c opt --define enable_clustar_fpga=true heu/library/benchmark:np -- --schema=ClustarFPGA
```
