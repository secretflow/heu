常见问题
==============


安装部署相关
-------------


HEU 支持 Mac 吗？
""""""""""""""""""""""""""""""""
支持，HEU 同时支持基于 Intel 和 Apple Silicon CPU 的 macOS。


Pip 找不到安装包
"""""""""""""""""""""""""""""""""
请依次检查安装环境是否满足要求：

#. Python 版本必须为 3.8
#. Pip 版本 22.0+
#. 操作系统版本是否满足要求，详见 :doc:`安装文档<./installation>`


HEU 是否支持其它的 Python 版本？
"""""""""""""""""""""""""""""""""
Pypi 仓库的包仅支持 Python 3.8 环境，如果要支持更多的 Python 版本可以尝试 :doc:`从源码编译<./installation>`，同时还需要修改 `此文件 <https://github.com/secretflow/heu/blob/main/heu/pylib/BUILD.bazel>`_ 中关于 Python 版本的声明。

受限于 Pybind 的特性，HEU 运行所用的 Python 版本必须与编译所用的 Python 版本一致，例如编译用的是 Python 3.10 版本，运行也必须在 Python 3.10 下。


功能相关
-------------

HEU 当前提供哪些功能，FHE 支持吗？
""""""""""""""""""""""""""""""""""""""""""
HEU 是一个业界领先的 PHE Library，支持加解密、明密文加减法、密文-明文乘法等计算，并提供 C++、Python 两种 API，您可以把 HEU 当做一个纯的 Library 来使用，也可以通过 `Secretflow <https://github.com/secretflow/secretflow>`_ 编程框架将 HEU 当做一个密态计算设备使用。

FHE 功能的支持在路上，届时将额外支持密文乘法、密文比较等操作，敬请关注。

