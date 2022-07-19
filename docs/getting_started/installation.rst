安装
====

环境准备
--------------

Python == 3.8

OS：
 - Centos 7
 - Ubuntu 18.04+
 - macOS with Intel CPU 11.1+ (macOS Big Sur+)


安装
----



通过 Pip 安装
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

HEU 安装包已经发布到了 PyPi，您可以通过 pip 工具安装 HEU

.. code-block:: bash

  pip install sf-heu


从源码安装
^^^^^^^^^^^^^^^^^^^^^^^^^^


如果您需要使用最新测试版本，可以从 `源码 <https://github.com/secretflow/heu>`_ 编译安装。

依赖工具：
 - `Bazel <https://docs.bazel.build/versions/main/install.html>`_
 - `GCC`

安装：

.. code-block:: bash

  git clone --recursive git@github.com:secretflow/heu.git
  cd heu
  bazel build //heu:heu_wheel -c opt
  pip install bazel-bin/heu/(cat bazel-bin/heu/heu_wheel.name) --force-reinstall


测试运行
---------------------------

安装完成后，建议执行以下命令检查 HEU 是否工作正常

.. code-block:: bash

  python -c "from heu import phe"

上述命令，如果没有任何输出，则说明安装成功；反之如果报错，则说明安装未成功，请参考 :doc:`FAQ </getting_started/faq>`
