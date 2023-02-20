#! /bin/bash
# Copyright 2022 Ant Group Co., Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -ex

bazel build -c opt //heu/pylib #--define disable_gpu=true --cxxopt=-DENABLE_GPAILLIER=false

heu_wheel=$(<bazel-bin/heu/pylib/pylib.name)
heu_wheel_path="bazel-bin/heu/pylib/${heu_wheel}"

python3 -m pip install $heu_wheel_path --force-reinstall --no-deps
# check import ok
python -c "import heu"
