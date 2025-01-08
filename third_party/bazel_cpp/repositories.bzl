# Copyright 2024 Ant Group Co., Ltd
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

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

def heu_cpp_deps():
    _com_github_nvlabs_cgbn()

def _com_github_nvlabs_cgbn():
    maybe(
        http_archive,
        name = "com_github_nvlabs_cgbn",
        sha256 = "1e8e4cdd0d36b1fb54c2f6adca2eb4b5846a6578dbb6e68b37858c42af0ce4f0",
        build_file = "//third_party/bazel_cpp:cgbn.BUILD",
        strip_prefix = "CGBN-e8b9d265c7b84077d02340b0986f3c91b2eb02fb",
        patch_args = ["-p1"],
        patches = [
            "//third_party/bazel_cpp:patches/cgbn.patch",
        ],
        urls = [
            "https://github.com/NVlabs/CGBN/archive/e8b9d265c7b84077d02340b0986f3c91b2eb02fb.tar.gz",
        ],
    )
