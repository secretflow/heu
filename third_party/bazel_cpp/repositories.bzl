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
    _bazel_skylib()
    _com_github_eigenteam_eigen()
    _com_github_microsoft_seal()
    _com_github_intel_ipcl()
    _com_github_uscilab_cereal()
    _com_github_nvlabs_cgbn()
    _com_github_intel_ipp()

def _bazel_skylib():
    maybe(
        http_archive,
        name = "bazel_skylib",
        sha256 = "cd55a062e763b9349921f0f5db8c3933288dc8ba4f76dd9416aac68acee3cb94",
        urls = [
            "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.5.0/bazel-skylib-1.5.0.tar.gz",
            "https://github.com/bazelbuild/bazel-skylib/releases/download/1.5.0/bazel-skylib-1.5.0.tar.gz",
        ],
    )

def _com_github_eigenteam_eigen():
    EIGEN_COMMIT = "66e8f38891841bf88ee976a316c0c78a52f0cee5"
    EIGEN_SHA256 = "01fcd68409c038bbcfd16394274c2bf71e2bb6dda89a2319e23fc59a2da17210"
    maybe(
        http_archive,
        name = "com_github_eigenteam_eigen",
        sha256 = EIGEN_SHA256,
        build_file = "@com_alipay_sf_heu//third_party/bazel_cpp:eigen.BUILD",
        strip_prefix = "eigen-{commit}".format(commit = EIGEN_COMMIT),
        urls = [
            "https://gitlab.com/libeigen/eigen/-/archive/{commit}/eigen-{commit}.tar.gz".format(
                commit = EIGEN_COMMIT,
            ),
        ],
    )

def _com_github_microsoft_seal():
    maybe(
        http_archive,
        name = "com_github_microsoft_seal",
        sha256 = "85a63188a5ccc8d61b0adbb92e84af9b7223fc494d33260fa17a121433790a0e",
        strip_prefix = "SEAL-3.6.6",
        type = "tar.gz",
        patch_args = ["-p1"],
        patches = [
            "@com_alipay_sf_heu//third_party/bazel_cpp:patches/seal.patch",
            "@com_alipay_sf_heu//third_party/bazel_cpp:patches/seal-evaluator.patch",
        ],
        urls = [
            "https://github.com/microsoft/SEAL/archive/refs/tags/v3.6.6.tar.gz",
        ],
        build_file = "@com_alipay_sf_heu//third_party/bazel_cpp:seal.BUILD",
    )

def _com_github_intel_ipcl():
    maybe(
        http_archive,
        name = "com_github_intel_ipcl",
        patch_args = ["-p1"],
        sha256 = "1a6ecb6cb830e45e501eace9b499ce776ab97aa6fddaeeb5b22dc3c340446467",
        patches = [
            "@com_alipay_sf_heu//third_party/bazel_cpp:patches/ipcl.patch",
        ],
        strip_prefix = "pailliercryptolib-fdc21350302117103452968ababc2f9676f0d383",
        build_file = "@com_alipay_sf_heu//third_party/bazel_cpp:ipcl.BUILD",
        urls = [
            "https://github.com/intel/pailliercryptolib/archive/fdc21350302117103452968ababc2f9676f0d383.tar.gz",
        ],
    )

def _com_github_uscilab_cereal():
    maybe(
        http_archive,
        name = "com_github_uscilab_cereal",
        sha256 = "ce52ae6abcdbda5fecd63abbaa7ab57e54b814b24d7cb6f5096f5753d1975d24",
        build_file = "@com_alipay_sf_heu//third_party/bazel_cpp:cereal.BUILD",
        strip_prefix = "cereal-ebef1e929807629befafbb2918ea1a08c7194554",
        urls = [
            "https://github.com/USCiLab/cereal/archive/ebef1e929807629befafbb2918ea1a08c7194554.tar.gz",
        ],
    )

def _com_github_nvlabs_cgbn():
    maybe(
        http_archive,
        name = "com_github_nvlabs_cgbn",
        sha256 = "1e8e4cdd0d36b1fb54c2f6adca2eb4b5846a6578dbb6e68b37858c42af0ce4f0",
        build_file = "@com_alipay_sf_heu//third_party/bazel_cpp:cgbn.BUILD",
        strip_prefix = "CGBN-e8b9d265c7b84077d02340b0986f3c91b2eb02fb",
        patch_args = ["-p1"],
        patches = [
            "@com_alipay_sf_heu//third_party/bazel_cpp:patches/cgbn.patch",
        ],
        urls = [
            "https://github.com/NVlabs/CGBN/archive/e8b9d265c7b84077d02340b0986f3c91b2eb02fb.tar.gz",
        ],
    )

def _com_github_intel_ipp():
    maybe(
        http_archive,
        name = "com_github_intel_ipp",
        sha256 = "1ecfa70328221748ceb694debffa0106b92e0f9bf6a484f8e8512c2730c7d730",
        strip_prefix = "ipp-crypto-ippcp_2021.8",
        build_file = "@com_alipay_sf_heu//third_party/bazel_cpp:ipp.BUILD",
        patch_args = ["-p1"],
        patches = [
            "@com_alipay_sf_heu//third_party/bazel_cpp:patches/ippcp.patch",
        ],
        urls = [
            "https://github.com/intel/ipp-crypto/archive/refs/tags/ippcp_2021.8.tar.gz",
        ],
    )
