# Copyright 2024 Ant Group Co., Ltd.
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

workspace(name = "com_alipay_sf_heu")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

#### fetch third-party deps ####

load("//third_party/bazel_cpp:repositories.bzl", "heu_cpp_deps")

heu_cpp_deps()

load("@yacl//bazel:repositories.bzl", "yacl_deps")

yacl_deps()

#### for cpp ####

load(
    "@rules_foreign_cc//foreign_cc:repositories.bzl",
    "rules_foreign_cc_dependencies",
)

rules_foreign_cc_dependencies(
    register_built_tools = False,
    register_default_tools = False,
    register_preinstalled_tools = True,
)

#### for python ####

load("@rules_python//python:repositories.bzl", "py_repositories")

py_repositories()

# Python binding.
http_archive(
    name = "pybind11_bazel",
    sha256 = "6426567481ee345eb48661e7db86adc053881cb4dd39fbf527c8986316b682b9",
    strip_prefix = "pybind11_bazel-fc56ce8a8b51e3dd941139d329b63ccfea1d304b",
    urls = [
        "https://github.com/pybind/pybind11_bazel/archive/fc56ce8a8b51e3dd941139d329b63ccfea1d304b.zip",
    ],
)

# We still require the pybind library.
http_archive(
    name = "pybind11",
    build_file = "@pybind11_bazel//:pybind11.BUILD",
    sha256 = "eacf582fa8f696227988d08cfc46121770823839fe9e301a20fbce67e7cd70ec",
    strip_prefix = "pybind11-2.10.0",
    urls = [
        "https://github.com/pybind/pybind11/archive/refs/tags/v2.10.0.tar.gz",
    ],
)

load("@pybind11_bazel//:python_configure.bzl", "python_configure")

python_configure(name = "local_config_python")

#### for rust ####

http_archive(
    name = "rules_rust",
    sha256 = "29fee78077bd8c6477bc895a47e6c759f92df0735ed60587e1da7b51f53d26eb",
    strip_prefix = "rules_rust-23a4631cad819003642b1a148e458fe4ed2c54e1",
    urls = [
        # Main branch as of 2021-12-07
        "https://github.com/bazelbuild/rules_rust/archive/23a4631cad819003642b1a148e458fe4ed2c54e1.tar.gz",
    ],
)

load("@rules_rust//rust:repositories.bzl", "rust_repositories")

rust_repositories(version = "1.58.1")

load("//third_party/bazel_rust/cargo:crates.bzl", "rust_fetch_remote_crates")

rust_fetch_remote_crates()

#### for cuda ####

load("@rules_cuda//cuda:repositories.bzl", "register_detected_cuda_toolchains", "rules_cuda_dependencies")

rules_cuda_dependencies()

register_detected_cuda_toolchains()

#### for other third-party libs ####

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")

protobuf_deps()
