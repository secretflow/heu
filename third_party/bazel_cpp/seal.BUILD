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

load("@rules_foreign_cc//foreign_cc:defs.bzl", "cmake", "configure_make")

package(default_visibility = ["//visibility:public"])

filegroup(
    name = "all",
    srcs = glob(["**"]),
)

cmake(
    name = "seal",
    cache_entries = {
        "SEAL_USE_MSGSL": "OFF",
        "SEAL_BUILD_DEPS": "OFF",
        "SEAL_USE_ZSTD": "OFF",
        "SEAL_USE_ZLIB": "OFF",
        "SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT": "OFF",
        "CMAKE_INSTALL_LIBDIR": "lib",
    },
    lib_source = "@com_github_microsoft_seal//:all",
    out_include_dir = "include/SEAL-3.6",
    out_static_libs = ["libseal-3.6.a"],
    deps = ["@zlib"],
)
