load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "new_git_repository")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")


def heu_cpp_deps():
    _com_github_msgpack_msgpack()
    _com_github_libtom_libtommath()
    _com_github_eigenteam_eigen()
    _com_github_madler_zlib()
    _com_github_microsoft_seal()
    _com_github_intel_ipcl()
    _com_github_uscilab_cereal()

def _com_github_libtom_libtommath():
    maybe(
        http_archive,
        name = "com_github_libtom_libtommath",
        sha256 = "f3c20ab5df600d8d89e054d096c116417197827d12732e678525667aa724e30f",
        type = "tar.gz",
        strip_prefix = "libtommath-1.2.0",
        patch_args = ["-p1"],
        patches = [
            "@com_alipay_sf_heu//third_party/bazel_cpp:patches/libtommath-1.2.0.patch",
        ],
        urls = [
            "https://github.com/libtom/libtommath/archive/v1.2.0.tar.gz",
        ],
        build_file = "@com_alipay_sf_heu//third_party/bazel_cpp:libtommath.BUILD",
    )

def _com_github_msgpack_msgpack():
    maybe(
        http_archive,
        name = "com_github_msgpack_msgpack",
        type = "tar.gz",
        strip_prefix = "msgpack-c-cpp-3.3.0",
        sha256 = "754c3ace499a63e45b77ef4bcab4ee602c2c414f58403bce826b76ffc2f77d0b",
        urls = [
            "https://github.com/msgpack/msgpack-c/archive/refs/tags/cpp-3.3.0.tar.gz",
        ],
        build_file = "@com_alipay_sf_heu//third_party/bazel_cpp:msgpack.BUILD",
    )

def _com_github_eigenteam_eigen():
    maybe(
        http_archive,
        name = "com_github_eigenteam_eigen",
        sha256 = "8586084f71f9bde545ee7fa6d00288b264a2b7ac3607b974e54d13e7162c1c72",
        build_file = "@com_alipay_sf_heu//third_party/bazel_cpp:eigen.BUILD",
        strip_prefix = "eigen-3.4.0",
        urls = [
            "https://gitlab.com/libeigen/eigen/-/archive/3.4.0/eigen-3.4.0.tar.gz",
        ],
    )

def _com_github_madler_zlib():
    maybe(
        http_archive,
        name = "zlib",
        build_file = "@com_alipay_sf_heu//third_party/bazel_cpp:zlib.BUILD",
        strip_prefix = "zlib-1.2.12",
        sha256 = "d8688496ea40fb61787500e863cc63c9afcbc524468cedeb478068924eb54932",
        type = ".tar.gz",
        urls = [
            "https://github.com/madler/zlib/archive/refs/tags/v1.2.12.tar.gz",
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

# def _com_github_intel_ipcl():
#     maybe(
#         http_archive,
#         name = "com_github_intel_ipcl",
#         strip_prefix = "pailliercryptolib-1.1.4",
#         type = "tar.gz",
#         patch_args = ["-p1"],
#         patches = [
#             "@com_alipay_sf_heu//third_party/bazel_cpp:patches/ipcl.patch",
#         ],
#         urls = [
#             "https://github.com/intel/pailliercryptolib/archive/refs/tags/v1.1.4.tar.gz"
#         ],
#         build_file ="@com_alipay_sf_heu//third_party/bazel_cpp:ipcl.BUILD",
#     )

def _com_github_intel_ipcl():
    maybe(
        new_git_repository,
        name = "com_github_intel_ipcl",
        commit = "8ed98584692a41ff2bacb7c9ef770b1e3ba3c2fa",   # tag v2.0.0
        patch_args = ["-p1"],
        patches = [
            "@com_alipay_sf_heu//third_party/bazel_cpp:patches/ipcl.patch",
        ],
        remote = "https://github.com/intel/pailliercryptolib.git",
        build_file ="@com_alipay_sf_heu//third_party/bazel_cpp:ipcl.BUILD",
    )

def _com_github_uscilab_cereal():
    maybe(
        new_git_repository,
        name = "com_github_uscilab_cereal",
        commit = "ebef1e929807629befafbb2918ea1a08c7194554",  # cereal - v1.3.2
        remote = "https://github.com/USCiLab/cereal.git",
        build_file ="@com_alipay_sf_heu//third_party/bazel_cpp:cereal.BUILD",
    )