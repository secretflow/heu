load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

def heu_cpp_deps():
    _com_github_msgpack_msgpack()
    _com_github_libtom_libtommath()
    _com_github_eigenteam_eigen()


def _com_github_libtom_libtommath():
    maybe(
        http_archive,
        name = "com_github_libtom_libtommath",
        sha256 = "f3c20ab5df600d8d89e054d096c116417197827d12732e678525667aa724e30f",
        type = "tar.gz",
        strip_prefix = "libtommath-1.2.0",
        patch_args = ["-p1"],
        patches = ["@com_alipay_sf_heu//third_party/bazel_cpp:patches/libtommath-1.2.0.patch"],
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
