load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

def heu_cpp_deps():
    _com_github_fmtlib_fmt()
    _com_google_googletest()
    _com_github_google_benchmark()
    _com_github_msgpack_msgpack()
    _com_github_libtom_libtommath()

def _com_github_fmtlib_fmt():
    maybe(
        http_archive,
        name = "com_github_fmtlib_fmt",
        strip_prefix = "fmt-8.0.1",
        sha256 = "b06ca3130158c625848f3fb7418f235155a4d389b2abc3a6245fb01cb0eb1e01",
        build_file = "@com_alipay_sf_heu//third_party/bazel_cpp:fmtlib.BUILD",
        urls = [
            "https://github.com/fmtlib/fmt/archive/refs/tags/8.0.1.tar.gz",
        ],
    )

def _com_google_googletest():
    maybe(
        http_archive,
        name = "com_google_googletest",
        sha256 = "b4870bf121ff7795ba20d20bcdd8627b8e088f2d1dab299a031c1034eddc93d5",
        type = "tar.gz",
        strip_prefix = "googletest-release-1.11.0",
        urls = [
            "https://github.com/google/googletest/archive/refs/tags/release-1.11.0.tar.gz",
        ],
    )

def _com_github_google_benchmark():
    maybe(
        http_archive,
        name = "com_github_google_benchmark",
        type = "tar.gz",
        strip_prefix = "benchmark-1.5.5",
        sha256 = "3bff5f237c317ddfd8d5a9b96b3eede7c0802e799db520d38ce756a2a46a18a0",
        urls = [
            "https://github.com/google/benchmark/archive/refs/tags/v1.5.5.tar.gz",
        ],
    )

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
