load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

def heu_cpp_deps():
    _com_github_eigenteam_eigen()
    _com_github_madler_zlib()
    _com_github_microsoft_seal()
    _com_github_intel_ipcl()
    _com_github_uscilab_cereal()

def _com_github_eigenteam_eigen():
    maybe(
        http_archive,
        name = "com_github_eigenteam_eigen",
        sha256 = "c1b115c153c27c02112a0ecbf1661494295d9dcff6427632113f2e4af9f3174d",
        build_file = "@com_alipay_sf_heu//third_party/bazel_cpp:eigen.BUILD",
        strip_prefix = "eigen-3.4",
        urls = [
            "https://gitlab.com/libeigen/eigen/-/archive/3.4/eigen-3.4.tar.gz",
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
