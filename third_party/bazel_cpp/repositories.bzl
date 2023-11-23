load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")

def heu_cpp_deps():
    _com_github_eigenteam_eigen()
    _com_github_microsoft_seal()
    _com_github_intel_ipcl()
    _com_github_uscilab_cereal()
    _com_github_nvlabs_cgbn()

def _com_github_eigenteam_eigen():
    maybe(
        http_archive,
        name = "com_github_eigenteam_eigen",
        sha256 = "606c404bdcbdb3782b4df3e9e32d76e1d940aa6704af5be0e75f6249bc9a6730",
        build_file = "@com_alipay_sf_heu//third_party/bazel_cpp:eigen.BUILD",
        strip_prefix = "eigen-3.4",
        urls = [
            "https://gitlab.com/libeigen/eigen/-/archive/3.4/eigen-3.4.tar.gz",
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
