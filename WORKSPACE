workspace(name = "com_alipay_sf_heu")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

#### for cpp ####


# rules_foreign_cc-0.7.1 cannot work on macOS
http_archive(
    name = "rules_foreign_cc",
    sha256 = "69023642d5781c68911beda769f91fcbc8ca48711db935a75da7f6536b65047f",
    strip_prefix = "rules_foreign_cc-0.6.0",
    urls = [
        "https://github.com/bazelbuild/rules_foreign_cc/archive/0.6.0.tar.gz",
    ],
)

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

http_archive(
    name = "rules_python",
    sha256 = "cd6730ed53a002c56ce4e2f396ba3b3be262fd7cb68339f0377a45e8227fe332",
    urls = [
        "https://github.com/bazelbuild/rules_python/releases/download/0.5.0/rules_python-0.5.0.tar.gz",
    ],
)

# Python binding.
http_archive(
    name = "pybind11_bazel",
    sha256 = "a5666d950c3344a8b0d3892a88dc6b55c8e0c78764f9294e806d69213c03f19d",
    strip_prefix = "pybind11_bazel-26973c0ff320cb4b39e45bc3e4297b82bc3a6c09",
    urls = [
        "https://github.com/pybind/pybind11_bazel/archive/26973c0ff320cb4b39e45bc3e4297b82bc3a6c09.zip",
    ],
)

# We still require the pybind library.
http_archive(
    name = "pybind11",
    build_file = "@pybind11_bazel//:pybind11.BUILD",
    sha256 = "057fb68dafd972bc13afb855f3b0d8cf0fa1a78ef053e815d9af79be7ff567cb",
    strip_prefix = "pybind11-2.9.0",
    urls = [
        "https://github.com/pybind/pybind11/archive/refs/tags/v2.9.0.tar.gz",
    ],
)

load("@pybind11_bazel//:python_configure.bzl", "python_configure")

python_configure(
    name = "local_config_python",
    python_version = "3",
)

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

### ref yasl ###

local_repository(
    name = "yasl",
    path = "{}/second_party/yasl".format(__workspace_dir__),
)

load("@yasl//bazel:repositories.bzl", "yasl_deps")

yasl_deps()

#### fetch third-party deps ####

load("//third_party/bazel_cpp:repositories.bzl", "heu_cpp_deps")

heu_cpp_deps()

load("//third_party/bazel_rust/cargo:crates.bzl", "rust_fetch_remote_crates")

rust_fetch_remote_crates()
