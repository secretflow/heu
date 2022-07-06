workspace(name = "com_alipay_sf_heu")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

#### for cpp ####

http_archive(
    name = "rules_foreign_cc",
    sha256 = "bcd0c5f46a49b85b384906daae41d277b3dc0ff27c7c752cc51e43048a58ec83",
    strip_prefix = "rules_foreign_cc-0.7.1",
    urls = [
        "https://github.com/bazelbuild/rules_foreign_cc/archive/0.7.1.tar.gz",
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
    sha256 = "9fcf91dbcc31fde6d1edb15f117246d912c33c36f44cf681976bd886538deba6",
    strip_prefix = "rules_python-0.8.0",
    urls = [
        "https://github.com/bazelbuild/rules_python/archive/refs/tags/0.8.0.tar.gz",
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
    sha256 = "6bd528c4dbe2276635dc787b6b1f2e5316cf6b49ee3e150264e455a0d68d19c1",
    strip_prefix = "pybind11-2.9.2",
    urls = [
        "https://github.com/pybind/pybind11/archive/refs/tags/v2.9.2.tar.gz",
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
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

git_repository(
    name = "yasl",
    commit = "5ee0e3346597cf6118b4a0f09205a97f535355b7",
    recursive_init_submodules = True,
    remote = "https://github.com/secretflow/yasl.git",
)

load("@yasl//bazel:repositories.bzl", "yasl_deps")

yasl_deps()

#### fetch third-party deps ####

load("//third_party/bazel_cpp:repositories.bzl", "heu_cpp_deps")

heu_cpp_deps()

load("//third_party/bazel_rust/cargo:crates.bzl", "rust_fetch_remote_crates")

rust_fetch_remote_crates()
