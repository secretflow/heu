workspace(name = "com_alipay_sf_heu")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

### ref yacl ###
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

SECRETFLOW_GIT = "https://github.com/secretflow"

YACL_COMMIT_ID  = "f96fd97484dea4e236b1baa0d88bbb4459c91867"

git_repository(
    name = "yacl",
    commit = YACL_COMMIT_ID,
    recursive_init_submodules = True,
    remote = "{}/yacl.git".format(SECRETFLOW_GIT),
)

load("@yacl//bazel:repositories.bzl", "yacl_deps")

yacl_deps()

#### fetch third-party deps ####

load("//third_party/bazel_cpp:repositories.bzl", "heu_cpp_deps")

heu_cpp_deps()

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

http_archive(
    name = "rules_python",
    sha256 = "8c15896f6686beb5c631a4459a3aa8392daccaab805ea899c9d14215074b60ef",
    strip_prefix = "rules_python-0.17.3",
    urls = [
        "https://github.com/bazelbuild/rules_python/archive/refs/tags/0.17.3.tar.gz",
    ],
)

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
