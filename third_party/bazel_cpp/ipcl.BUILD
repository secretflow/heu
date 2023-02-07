load("@rules_foreign_cc//foreign_cc:defs.bzl", "cmake", "configure_make")

package(default_visibility = ["//visibility:public"])

filegroup(
    name = "all",
    srcs = glob(["**"]),
)

cmake(
    name = "ipcl",
    cache_entries = {
        "CMAKE_INSTALL_LIBDIR": "lib",
        "IPCL_SHARED": "OFF",
        "IPCL_TEST": "OFF",
        "IPCL_BENCHMARK": "OFF",
        "IPCL_ENABLE_OMP": "OFF",
        "IPPCRYPTO_INC_DIR": "$EXT_BUILD_DEPS/ipp/include",
        "CEREAL_INC_DIR": "$EXT_BUILD_DEPS/cereal/include",
        "IPPCRYPTO_LIB_DIR": "$EXT_BUILD_DEPS/ipp/lib/intel64",
        "OPENSSL_INCLUDE_DIR": "$EXT_BUILD_DEPS/openssl/include",
        "OPENSSL_LIBRARIES": "$EXT_BUILD_DEPS/openssl/lib",
        "OPENSSL_ROOT_DIR": "$EXT_BUILD_DEPS/openssl",
    },
    lib_source = "@com_github_intel_ipcl//:all",
    linkopts = ["-ldl"],
    out_static_libs = ["libipcl.a"],
    deps = [
        "@com_github_intel_ipp//:ipp",
        "@com_github_openssl_openssl//:openssl",
        "@com_github_uscilab_cereal//:cereal",
    ],
)
