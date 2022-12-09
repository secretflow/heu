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
        "IPCL_SHARED" : "OFF",
        "IPCL_TEST" : "OFF",
        "IPCL_BENCHMARK" : "OFF",
        "IPCL_ENABLE_OMP" : "OFF",
        "IPPCRYPTO_INC_DIR" : "$EXT_BUILD_DEPS/ipp/include",
        "CEREAL_INC_DIR" : "$EXT_BUILD_DEPS/cereal/include",
        "IPPCRYPTO_LIB_DIR": "$EXT_BUILD_DEPS/ipp/lib/intel64",
    },
    lib_source = "@com_github_intel_ipcl//:all",
    out_static_libs = ["libipcl.a"],
    linkopts = ["-ldl"],
    deps = ["@com_github_intel_ipp//:ipp",
            "@com_github_uscilab_cereal//:cereal",
            "@com_github_openssl_openssl//:openssl",],
)
