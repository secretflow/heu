load("@rules_foreign_cc//foreign_cc:defs.bzl", "cmake", "configure_make")
package(default_visibility = ["//visibility:public"])

filegroup(
    name = "all_srcs",
    srcs = glob(["**"]),
)

cmake(
    name = "msgpack",
    cache_entries = {
        "MSGPACK_CXX17": "ON",
        "MSGPACK_BUILD_EXAMPLES": "OFF",
        "BUILD_SHARED_LIBS": "OFF",
        "MSGPACK_BUILD_TESTS": "OFF",
    },
    lib_source = ":all_srcs",
    out_headers_only = True,
    build_args = ["-j"]
)
