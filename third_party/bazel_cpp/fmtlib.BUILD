load("@rules_foreign_cc//foreign_cc:defs.bzl", "cmake", "configure_make")

package(default_visibility = ["//visibility:public"])

filegroup(
    name = "all_srcs",
    srcs = glob(["**"]),
)

cmake(
    name = "fmtlib",
    build_args = ["-j"],
    cache_entries = {
        "FMT_TEST": "OFF",
    },
    defines = ["FMT_HEADER_ONLY"],
    lib_source = ":all_srcs",
    out_headers_only = True,
)
