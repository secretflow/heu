load("@rules_foreign_cc//foreign_cc:defs.bzl", "cmake")

package(default_visibility = ["//visibility:public"])

filegroup(
    name = "all",
    srcs = glob(["**"]),
)

cmake(
    name = "cereal",
    lib_source = "@com_github_uscilab_cereal//:all",
    out_headers_only = True,
    cache_entries = {
        "BUILD_DOC" : "OFF",
        "BUILD_TESTS" : "OFF",
        "BUILD_SANDBOX" : "OFF",
    },
)