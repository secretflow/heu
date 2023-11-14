load("@rules_cuda//cuda:defs.bzl", "cuda_library")

package(default_visibility = ["//visibility:public"])

cuda_library(
    name = "arith",
    srcs = [],
    hdrs = glob([
        "include/cgbn/arith/*.h",
        "include/cgbn/arith/*.cuh",
    ]),
)

cuda_library(
    name = "core",
    srcs = [],
    hdrs = glob([
        "include/cgbn/core/*.cuh",
    ]),
)

cuda_library(
    name = "cgbn",
    srcs = [],
    hdrs = glob([
        "include/cgbn/*.h",
        "include/cgbn/*.cuh",
    ]),
    deps = [
        ":arith",
        ":core",
    ],
)
