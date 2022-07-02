load("@rules_foreign_cc//foreign_cc:defs.bzl", "make")

package(default_visibility = ["//visibility:public"])

filegroup(
    name = "all_srcs",
    srcs = glob(["**"]),
)

make(
    name = "libtommath",
    copts = ["-O2", "-j"],  # libtommath rely on DCE to compile, increase optimization level to ensure it compiles
    lib_source = ":all_srcs",
    out_static_libs = ["libtommath.a"],
    targets = ["install"],
)
