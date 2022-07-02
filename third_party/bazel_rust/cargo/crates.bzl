"""
@generated
cargo-raze generated Bazel file.

DO NOT EDIT! Replaced on runs of cargo-raze
"""

load("@bazel_tools//tools/build_defs/repo:git.bzl", "new_git_repository")  # buildifier: disable=load
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")  # buildifier: disable=load
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")  # buildifier: disable=load

# EXPERIMENTAL -- MAY CHANGE AT ANY TIME: A mapping of package names to a set of normal dependencies for the Rust targets of that package.
_DEPENDENCIES = {
    "heu/tfhe": {
        "colored": "@rust__colored__2_0_0//:colored",
        "concrete": "@rust__concrete__0_1_11//:concrete",
        "concrete-boolean": "@rust__concrete_boolean__0_1_0//:concrete_boolean",
        "concrete-core": "@rust__concrete_core__0_1_10//:concrete_core",
        "cxx": "@rust__cxx__1_0_65//:cxx",
        "log": "@rust__log__0_4_14//:log",
        "simple_logger": "@rust__simple_logger__2_1_0//:simple_logger",
    },
}

# EXPERIMENTAL -- MAY CHANGE AT ANY TIME: A mapping of package names to a set of proc_macro dependencies for the Rust targets of that package.
_PROC_MACRO_DEPENDENCIES = {
    "heu/tfhe": {
    },
}

# EXPERIMENTAL -- MAY CHANGE AT ANY TIME: A mapping of package names to a set of normal dev dependencies for the Rust targets of that package.
_DEV_DEPENDENCIES = {
    "heu/tfhe": {
        "criterion": "@rust__criterion__0_3_5//:criterion",
        "tempfile": "@rust__tempfile__3_3_0//:tempfile",
    },
}

# EXPERIMENTAL -- MAY CHANGE AT ANY TIME: A mapping of package names to a set of proc_macro dev dependencies for the Rust targets of that package.
_DEV_PROC_MACRO_DEPENDENCIES = {
    "heu/tfhe": {
    },
}

def crate_deps(deps, package_name = None):
    """EXPERIMENTAL -- MAY CHANGE AT ANY TIME: Finds the fully qualified label of the requested crates for the package where this macro is called.

    WARNING: This macro is part of an expeirmental API and is subject to change.

    Args:
        deps (list): The desired list of crate targets.
        package_name (str, optional): The package name of the set of dependencies to look up.
            Defaults to `native.package_name()`.
    Returns:
        list: A list of labels to cargo-raze generated targets (str)
    """

    if not package_name:
        package_name = native.package_name()

    # Join both sets of dependencies
    dependencies = _flatten_dependency_maps([
        _DEPENDENCIES,
        _PROC_MACRO_DEPENDENCIES,
        _DEV_DEPENDENCIES,
        _DEV_PROC_MACRO_DEPENDENCIES,
    ])

    if not deps:
        return []

    missing_crates = []
    crate_targets = []
    for crate_target in deps:
        if crate_target not in dependencies[package_name]:
            missing_crates.append(crate_target)
        else:
            crate_targets.append(dependencies[package_name][crate_target])

    if missing_crates:
        fail("Could not find crates `{}` among dependencies of `{}`. Available dependencies were `{}`".format(
            missing_crates,
            package_name,
            dependencies[package_name],
        ))

    return crate_targets

def all_crate_deps(normal = False, normal_dev = False, proc_macro = False, proc_macro_dev = False, package_name = None):
    """EXPERIMENTAL -- MAY CHANGE AT ANY TIME: Finds the fully qualified label of all requested direct crate dependencies \
    for the package where this macro is called.

    If no parameters are set, all normal dependencies are returned. Setting any one flag will
    otherwise impact the contents of the returned list.

    Args:
        normal (bool, optional): If True, normal dependencies are included in the
            output list. Defaults to False.
        normal_dev (bool, optional): If True, normla dev dependencies will be
            included in the output list. Defaults to False.
        proc_macro (bool, optional): If True, proc_macro dependencies are included
            in the output list. Defaults to False.
        proc_macro_dev (bool, optional): If True, dev proc_macro dependencies are
            included in the output list. Defaults to False.
        package_name (str, optional): The package name of the set of dependencies to look up.
            Defaults to `native.package_name()`.

    Returns:
        list: A list of labels to cargo-raze generated targets (str)
    """

    if not package_name:
        package_name = native.package_name()

    # Determine the relevant maps to use
    all_dependency_maps = []
    if normal:
        all_dependency_maps.append(_DEPENDENCIES)
    if normal_dev:
        all_dependency_maps.append(_DEV_DEPENDENCIES)
    if proc_macro:
        all_dependency_maps.append(_PROC_MACRO_DEPENDENCIES)
    if proc_macro_dev:
        all_dependency_maps.append(_DEV_PROC_MACRO_DEPENDENCIES)

    # Default to always using normal dependencies
    if not all_dependency_maps:
        all_dependency_maps.append(_DEPENDENCIES)

    dependencies = _flatten_dependency_maps(all_dependency_maps)

    if not dependencies:
        return []

    return dependencies[package_name].values()

def _flatten_dependency_maps(all_dependency_maps):
    """Flatten a list of dependency maps into one dictionary.

    Dependency maps have the following structure:

    ```python
    DEPENDENCIES_MAP = {
        # The first key in the map is a Bazel package
        # name of the workspace this file is defined in.
        "package_name": {

            # An alias to a crate target.     # The label of the crate target the
            # Aliases are only crate names.   # alias refers to.
            "alias":                          "@full//:label",
        }
    }
    ```

    Args:
        all_dependency_maps (list): A list of dicts as described above

    Returns:
        dict: A dictionary as described above
    """
    dependencies = {}

    for dep_map in all_dependency_maps:
        for pkg_name in dep_map:
            if pkg_name not in dependencies:
                # Add a non-frozen dict to the collection of dependencies
                dependencies.setdefault(pkg_name, dict(dep_map[pkg_name].items()))
                continue

            duplicate_crate_aliases = [key for key in dependencies[pkg_name] if key in dep_map[pkg_name]]
            if duplicate_crate_aliases:
                fail("There should be no duplicate crate aliases: {}".format(duplicate_crate_aliases))

            dependencies[pkg_name].update(dep_map[pkg_name])

    return dependencies

def rust_fetch_remote_crates():
    """This function defines a collection of repos and should be called in a WORKSPACE file"""
    maybe(
        http_archive,
        name = "rust__addr2line__0_17_0",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/addr2line/0.17.0/download",
        type = "tar.gz",
        sha256 = "b9ecd88a8c8378ca913a680cd98f0f13ac67383d35993f86c90a70e3f137816b",
        strip_prefix = "addr2line-0.17.0",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.addr2line-0.17.0.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__adler__1_0_2",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/adler/1.0.2/download",
        type = "tar.gz",
        sha256 = "f26201604c87b1e01bd3d98f8d5d9a8fcbb815e8cedb41ffccbeb4bf593a35fe",
        strip_prefix = "adler-1.0.2",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.adler-1.0.2.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__aes_soft__0_6_4",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/aes-soft/0.6.4/download",
        type = "tar.gz",
        sha256 = "be14c7498ea50828a38d0e24a765ed2effe92a705885b57d029cd67d45744072",
        strip_prefix = "aes-soft-0.6.4",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.aes-soft-0.6.4.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__atty__0_2_14",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/atty/0.2.14/download",
        type = "tar.gz",
        sha256 = "d9b39be18770d11421cdb1b9947a45dd3f37e93092cbf377614828a319d5fee8",
        strip_prefix = "atty-0.2.14",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.atty-0.2.14.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__autocfg__1_0_1",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/autocfg/1.0.1/download",
        type = "tar.gz",
        sha256 = "cdb031dd78e28731d87d56cc8ffef4a8f36ca26c38fe2de700543e627f8a464a",
        strip_prefix = "autocfg-1.0.1",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.autocfg-1.0.1.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__backtrace__0_3_63",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/backtrace/0.3.63/download",
        type = "tar.gz",
        sha256 = "321629d8ba6513061f26707241fa9bc89524ff1cd7a915a97ef0c62c666ce1b6",
        strip_prefix = "backtrace-0.3.63",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.backtrace-0.3.63.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__bincode__1_3_3",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/bincode/1.3.3/download",
        type = "tar.gz",
        sha256 = "b1f45e9417d87227c7a56d22e471c6206462cba514c7590c09aff4cf6d1ddcad",
        strip_prefix = "bincode-1.3.3",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.bincode-1.3.3.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__bitflags__1_3_2",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/bitflags/1.3.2/download",
        type = "tar.gz",
        sha256 = "bef38d45163c2f1dde094a7dfd33ccf595c92905c8f8f4fdc18d06fb1037718a",
        strip_prefix = "bitflags-1.3.2",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.bitflags-1.3.2.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__bstr__0_2_17",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/bstr/0.2.17/download",
        type = "tar.gz",
        sha256 = "ba3569f383e8f1598449f1a423e72e99569137b47740b1da11ef19af3d5c3223",
        strip_prefix = "bstr-0.2.17",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.bstr-0.2.17.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__bumpalo__3_8_0",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/bumpalo/3.8.0/download",
        type = "tar.gz",
        sha256 = "8f1e260c3a9040a7c19a12468758f4c16f31a81a1fe087482be9570ec864bb6c",
        strip_prefix = "bumpalo-3.8.0",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.bumpalo-3.8.0.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__cast__0_2_7",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/cast/0.2.7/download",
        type = "tar.gz",
        sha256 = "4c24dab4283a142afa2fdca129b80ad2c6284e073930f964c3a1293c225ee39a",
        strip_prefix = "cast-0.2.7",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.cast-0.2.7.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__cc__1_0_72",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/cc/1.0.72/download",
        type = "tar.gz",
        sha256 = "22a9137b95ea06864e018375b72adfb7db6e6f68cfc8df5a04d00288050485ee",
        strip_prefix = "cc-1.0.72",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.cc-1.0.72.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__cfg_if__1_0_0",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/cfg-if/1.0.0/download",
        type = "tar.gz",
        sha256 = "baf1de4339761588bc0619e3cbc0120ee582ebb74b53b4efbf79117bd2da40fd",
        strip_prefix = "cfg-if-1.0.0",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.cfg-if-1.0.0.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__cipher__0_2_5",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/cipher/0.2.5/download",
        type = "tar.gz",
        sha256 = "12f8e7987cbd042a63249497f41aed09f8e65add917ea6566effbc56578d6801",
        strip_prefix = "cipher-0.2.5",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.cipher-0.2.5.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__clap__2_34_0",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/clap/2.34.0/download",
        type = "tar.gz",
        sha256 = "a0610544180c38b88101fecf2dd634b174a62eef6946f84dfc6a7127512b381c",
        strip_prefix = "clap-2.34.0",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.clap-2.34.0.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__clap__3_1_1",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/clap/3.1.1/download",
        type = "tar.gz",
        sha256 = "6d76c22c9b9b215eeb8d016ad3a90417bd13cb24cf8142756e6472445876cab7",
        strip_prefix = "clap-3.1.1",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.clap-3.1.1.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__codespan_reporting__0_11_1",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/codespan-reporting/0.11.1/download",
        type = "tar.gz",
        sha256 = "3538270d33cc669650c4b093848450d380def10c331d38c768e34cac80576e6e",
        strip_prefix = "codespan-reporting-0.11.1",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.codespan-reporting-0.11.1.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__colored__2_0_0",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/colored/2.0.0/download",
        type = "tar.gz",
        sha256 = "b3616f750b84d8f0de8a58bda93e08e2a81ad3f523089b05f1dffecab48c6cbd",
        strip_prefix = "colored-2.0.0",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.colored-2.0.0.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__concrete__0_1_11",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/concrete/0.1.11/download",
        type = "tar.gz",
        sha256 = "2cf096f091cdcdcd6de4497998727853ba6fc3e7ef7210207ca60a941ae82802",
        strip_prefix = "concrete-0.1.11",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.concrete-0.1.11.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__concrete_boolean__0_1_0",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/concrete-boolean/0.1.0/download",
        type = "tar.gz",
        sha256 = "10741af48d30c6f92560344dd4d27587182cea2423a86eea53f6413e3b77244b",
        strip_prefix = "concrete-boolean-0.1.0",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.concrete-boolean-0.1.0.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__concrete_commons__0_1_1",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/concrete-commons/0.1.1/download",
        type = "tar.gz",
        sha256 = "babe58f12d6e7a0045b13e10a8eb67b7af50eadc061438ce1e8b016b9962912d",
        strip_prefix = "concrete-commons-0.1.1",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.concrete-commons-0.1.1.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__concrete_core__0_1_10",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/concrete-core/0.1.10/download",
        type = "tar.gz",
        sha256 = "866871b087c9ddab7d03d6c8cf67e53838babc7de30f06c017ed96bdd79bc5cc",
        strip_prefix = "concrete-core-0.1.10",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.concrete-core-0.1.10.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__concrete_csprng__0_1_7",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/concrete-csprng/0.1.7/download",
        type = "tar.gz",
        sha256 = "571a3aec821eaa7445e5b598b236270192e4878c8d762e804f4dd39571fc5414",
        strip_prefix = "concrete-csprng-0.1.7",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.concrete-csprng-0.1.7.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__concrete_fftw__0_1_2",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/concrete-fftw/0.1.2/download",
        type = "tar.gz",
        sha256 = "573d29f6d683d4c703ef25ec560877e790388823b932f558566e1140404f2eea",
        strip_prefix = "concrete-fftw-0.1.2",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.concrete-fftw-0.1.2.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__concrete_fftw_sys__0_1_2",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/concrete-fftw-sys/0.1.2/download",
        type = "tar.gz",
        sha256 = "0888155c603c526d038ec18213657ed609763e66eae9041196ca78b3f0e6dcbb",
        strip_prefix = "concrete-fftw-sys-0.1.2",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.concrete-fftw-sys-0.1.2.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__concrete_npe__0_1_9",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/concrete-npe/0.1.9/download",
        type = "tar.gz",
        sha256 = "9812f0ffdfb6ed419fd7ea28ab9ec9650848c2b1953eea0a1ead53ae72f12c0b",
        strip_prefix = "concrete-npe-0.1.9",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.concrete-npe-0.1.9.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__criterion__0_3_5",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/criterion/0.3.5/download",
        type = "tar.gz",
        sha256 = "1604dafd25fba2fe2d5895a9da139f8dc9b319a5fe5354ca137cbbce4e178d10",
        strip_prefix = "criterion-0.3.5",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.criterion-0.3.5.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__criterion_plot__0_4_4",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/criterion-plot/0.4.4/download",
        type = "tar.gz",
        sha256 = "d00996de9f2f7559f7f4dc286073197f83e92256a59ed395f9aac01fe717da57",
        strip_prefix = "criterion-plot-0.4.4",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.criterion-plot-0.4.4.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__crossbeam_channel__0_5_1",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/crossbeam-channel/0.5.1/download",
        type = "tar.gz",
        sha256 = "06ed27e177f16d65f0f0c22a213e17c696ace5dd64b14258b52f9417ccb52db4",
        strip_prefix = "crossbeam-channel-0.5.1",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.crossbeam-channel-0.5.1.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__crossbeam_deque__0_8_1",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/crossbeam-deque/0.8.1/download",
        type = "tar.gz",
        sha256 = "6455c0ca19f0d2fbf751b908d5c55c1f5cbc65e03c4225427254b46890bdde1e",
        strip_prefix = "crossbeam-deque-0.8.1",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.crossbeam-deque-0.8.1.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__crossbeam_epoch__0_9_5",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/crossbeam-epoch/0.9.5/download",
        type = "tar.gz",
        sha256 = "4ec02e091aa634e2c3ada4a392989e7c3116673ef0ac5b72232439094d73b7fd",
        strip_prefix = "crossbeam-epoch-0.9.5",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.crossbeam-epoch-0.9.5.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__crossbeam_utils__0_8_5",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/crossbeam-utils/0.8.5/download",
        type = "tar.gz",
        sha256 = "d82cfc11ce7f2c3faef78d8a684447b40d503d9681acebed6cb728d45940c4db",
        strip_prefix = "crossbeam-utils-0.8.5",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.crossbeam-utils-0.8.5.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__csv__1_1_6",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/csv/1.1.6/download",
        type = "tar.gz",
        sha256 = "22813a6dc45b335f9bade10bf7271dc477e81113e89eb251a0bc2a8a81c536e1",
        strip_prefix = "csv-1.1.6",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.csv-1.1.6.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__csv_core__0_1_10",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/csv-core/0.1.10/download",
        type = "tar.gz",
        sha256 = "2b2466559f260f48ad25fe6317b3c8dac77b5bdb5763ac7d9d6103530663bc90",
        strip_prefix = "csv-core-0.1.10",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.csv-core-0.1.10.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__cxx__1_0_65",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/cxx/1.0.65/download",
        type = "tar.gz",
        sha256 = "8f0432498c7382a83e9d40a7e4293cdd789ca561aac0d0c17ddb32e3627d989b",
        strip_prefix = "cxx-1.0.65",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.cxx-1.0.65.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__cxxbridge_cmd__1_0_65",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/cxxbridge-cmd/1.0.65/download",
        type = "tar.gz",
        sha256 = "8ba836892b958346427ac6dbeb3fa21f61a126b3710517ef50dcd389524d3cd1",
        strip_prefix = "cxxbridge-cmd-1.0.65",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.cxxbridge-cmd-1.0.65.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__cxxbridge_flags__1_0_65",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/cxxbridge-flags/1.0.65/download",
        type = "tar.gz",
        sha256 = "63125c8c1bd5203a8dbf572e502c220383d409e8c287ae4bc455c2bc37de9223",
        strip_prefix = "cxxbridge-flags-1.0.65",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.cxxbridge-flags-1.0.65.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__cxxbridge_macro__1_0_65",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/cxxbridge-macro/1.0.65/download",
        type = "tar.gz",
        sha256 = "4cd893a7a7317226890316f59576112030de3484dca8573fe0d6c28323902697",
        strip_prefix = "cxxbridge-macro-1.0.65",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.cxxbridge-macro-1.0.65.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__either__1_6_1",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/either/1.6.1/download",
        type = "tar.gz",
        sha256 = "e78d4f1cc4ae33bbfc157ed5d5a5ef3bc29227303d595861deb238fcec4e9457",
        strip_prefix = "either-1.6.1",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.either-1.6.1.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__fastrand__1_6_0",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/fastrand/1.6.0/download",
        type = "tar.gz",
        sha256 = "779d043b6a0b90cc4c0ed7ee380a6504394cee7efd7db050e3774eee387324b2",
        strip_prefix = "fastrand-1.6.0",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.fastrand-1.6.0.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__fs_extra__1_2_0",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/fs_extra/1.2.0/download",
        type = "tar.gz",
        sha256 = "2022715d62ab30faffd124d40b76f4134a550a87792276512b18d63272333394",
        strip_prefix = "fs_extra-1.2.0",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.fs_extra-1.2.0.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__generic_array__0_14_4",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/generic-array/0.14.4/download",
        type = "tar.gz",
        sha256 = "501466ecc8a30d1d3b7fc9229b122b2ce8ed6e9d9223f1138d4babb253e51817",
        strip_prefix = "generic-array-0.14.4",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.generic-array-0.14.4.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__gimli__0_26_1",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/gimli/0.26.1/download",
        type = "tar.gz",
        sha256 = "78cc372d058dcf6d5ecd98510e7fbc9e5aec4d21de70f65fea8fecebcd881bd4",
        strip_prefix = "gimli-0.26.1",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.gimli-0.26.1.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__half__1_8_2",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/half/1.8.2/download",
        type = "tar.gz",
        sha256 = "eabb4a44450da02c90444cf74558da904edde8fb4e9035a9a6a4e15445af0bd7",
        strip_prefix = "half-1.8.2",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.half-1.8.2.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__hashbrown__0_11_2",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/hashbrown/0.11.2/download",
        type = "tar.gz",
        sha256 = "ab5ef0d4909ef3724cc8cce6ccc8572c5c817592e9285f5464f8e86f8bd3726e",
        strip_prefix = "hashbrown-0.11.2",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.hashbrown-0.11.2.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__hermit_abi__0_1_19",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/hermit-abi/0.1.19/download",
        type = "tar.gz",
        sha256 = "62b467343b94ba476dcb2500d242dadbb39557df889310ac77c5d99100aaac33",
        strip_prefix = "hermit-abi-0.1.19",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.hermit-abi-0.1.19.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__indexmap__1_8_0",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/indexmap/1.8.0/download",
        type = "tar.gz",
        sha256 = "282a6247722caba404c065016bbfa522806e51714c34f5dfc3e4a3a46fcb4223",
        strip_prefix = "indexmap-1.8.0",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.indexmap-1.8.0.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__instant__0_1_12",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/instant/0.1.12/download",
        type = "tar.gz",
        sha256 = "7a5bbe824c507c5da5956355e86a746d82e0e1464f65d862cc5e71da70e94b2c",
        strip_prefix = "instant-0.1.12",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.instant-0.1.12.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__itertools__0_10_3",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/itertools/0.10.3/download",
        type = "tar.gz",
        sha256 = "a9a9d19fa1e79b6215ff29b9d6880b706147f16e9b1dbb1e4e5947b5b02bc5e3",
        strip_prefix = "itertools-0.10.3",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.itertools-0.10.3.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__itertools__0_9_0",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/itertools/0.9.0/download",
        type = "tar.gz",
        sha256 = "284f18f85651fe11e8a991b2adb42cb078325c996ed026d994719efcfca1d54b",
        strip_prefix = "itertools-0.9.0",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.itertools-0.9.0.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__itoa__0_4_8",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/itoa/0.4.8/download",
        type = "tar.gz",
        sha256 = "b71991ff56294aa922b450139ee08b3bfc70982c6b2c7562771375cf73542dd4",
        strip_prefix = "itoa-0.4.8",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.itoa-0.4.8.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__js_sys__0_3_55",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/js-sys/0.3.55/download",
        type = "tar.gz",
        sha256 = "7cc9ffccd38c451a86bf13657df244e9c3f37493cce8e5e21e940963777acc84",
        strip_prefix = "js-sys-0.3.55",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.js-sys-0.3.55.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__lazy_static__1_4_0",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/lazy_static/1.4.0/download",
        type = "tar.gz",
        sha256 = "e2abad23fbc42b3700f2f279844dc832adb2b2eb069b2df918f455c4e18cc646",
        strip_prefix = "lazy_static-1.4.0",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.lazy_static-1.4.0.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__libc__0_2_109",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/libc/0.2.109/download",
        type = "tar.gz",
        sha256 = "f98a04dce437184842841303488f70d0188c5f51437d2a834dc097eafa909a01",
        strip_prefix = "libc-0.2.109",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.libc-0.2.109.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__link_cplusplus__1_0_6",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/link-cplusplus/1.0.6/download",
        type = "tar.gz",
        sha256 = "f8cae2cd7ba2f3f63938b9c724475dfb7b9861b545a90324476324ed21dbc8c8",
        strip_prefix = "link-cplusplus-1.0.6",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.link-cplusplus-1.0.6.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__log__0_4_14",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/log/0.4.14/download",
        type = "tar.gz",
        sha256 = "51b9bbe6c47d51fc3e1a9b945965946b4c44142ab8792c50835a980d362c2710",
        strip_prefix = "log-0.4.14",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.log-0.4.14.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__memchr__2_4_1",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/memchr/2.4.1/download",
        type = "tar.gz",
        sha256 = "308cc39be01b73d0d18f82a0e7b2a3df85245f84af96fdddc5d202d27e47b86a",
        strip_prefix = "memchr-2.4.1",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.memchr-2.4.1.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__memoffset__0_6_5",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/memoffset/0.6.5/download",
        type = "tar.gz",
        sha256 = "5aa361d4faea93603064a027415f07bd8e1d5c88c9fbf68bf56a285428fd79ce",
        strip_prefix = "memoffset-0.6.5",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.memoffset-0.6.5.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__miniz_oxide__0_4_4",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/miniz_oxide/0.4.4/download",
        type = "tar.gz",
        sha256 = "a92518e98c078586bc6c934028adcca4c92a53d6a958196de835170a01d84e4b",
        strip_prefix = "miniz_oxide-0.4.4",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.miniz_oxide-0.4.4.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__num_complex__0_4_0",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/num-complex/0.4.0/download",
        type = "tar.gz",
        sha256 = "26873667bbbb7c5182d4a37c1add32cdf09f841af72da53318fdb81543c15085",
        strip_prefix = "num-complex-0.4.0",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.num-complex-0.4.0.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__num_traits__0_2_14",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/num-traits/0.2.14/download",
        type = "tar.gz",
        sha256 = "9a64b1ec5cda2586e284722486d802acf1f7dbdc623e2bfc57e65ca1cd099290",
        strip_prefix = "num-traits-0.2.14",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.num-traits-0.2.14.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__num_cpus__1_13_0",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/num_cpus/1.13.0/download",
        type = "tar.gz",
        sha256 = "05499f3756671c15885fee9034446956fff3f243d6077b91e5767df161f766b3",
        strip_prefix = "num_cpus-1.13.0",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.num_cpus-1.13.0.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__object__0_27_1",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/object/0.27.1/download",
        type = "tar.gz",
        sha256 = "67ac1d3f9a1d3616fd9a60c8d74296f22406a238b6a72f5cc1e6f314df4ffbf9",
        strip_prefix = "object-0.27.1",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.object-0.27.1.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__oorandom__11_1_3",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/oorandom/11.1.3/download",
        type = "tar.gz",
        sha256 = "0ab1bc2a289d34bd04a330323ac98a1b4bc82c9d9fcb1e66b63caa84da26b575",
        strip_prefix = "oorandom-11.1.3",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.oorandom-11.1.3.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__opaque_debug__0_3_0",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/opaque-debug/0.3.0/download",
        type = "tar.gz",
        sha256 = "624a8340c38c1b80fd549087862da4ba43e08858af025b236e509b6649fc13d5",
        strip_prefix = "opaque-debug-0.3.0",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.opaque-debug-0.3.0.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__os_str_bytes__6_0_0",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/os_str_bytes/6.0.0/download",
        type = "tar.gz",
        sha256 = "8e22443d1643a904602595ba1cd8f7d896afe56d26712531c5ff73a15b2fbf64",
        strip_prefix = "os_str_bytes-6.0.0",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.os_str_bytes-6.0.0.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__plotters__0_3_1",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/plotters/0.3.1/download",
        type = "tar.gz",
        sha256 = "32a3fd9ec30b9749ce28cd91f255d569591cdf937fe280c312143e3c4bad6f2a",
        strip_prefix = "plotters-0.3.1",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.plotters-0.3.1.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__plotters_backend__0_3_2",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/plotters-backend/0.3.2/download",
        type = "tar.gz",
        sha256 = "d88417318da0eaf0fdcdb51a0ee6c3bed624333bff8f946733049380be67ac1c",
        strip_prefix = "plotters-backend-0.3.2",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.plotters-backend-0.3.2.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__plotters_svg__0_3_1",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/plotters-svg/0.3.1/download",
        type = "tar.gz",
        sha256 = "521fa9638fa597e1dc53e9412a4f9cefb01187ee1f7413076f9e6749e2885ba9",
        strip_prefix = "plotters-svg-0.3.1",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.plotters-svg-0.3.1.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__proc_macro2__1_0_33",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/proc-macro2/1.0.33/download",
        type = "tar.gz",
        sha256 = "fb37d2df5df740e582f28f8560cf425f52bb267d872fe58358eadb554909f07a",
        strip_prefix = "proc-macro2-1.0.33",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.proc-macro2-1.0.33.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__quote__1_0_10",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/quote/1.0.10/download",
        type = "tar.gz",
        sha256 = "38bc8cc6a5f2e3655e0899c1b848643b2562f853f114bfec7be120678e3ace05",
        strip_prefix = "quote-1.0.10",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.quote-1.0.10.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__rayon__1_5_1",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/rayon/1.5.1/download",
        type = "tar.gz",
        sha256 = "c06aca804d41dbc8ba42dfd964f0d01334eceb64314b9ecf7c5fad5188a06d90",
        strip_prefix = "rayon-1.5.1",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.rayon-1.5.1.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__rayon_core__1_9_1",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/rayon-core/1.9.1/download",
        type = "tar.gz",
        sha256 = "d78120e2c850279833f1dd3582f730c4ab53ed95aeaaaa862a2a5c71b1656d8e",
        strip_prefix = "rayon-core-1.9.1",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.rayon-core-1.9.1.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__redox_syscall__0_2_10",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/redox_syscall/0.2.10/download",
        type = "tar.gz",
        sha256 = "8383f39639269cde97d255a32bdb68c047337295414940c68bdd30c2e13203ff",
        strip_prefix = "redox_syscall-0.2.10",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.redox_syscall-0.2.10.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__regex__1_5_4",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/regex/1.5.4/download",
        type = "tar.gz",
        sha256 = "d07a8629359eb56f1e2fb1652bb04212c072a87ba68546a04065d525673ac461",
        strip_prefix = "regex-1.5.4",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.regex-1.5.4.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__regex_automata__0_1_10",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/regex-automata/0.1.10/download",
        type = "tar.gz",
        sha256 = "6c230d73fb8d8c1b9c0b3135c5142a8acee3a0558fb8db5cf1cb65f8d7862132",
        strip_prefix = "regex-automata-0.1.10",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.regex-automata-0.1.10.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__regex_syntax__0_6_25",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/regex-syntax/0.6.25/download",
        type = "tar.gz",
        sha256 = "f497285884f3fcff424ffc933e56d7cbca511def0c9831a7f9b5f6153e3cc89b",
        strip_prefix = "regex-syntax-0.6.25",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.regex-syntax-0.6.25.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__remove_dir_all__0_5_3",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/remove_dir_all/0.5.3/download",
        type = "tar.gz",
        sha256 = "3acd125665422973a33ac9d3dd2df85edad0f4ae9b00dafb1a05e43a9f5ef8e7",
        strip_prefix = "remove_dir_all-0.5.3",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.remove_dir_all-0.5.3.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__rustc_demangle__0_1_21",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/rustc-demangle/0.1.21/download",
        type = "tar.gz",
        sha256 = "7ef03e0a2b150c7a90d01faf6254c9c48a41e95fb2a8c2ac1c6f0d2b9aefc342",
        strip_prefix = "rustc-demangle-0.1.21",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.rustc-demangle-0.1.21.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__rustc_version__0_4_0",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/rustc_version/0.4.0/download",
        type = "tar.gz",
        sha256 = "bfa0f585226d2e68097d4f95d113b15b83a82e819ab25717ec0590d9584ef366",
        strip_prefix = "rustc_version-0.4.0",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.rustc_version-0.4.0.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__ryu__1_0_6",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/ryu/1.0.6/download",
        type = "tar.gz",
        sha256 = "3c9613b5a66ab9ba26415184cfc41156594925a9cf3a2057e57f31ff145f6568",
        strip_prefix = "ryu-1.0.6",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.ryu-1.0.6.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__same_file__1_0_6",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/same-file/1.0.6/download",
        type = "tar.gz",
        sha256 = "93fc1dc3aaa9bfed95e02e6eadabb4baf7e3078b0bd1b4d7b6b0b68378900502",
        strip_prefix = "same-file-1.0.6",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.same-file-1.0.6.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__scopeguard__1_1_0",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/scopeguard/1.1.0/download",
        type = "tar.gz",
        sha256 = "d29ab0c6d3fc0ee92fe66e2d99f700eab17a8d57d1c1d3b748380fb20baa78cd",
        strip_prefix = "scopeguard-1.1.0",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.scopeguard-1.1.0.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__semver__1_0_4",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/semver/1.0.4/download",
        type = "tar.gz",
        sha256 = "568a8e6258aa33c13358f81fd834adb854c6f7c9468520910a9b1e8fac068012",
        strip_prefix = "semver-1.0.4",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.semver-1.0.4.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__serde__1_0_130",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/serde/1.0.130/download",
        type = "tar.gz",
        sha256 = "f12d06de37cf59146fbdecab66aa99f9fe4f78722e3607577a5375d66bd0c913",
        strip_prefix = "serde-1.0.130",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.serde-1.0.130.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__serde_cbor__0_11_2",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/serde_cbor/0.11.2/download",
        type = "tar.gz",
        sha256 = "2bef2ebfde456fb76bbcf9f59315333decc4fda0b2b44b420243c11e0f5ec1f5",
        strip_prefix = "serde_cbor-0.11.2",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.serde_cbor-0.11.2.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__serde_derive__1_0_130",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/serde_derive/1.0.130/download",
        type = "tar.gz",
        sha256 = "d7bc1a1ab1961464eae040d96713baa5a724a8152c1222492465b54322ec508b",
        strip_prefix = "serde_derive-1.0.130",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.serde_derive-1.0.130.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__serde_json__1_0_72",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/serde_json/1.0.72/download",
        type = "tar.gz",
        sha256 = "d0ffa0837f2dfa6fb90868c2b5468cad482e175f7dad97e7421951e663f2b527",
        strip_prefix = "serde_json-1.0.72",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.serde_json-1.0.72.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__simple_logger__2_1_0",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/simple_logger/2.1.0/download",
        type = "tar.gz",
        sha256 = "c75a9723083573ace81ad0cdfc50b858aa3c366c48636edb4109d73122a0c0ea",
        strip_prefix = "simple_logger-2.1.0",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.simple_logger-2.1.0.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__strsim__0_10_0",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/strsim/0.10.0/download",
        type = "tar.gz",
        sha256 = "73473c0e59e6d5812c5dfe2a064a6444949f089e20eec9a2e5506596494e4623",
        strip_prefix = "strsim-0.10.0",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.strsim-0.10.0.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__syn__1_0_82",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/syn/1.0.82/download",
        type = "tar.gz",
        sha256 = "8daf5dd0bb60cbd4137b1b587d2fc0ae729bc07cf01cd70b36a1ed5ade3b9d59",
        strip_prefix = "syn-1.0.82",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.syn-1.0.82.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__tempfile__3_3_0",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/tempfile/3.3.0/download",
        type = "tar.gz",
        sha256 = "5cdb1ef4eaeeaddc8fbd371e5017057064af0911902ef36b39801f67cc6d79e4",
        strip_prefix = "tempfile-3.3.0",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.tempfile-3.3.0.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__termcolor__1_1_2",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/termcolor/1.1.2/download",
        type = "tar.gz",
        sha256 = "2dfed899f0eb03f32ee8c6a0aabdb8a7949659e3466561fc0adf54e26d88c5f4",
        strip_prefix = "termcolor-1.1.2",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.termcolor-1.1.2.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__textwrap__0_11_0",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/textwrap/0.11.0/download",
        type = "tar.gz",
        sha256 = "d326610f408c7a4eb6f51c37c330e496b08506c9457c9d34287ecc38809fb060",
        strip_prefix = "textwrap-0.11.0",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.textwrap-0.11.0.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__textwrap__0_14_2",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/textwrap/0.14.2/download",
        type = "tar.gz",
        sha256 = "0066c8d12af8b5acd21e00547c3797fde4e8677254a7ee429176ccebbe93dd80",
        strip_prefix = "textwrap-0.14.2",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.textwrap-0.14.2.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__time__0_3_5",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/time/0.3.5/download",
        type = "tar.gz",
        sha256 = "41effe7cfa8af36f439fac33861b66b049edc6f9a32331e2312660529c1c24ad",
        strip_prefix = "time-0.3.5",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.time-0.3.5.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__time_macros__0_2_3",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/time-macros/0.2.3/download",
        type = "tar.gz",
        sha256 = "25eb0ca3468fc0acc11828786797f6ef9aa1555e4a211a60d64cc8e4d1be47d6",
        strip_prefix = "time-macros-0.2.3",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.time-macros-0.2.3.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__tinytemplate__1_2_1",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/tinytemplate/1.2.1/download",
        type = "tar.gz",
        sha256 = "be4d6b5f19ff7664e8c98d03e2139cb510db9b0a60b55f8e8709b689d939b6bc",
        strip_prefix = "tinytemplate-1.2.1",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.tinytemplate-1.2.1.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__typenum__1_14_0",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/typenum/1.14.0/download",
        type = "tar.gz",
        sha256 = "b63708a265f51345575b27fe43f9500ad611579e764c79edbc2037b1121959ec",
        strip_prefix = "typenum-1.14.0",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.typenum-1.14.0.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__unicode_width__0_1_9",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/unicode-width/0.1.9/download",
        type = "tar.gz",
        sha256 = "3ed742d4ea2bd1176e236172c8429aaf54486e7ac098db29ffe6529e0ce50973",
        strip_prefix = "unicode-width-0.1.9",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.unicode-width-0.1.9.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__unicode_xid__0_2_2",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/unicode-xid/0.2.2/download",
        type = "tar.gz",
        sha256 = "8ccb82d61f80a663efe1f787a51b16b5a51e3314d6ac365b08639f52387b33f3",
        strip_prefix = "unicode-xid-0.2.2",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.unicode-xid-0.2.2.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__version_check__0_9_3",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/version_check/0.9.3/download",
        type = "tar.gz",
        sha256 = "5fecdca9a5291cc2b8dcf7dc02453fee791a280f3743cb0905f8822ae463b3fe",
        strip_prefix = "version_check-0.9.3",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.version_check-0.9.3.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__walkdir__2_3_2",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/walkdir/2.3.2/download",
        type = "tar.gz",
        sha256 = "808cf2735cd4b6866113f648b791c6adc5714537bc222d9347bb203386ffda56",
        strip_prefix = "walkdir-2.3.2",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.walkdir-2.3.2.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__wasm_bindgen__0_2_78",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/wasm-bindgen/0.2.78/download",
        type = "tar.gz",
        sha256 = "632f73e236b219150ea279196e54e610f5dbafa5d61786303d4da54f84e47fce",
        strip_prefix = "wasm-bindgen-0.2.78",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.wasm-bindgen-0.2.78.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__wasm_bindgen_backend__0_2_78",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/wasm-bindgen-backend/0.2.78/download",
        type = "tar.gz",
        sha256 = "a317bf8f9fba2476b4b2c85ef4c4af8ff39c3c7f0cdfeed4f82c34a880aa837b",
        strip_prefix = "wasm-bindgen-backend-0.2.78",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.wasm-bindgen-backend-0.2.78.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__wasm_bindgen_macro__0_2_78",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/wasm-bindgen-macro/0.2.78/download",
        type = "tar.gz",
        sha256 = "d56146e7c495528bf6587663bea13a8eb588d39b36b679d83972e1a2dbbdacf9",
        strip_prefix = "wasm-bindgen-macro-0.2.78",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.wasm-bindgen-macro-0.2.78.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__wasm_bindgen_macro_support__0_2_78",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/wasm-bindgen-macro-support/0.2.78/download",
        type = "tar.gz",
        sha256 = "7803e0eea25835f8abdc585cd3021b3deb11543c6fe226dcd30b228857c5c5ab",
        strip_prefix = "wasm-bindgen-macro-support-0.2.78",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.wasm-bindgen-macro-support-0.2.78.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__wasm_bindgen_shared__0_2_78",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/wasm-bindgen-shared/0.2.78/download",
        type = "tar.gz",
        sha256 = "0237232789cf037d5480773fe568aac745bfe2afbc11a863e97901780a6b47cc",
        strip_prefix = "wasm-bindgen-shared-0.2.78",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.wasm-bindgen-shared-0.2.78.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__web_sys__0_3_55",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/web-sys/0.3.55/download",
        type = "tar.gz",
        sha256 = "38eb105f1c59d9eaa6b5cdc92b859d85b926e82cb2e0945cd0c9259faa6fe9fb",
        strip_prefix = "web-sys-0.3.55",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.web-sys-0.3.55.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__winapi__0_3_9",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/winapi/0.3.9/download",
        type = "tar.gz",
        sha256 = "5c839a674fcd7a98952e593242ea400abe93992746761e38641405d28b00f419",
        strip_prefix = "winapi-0.3.9",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.winapi-0.3.9.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__winapi_i686_pc_windows_gnu__0_4_0",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/winapi-i686-pc-windows-gnu/0.4.0/download",
        type = "tar.gz",
        sha256 = "ac3b87c63620426dd9b991e5ce0329eff545bccbbb34f3be09ff6fb6ab51b7b6",
        strip_prefix = "winapi-i686-pc-windows-gnu-0.4.0",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.winapi-i686-pc-windows-gnu-0.4.0.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__winapi_util__0_1_5",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/winapi-util/0.1.5/download",
        type = "tar.gz",
        sha256 = "70ec6ce85bb158151cae5e5c87f95a8e97d2c0c4b001223f33a334e3ce5de178",
        strip_prefix = "winapi-util-0.1.5",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.winapi-util-0.1.5.bazel"),
    )

    maybe(
        http_archive,
        name = "rust__winapi_x86_64_pc_windows_gnu__0_4_0",
        url = "https://crates-io.proxy.ustclug.org/api/v1/crates/winapi-x86_64-pc-windows-gnu/0.4.0/download",
        type = "tar.gz",
        sha256 = "712e227841d057c1ee1cd2fb22fa7e5a5461ae8e48fa2ca79ec42cfc1931183f",
        strip_prefix = "winapi-x86_64-pc-windows-gnu-0.4.0",
        build_file = Label("//third_party/bazel_rust/cargo/remote:BUILD.winapi-x86_64-pc-windows-gnu-0.4.0.bazel"),
    )
