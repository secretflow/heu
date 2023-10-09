## update rust

```shell
rustup update stable
```

## update deps in cargo.toml

```shell
cargo upgrade
```

## generate bazel build file from cargo.toml

```shell
# Install cargo-raze. (optional)
cargo install cargo-raze

cargo raze
```

detail doc: https://github.com/google/cargo-raze
