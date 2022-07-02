# syntax=docker/dockerfile:1.3-labs
FROM openanolis/anolisos:8.4-x86_64

ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# install raven-release for lcov
RUN dnf -y update && \
    dnf -y install https://pkgs.dyn.su/el8/base/x86_64/raven-release-1.0-3.el8.noarch.rpm && \
    dnf -y install raven-release && \
    dnf clean all

# repo address for bazel
# https://docs.bazel.build/versions/master/install-redhat.html
ADD https://copr.fedorainfracloud.org/coprs/vbatts/bazel/repo/epel-7/vbatts-bazel-epel-7.repo /etc/yum.repos.d/

RUN dnf --enablerepo=raven-extras install -y \
        autoconf automake cmake3 ninja-build \
        gcc-toolset-10 bazel4 openssh openssl \
        tree iproute jq git lcov \
    && dnf clean all

ENV PATH=/opt/rh/gcc-toolset-10/root/usr/bin:$PATH

# install Rust
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y

# rust 替换成国内源
COPY <<EOF /root/.cargo/config
[source.crates-io]
registry = \"https://github.com/rust-lang/crates.io-index\"
replace-with = \'ustc\'
[source.ustc]
registry = \"git://mirrors.ustc.edu.cn/crates.io-index\"
EOF

# install python
RUN dnf install -y python39-devel && \
    dnf clean all && \
    ln -s /usr/bin/python3 /usr/bin/python

# generate ssh-keys (for CI to access git repo)
RUN ssh-keygen -t rsa -b 4096 -f $HOME/.ssh/id_rsa -N '' \
    && cat $HOME/.ssh/id_rsa.pub
