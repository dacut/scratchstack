FROM public.ecr.aws/amazonlinux/amazonlinux:2
RUN yum update -y
RUN yum groupinstall -y 'Development Tools'
RUN yum install -y llvm clang
RUN yum install -y \
https://dist.ionosphere.io/amzn2/RPMS/x86_64/postgresql12-12.6-1.amzn2.x86_64.rpm \
https://dist.ionosphere.io/amzn2/RPMS/x86_64/postgresql12-devel-12.6-1.amzn2.x86_64.rpm \
https://dist.ionosphere.io/amzn2/RPMS/x86_64/postgresql12-libs-12.6-1.amzn2.x86_64.rpm
COPY rustup.sh /tmp
RUN sh /tmp/rustup.sh --default-toolchain nightly --profile default -y
ENV PATH=/root/.cargo/bin:/usr/pgsql-12/bin:$PATH
RUN cargo search
COPY services /build/services/
COPY Cargo.toml Cargo.lock /build/
WORKDIR /build
RUN cargo build
RUN cargo install diesel_cli --no-default-features --features postgres
