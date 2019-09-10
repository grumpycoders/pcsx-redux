# Dockerfile for grumpycoders/pcsx-redux-build

FROM ubuntu:18.04 as builder
RUN apt update
RUN apt install -y wget
RUN apt install -y build-essential bison flex libgmp3-dev libmpc-dev libmpfr-dev texinfo
RUN wget https://ftp.gnu.org/gnu/binutils/binutils-2.32.tar.xz
RUN wget https://ftp.gnu.org/gnu/gcc/gcc-9.2.0/gcc-9.2.0.tar.xz
RUN tar xvf binutils-2.32.tar.xz
RUN tar xvf gcc-9.2.0.tar.xz
RUN mkdir /build-binutils
WORKDIR /build-binutils
RUN ../binutils-2.32/configure --target=mipsel-elf --enable-multilib --disable-nls --disable-werror
RUN make -j
RUN make install
RUN mkdir /build-gcc
WORKDIR /build-gcc
RUN ../gcc-9.2.0/configure --target=mipsel-elf --enable-languages=c --disable-nls --without-headers --with-float=soft --enable-multilib --disable-libssp --disable-libgomp
RUN make -j
RUN make install

FROM ubuntu:18.04

RUN apt update
RUN apt install -y wget gnupg
RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
RUN apt update
RUN apt install -y software-properties-common
RUN apt-add-repository "deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-9 main"
RUN apt update
RUN apt install -y make g++-8 clang-9 git
RUN apt install -y pkg-config libsdl2-dev libavcodec-dev libavformat-dev libavutil-dev libswresample-dev zlib1g-dev libglfw3-dev libuv1-dev
COPY --from=builder /usr/local /usr/local

RUN mkdir /project
WORKDIR /project
