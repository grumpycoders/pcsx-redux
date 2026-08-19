# Dockerfile for ghcr.io/grumpycoders/pcsx-redux-build
#
# This one needs the repository root as its build context, as the first stage
# builds the mips toolchain using tools/linux-mips/spawn-compiler.sh:
#
#   docker build -f tools/build/Dockerfile -t ghcr.io/grumpycoders/pcsx-redux-build .

FROM ubuntu:26.04 AS toolchain

ENV DEBIAN_FRONTEND noninteractive
ENV TZ Etc/GMT

RUN apt update
RUN apt dist-upgrade -y
RUN apt install -y make g++ wget bzip2 xz-utils bison flex texinfo
RUN apt install -y libgmp-dev libmpfr-dev libmpc-dev

ARG JOBS=

WORKDIR /tmp/toolchain
COPY tools/linux-mips/spawn-compiler.sh .
RUN JOBS=$JOBS sh spawn-compiler.sh

FROM ubuntu:26.04

# The tzdata package isn't docker-friendly, and something pulls it.
ENV DEBIAN_FRONTEND noninteractive
ENV TZ Etc/GMT

RUN apt update
RUN apt dist-upgrade -y

# Utility packages
RUN apt install -y git
RUN apt install -y make
RUN apt install -y pkg-config

# Compilers & base libraries
RUN apt install -y g++

# Development packages
RUN apt install -y libavcodec-dev
RUN apt install -y libavformat-dev
RUN apt install -y libavutil-dev
RUN apt install -y libcapstone-dev
RUN apt install -y libcurl4-openssl-dev
RUN apt install -y libfreetype-dev
RUN apt install -y libsdl3-dev
RUN apt install -y libswresample-dev
RUN apt install -y libuv1-dev
RUN apt install -y zlib1g-dev

# CI utilities
RUN apt install -y curl wget
RUN apt install -y xvfb
RUN apt install -y python3-pip python3-setuptools patchelf desktop-file-utils libgdk-pixbuf-2.0-dev fakeroot strace
RUN apt install -y glibc-tools lcov
RUN apt install -y file

# AppImage dependencies
RUN apt install -y libfuse2t64
RUN apt install -y fuse

# AppImage tools
RUN apt install -y imagemagick-7.q16 gtk-update-icon-cache appstream
RUN apt install -y squashfs-tools zip zsync

# The mips toolchain, built from source in the first stage. Ubuntu dropped the
# mipsel cross compilers, so there's no distribution package to install here.
COPY --from=toolchain /usr/local /usr/local

# Both projects name their releases after uname's spelling of the architecture,
# which is also the one the AppImage ends up carrying.
WORKDIR /tmp
RUN wget https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-`uname -m`.AppImage && \
    chmod +x appimagetool-`uname -m`.AppImage && \
    mv appimagetool-`uname -m`.AppImage /usr/bin/appimagetool
RUN wget https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-`uname -m`.AppImage && \
    chmod +x linuxdeploy-`uname -m`.AppImage && \
    mv linuxdeploy-`uname -m`.AppImage /usr/bin/linuxdeploy

RUN mkdir /project
ENV HOME=/home/coder
RUN mkdir -p /home/coder/dconf
RUN chmod a+rwx /home/coder/dconf

WORKDIR /project
