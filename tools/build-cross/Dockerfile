# Dockerfile for grumpycoders/pcsx-redux-build-cross
# IMPORTANT: to build this file, the package qemu-user-static needs to be
# installed on the host machine.

FROM debian:bullseye-slim

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
RUN apt install -y g++-10
RUN apt install -y gcc-10
RUN apt install -y gcc
# CI utilities
RUN apt install -y curl wget
RUN apt install -y python


# Cross Compiler stuff
RUN apt install -y debootstrap
RUN apt install -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
RUN apt install -y qemu-user-static

WORKDIR /

# Create directory to hold aarch64 sysroot
RUN mkdir -p /opt/cross/sysroot

# Run debootstrap to pull down Debian bullseye aarch64 rootfs
RUN debootstrap --arch=arm64 --variant=minbase \
    --include=\
build-essential,\
pkg-config,\
libavcodec-dev,\
libavformat-dev,\
libavutil-dev,\
libcapstone-dev,\
libcurl4-openssl-dev,\
libfreetype-dev,\
libglfw3-dev,\
libswresample-dev,\
libuv1-dev,\
zlib1g-dev --foreign bullseye /opt/cross/sysroot

# Copy qemu-user-static over to sysroot so second stage can run
RUN cp /usr/bin/qemu-aarch64-static /opt/cross/sysroot/usr/bin/

# chroot into aarch64 sysroot and run debootstrap second stage to unpack packages and set up symlinks
RUN chroot /opt/cross/sysroot /usr/bin/qemu-aarch64-static /bin/sh -c "/debootstrap/debootstrap --second-stage"

# Fix symlinks in the sysroot
WORKDIR /opt/cross
RUN wget https://raw.githubusercontent.com/abhiTronix/rpi_rootfs/master/scripts/sysroot-relativelinks.py
RUN chmod +x sysroot-relativelinks.py
RUN ./sysroot-relativelinks.py sysroot

RUN mkdir /project
RUN mkdir -p /home/coder/dconf
RUN chmod a+rwx /home/coder/dconf
WORKDIR /project
