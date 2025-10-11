# Dockerfile for ghcr.io/grumpycoders/pcsx-redux-build

FROM ubuntu:24.04

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
RUN apt install -y g++-mipsel-linux-gnu

# Development packages
RUN apt install -y libavcodec-dev
RUN apt install -y libavformat-dev
RUN apt install -y libavutil-dev
RUN apt install -y libcapstone-dev
RUN apt install -y libcurl4-openssl-dev
RUN apt install -y libfreetype-dev
RUN apt install -y libglfw3-dev
RUN apt install -y libswresample-dev
RUN apt install -y libuv1-dev
RUN apt install -y zlib1g-dev

# CI utilities
RUN apt install -y curl wget
RUN apt install -y xvfb
RUN apt install -y python3-pip python3-setuptools patchelf desktop-file-utils libgdk-pixbuf2.0-dev fakeroot strace
RUN apt install -y glibc-tools lcov
RUN apt install -y file

# AppImage dependencies
RUN apt install -y libfuse2t64
RUN apt install -y fuse

# AppImage tools
RUN apt install -y imagemagick-6.q16 gtk-update-icon-cache appstream
RUN apt install -y squashfs-tools zip zsync

WORKDIR /tmp
RUN wget https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage && \
    chmod +x appimagetool-x86_64.AppImage && \
    mv appimagetool-x86_64.AppImage /usr/bin/appimagetool
RUN wget https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage && \
    chmod +x linuxdeploy-x86_64.AppImage && \
    mv linuxdeploy-x86_64.AppImage /usr/bin/linuxdeploy

RUN mkdir /project
RUN mkdir -p /home/coder/dconf
RUN chmod a+rwx /home/coder/dconf

WORKDIR /project
