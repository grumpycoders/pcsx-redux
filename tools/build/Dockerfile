# Dockerfile for grumpycoders/pcsx-redux-build

FROM ubuntu:20.04

# The tzdata package isn't docker-friendly, and something pulls it.
ENV DEBIAN_FRONTEND noninteractive
ENV TZ Etc/GMT

RUN apt update

# Utility packages
RUN apt install -y git
RUN apt install -y make
RUN apt install -y pkg-config

# Compilers & base libraries
RUN apt install -y clang-10
RUN apt install -y g++-10
RUN apt install -y g++-mipsel-linux-gnu

# Development packages
RUN apt install -y libavcodec-dev
RUN apt install -y libavformat-dev
RUN apt install -y libavutil-dev
RUN apt install -y libglfw3-dev
RUN apt install -y libsdl2-dev
RUN apt install -y libswresample-dev
RUN apt install -y libuv1-dev
RUN apt install -y zlib1g-dev

# CI utilities
RUN apt install -y curl
RUN apt install -y xvfb

# 32 bits
#RUN dpkg --add-architecture i386
#RUN apt update
#RUN apt install -y libc6:i386
#RUN apt install -y libstdc++6:i386

# 32 bits development packages
#RUN apt install -y libavcodec-dev:i386
#RUN apt install -y libavformat-dev:i386
#RUN apt install -y libavutil-dev:i386
#RUN apt install -y libglfw3-dev:i386
#RUN apt install -y libsdl2-dev:i386
#RUN apt install -y libswresample-dev:i386
#RUN apt install -y libuv1-dev:i386
#RUN apt install -y zlib1g-dev:i386

RUN mkdir /project
WORKDIR /project
