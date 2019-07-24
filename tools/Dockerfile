# Dockerfile for grumpycoders/pcsx-redux-build

FROM ubuntu:18.04

RUN apt update
RUN apt install -y wget gnupg
RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
RUN apt update
RUN apt install -y software-properties-common
RUN apt-add-repository "deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic main"
RUN apt update
RUN apt install -y make g++-8 clang-9 git
RUN apt install -y pkg-config libsdl2-dev libavcodec-dev libavformat-dev libavutil-dev libswresample-dev zlib1g-dev libglfw3-dev libuv1-dev
RUN mkdir /project
WORKDIR /project
