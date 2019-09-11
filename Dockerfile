# Dockerfile for grumpycoders/pcsx-redux-code-server

FROM codercom/code-server:1.1156-vsc1.33.1

USER root

RUN apt update
RUN apt install -y wget gnupg
RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
RUN apt update
RUN apt install -y software-properties-common
RUN apt-add-repository "deb http://apt.llvm.org/bionic/ llvm-toolchain-bionic-9 main"
RUN apt update
RUN apt install -y make g++-8 clang-9 git
RUN apt install -y pkg-config libsdl2-dev libavcodec-dev libavformat-dev libavutil-dev libswresample-dev zlib1g-dev libglfw3-dev libuv1-dev
RUN apt install -y g++-mipsel-linux-gnu

USER coder

ENV CC clang-9
ENV CXX clang++-9
ENV LD clang++-9
