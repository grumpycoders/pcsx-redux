# Dockerfile for grumpycoders/pcsx-redux-code-server

FROM codercom/code-server:3.4.0

USER root

# The tzdata package isn't docker-friendly, and something pulls it.
ENV DEBIAN_FRONTEND noninteractive
ENV TZ Etc/GMT

RUN apt update

# Utility packages
RUN apt install -y git
RUN apt install -y gnupg
RUN apt install -y make
RUN apt install -y pkg-config
RUN apt install -y wget

# Clang setup
RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
RUN apt update
RUN apt install -y software-properties-common
RUN apt-add-repository "deb http://apt.llvm.org/buster/ llvm-toolchain-buster-10 main"
RUN apt update

# Compilers & base libraries
RUN apt install -y clang-10
RUN apt install -y g++-8
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

USER coder

ENV CC clang-10
ENV CXX clang++-10
ENV LD clang++-10
