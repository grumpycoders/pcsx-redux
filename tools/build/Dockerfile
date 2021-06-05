# Dockerfile for grumpycoders/pcsx-redux-build

FROM ubuntu:20.04

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
RUN apt install -y clang-11
RUN apt install -y g++-10
RUN apt install -y g++-mipsel-linux-gnu

# Development packages
RUN apt install -y libavcodec-dev
RUN apt install -y libavformat-dev
RUN apt install -y libavutil-dev
RUN apt install -y libfreetype-dev
RUN apt install -y libglfw3-dev
RUN apt install -y libsdl2-dev
RUN apt install -y libswresample-dev
RUN apt install -y libuv1-dev
RUN apt install -y zlib1g-dev

# CI utilities
RUN apt install -y curl wget
RUN apt install -y xvfb
RUN apt install -y python3-pip python3-setuptools patchelf desktop-file-utils libgdk-pixbuf2.0-dev fakeroot strace
WORKDIR /tmp
RUN wget https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage && \
    chmod +x /tmp/appimagetool-x86_64.AppImage && \
    cd /opt && /tmp/appimagetool-x86_64.AppImage --appimage-extract && \
    mv squashfs-root appimage-tool.AppDir && \
    ln -s /opt/appimage-tool.AppDir/AppRun /usr/bin/appimagetool && \
    rm /tmp/appimagetool-x86_64.AppImage
WORKDIR /
RUN pip3 install appimage-builder
RUN apt install -y imagemagick-6.q16 gtk-update-icon-cache appstream
ENV NVM_DIR /usr/local/nvm
ENV NODE_VERSION 14.17.0
RUN mkdir -p /usr/local/nvm
RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.38.0/install.sh | bash \
    && . $NVM_DIR/nvm.sh \
    && nvm install $NODE_VERSION \
    && nvm alias default $NODE_VERSION \
    && nvm use default
RUN . $NVM_DIR/nvm.sh && npm install -g appcenter-cli
RUN apt install -y zip

RUN mkdir /project
RUN mkdir -p /home/coder/dconf
RUN chmod a+rwx /home/coder/dconf
WORKDIR /project
