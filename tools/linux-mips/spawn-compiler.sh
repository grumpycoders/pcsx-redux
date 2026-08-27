#!/bin/sh
#
# Building gcc from source isn't necessarily an easy task, and it requires
# a lot of various dependency packages to work properly. Here's how to build
# a working mips compiler that can produce code for the R3000A CPU, granted
# you have the necessary dependencies to do so. The script can be run as
# root, or as a regular user when the PREFIX environment variable is
# provided. Set JOBS to override the parallelism, which defaults to the
# number of available cores.
#

set -ex

PREFIX=${PREFIX:-"/usr/local"}
JOBS=${JOBS:-$(nproc 2> /dev/null || echo 1)}

for url in https://ftpmirror.gnu.org/gnu/binutils/binutils-2.47.tar.gz https://mirrors.kernel.org/gnu/binutils/binutils-2.47.tar.gz ; do
    wget --max-redirect=2 --timeout=60 --continue --trust-server-names $url && break
done
tar xvfz binutils-2.47.tar.gz
cd binutils-2.47
./configure --target=mipsel-none-elf --disable-multilib --disable-nls --disable-werror --prefix=$PREFIX
make -j$JOBS
make install-strip
cd ..

for url in https://ftpmirror.gnu.org/gnu/gcc/gcc-16.2.0/gcc-16.2.0.tar.gz https://mirrors.kernel.org/gnu/gcc/gcc-16.2.0/gcc-16.2.0.tar.gz ; do
    wget --max-redirect=2 --timeout=60 --continue --trust-server-names $url && break
done
tar xvfz gcc-16.2.0.tar.gz
cd gcc-16.2.0
./contrib/download_prerequisites
mkdir build
cd build
../configure --target=mipsel-none-elf --without-isl --disable-nls --disable-threads --disable-shared --disable-libssp --disable-libstdcxx-pch --disable-libgomp --disable-werror --without-headers --disable-hosted-libstdcxx --with-as=$PREFIX/bin/mipsel-none-elf-as --with-ld=$PREFIX/bin/mipsel-none-elf-ld --enable-languages=c,c++ --prefix=$PREFIX
make -j$JOBS all-gcc
make install-strip-gcc
make -j$JOBS all-target-libgcc
make install-strip-target-libgcc
make -j$JOBS all-target-libstdc++-v3
make install-strip-target-libstdc++-v3
