#!/bin/sh
#
# Building gcc from source isn't necessarily an easy task, and it requires
# a lot of various dependency packages to work properly. The easiest way
# to use a mips compiler for Linux is still to use a package from your
# distribution. Nevertheless, here's how to build a working mips compiler
# that can produce code for the R3000A CPU, granted you have the necessary
# dependencies to do so. The script can be run as root, or as a regular user
# when the PREFIX environment variable is provided.
#

set -ex

PREFIX=${PREFIX:-"/usr/local"}

wget https://ftp.gnu.org/gnu/binutils/binutils-2.40.tar.gz
tar xvfz binutils-2.40.tar.gz
cd binutils-2.40
./configure --target=mipsel-none-elf --disable-multilib --disable-nls --disable-werror --prefix=$PREFIX
make
make install-strip
cd ..

wget https://ftp.gnu.org/gnu/gcc/gcc-12.2.0/gcc-12.2.0.tar.gz
tar xvfz gcc-12.2.0.tar.gz
cd gcc-12.2.0
./contrib/download_prerequisites
mkdir build
cd build
../configure --target=mipsel-none-elf --without-isl --disable-nls --disable-threads --disable-shared --disable-libssp --disable-libstdcxx-pch --disable-libgomp --disable-werror --without-headers --disable-hosted-libstdcxx --with-as=$PREFIX/bin/mipsel-none-elf-as --with-ld=$PREFIX/bin/mipsel-none-elf-ld --enable-languages=c,c++ --prefix=$PREFIX
make all-gcc
make install-strip-gcc
make all-target-libgcc
make install-strip-target-libgcc
make all-target-libstdc++-v3
make install-strip-target-libstdc++-v3
