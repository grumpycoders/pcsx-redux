#!/bin/sh
#
# Building gcc from source isn't necessarily an easy task, and it requires
# a lot of various dependency packages to work properly. The easiest way
# to use a mips compiler for Linux is still to use a package from your
# distribution. Nevertheless, here's how to build a working mips compiler
# that can produce code for the R3000A CPU, granted you have the necessary
# dependencies to do so. The script expects to be run as root.
#

wget https://ftp.gnu.org/gnu/binutils/binutils-2.36.1.tar.gz
tar xvfz binutils-2.36.1.tar.gz
cd binutils-2.36.1
./configure --target=mipsel-none-elf --disable-multilib --disable-nls --disable-werror
make
make install-strip
cd ..

wget https://ftp.gnu.org/gnu/gcc/gcc-10.3.0/gcc-10.3.0.tar.gz
tar xvfz gcc-10.3.0.tar.gz
cd gcc-10.3.0
mkdir build
cd build
../configure --target=mipsel-none-elf --without-isl --disable-nls --disable-threads --disable-shared --disable-libssp --disable-libstdcxx-pch --disable-libgomp --disable-werror --without-headers --with-as=/usr/local/bin/mipsel-none-elf-as --with-ld=/usr/local/bin/mipsel-none-elf-ld --enable-languages=c,c++
make all-gcc
make install-strip-gcc
make all-target-libgcc
make install-strip-target-libgcc
