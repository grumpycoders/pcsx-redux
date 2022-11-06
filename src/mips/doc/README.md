# Nugget

## Where

There are two canonical ways to access the code located here. First is to access the full [PCSX-Redux repository](https://github.com/grumpycoders/pcsx-redux/tree/main/src/mips), which is in read-write mode. The second is to access the [Nugget mirror](https://github.com/pcsx-redux/nugget), which is read only. The purpose of the mirror is to have a smaller set of sources and dependencies if somebody wants to only access the mips code of PCSX-Redux. It is suitable for using as a submodule.

## What

This is a collection of several projects that are intended for running on the PlayStation 1, either through the official hardware or emulators.

This can serve as a base for other projects, or as a reference for how to write code for the PlayStation 1.

 - [common](../common) - Common code for all projects. Highly recommended to be used by other projects.
 - [crc32](../crc32) A CRC32 implementation that is optimized for the PlayStation 1, using the scratchpad as a speedup.
 - [cube](../cube) A small demo that's demonstrating the use of the converted psyq libraries.
 - [cxxhello](../cxxhello) A very quick hello world using C++.
 - [helloworld](../helloworld) A very simple hello world.
 - [modplayer](../modplayer) A MOD player from the reverse engineering of HITMEN's modplayer.
 - [openbios](../openbios) A fully functional BIOS implementation for the PlayStation 1, based on the reverse engineering of Sony's BIOS.
 - [psyq](../psyq) Some additional code for the converted psyq libraries.
 - [psyqo](../psyqo) The PSYQo project. This is a new SDK for the PlayStation 1, written from scratch in C++, using modern paradigms. This is probably where the most complete documentation exists for this project, and should be used as a reference for how to write code for the PlayStation 1.
 - [shell](../shell) The tiny shell project. This is currently the shell software that OpenBIOS uses to have a boot logo and chime.
 - [tests](../tests) A collection of tests to verify emulators behavior.

## How

A toolchain will need to be installed before any of the projects can be built. The [PSYQo's Getting Started](../psyqo/GETTING_STARTED.md) documentation has instructions on how to install the toolchain.

Use the `Makefile` in each project to build that project.

## Who

The PCSX-Redux project's authors are also the main authors and maintainers of this code. To discuss PlayStation 1 development, hacking, and reverse engineering in general, please join the PSX.Dev Discord server: [![Discord](https://img.shields.io/discord/642647820683444236)](https://discord.gg/QByKPpH)
