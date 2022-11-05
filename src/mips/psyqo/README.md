# PSYQo

## What?
The PSYQo library is a object oriented C++ library for developing applications that run on the PlayStation 1. It is an opinionated yet lightweight and safe solution for modern development on the PS1.

## How?
Please refer to the [Getting Started](GETTING_STARTED.md) and [Concepts](CONCEPTS.md) pages for more information. While the library makes heavy use of C++, the surface API only requires some basic knowledge of C++. Still, the user of the library is encouraged to get familiar with C++ concepts such as [classes](https://cplusplus.com/doc/tutorial/classes/), [lambdas](https://en.cppreference.com/w/cpp/language/lambda), or [inheritance](https://cplusplus.com/doc/tutorial/inheritance/).

The library makes uses of the [EASTL](https://github.com/electronicarts/EASTL), and is available to the user as a side effect. However, not all pieces of the library will be guaranteed to work properly at the moment. It has been modified to support the PlayStation1. The goal is still to get most of the EASTL working properly eventually.

## Who?
The PSYQo library is developed by [the PCSX-Redux authors](https://pcsx-redux.consoledev.net/).
To discuss PlayStation1's development, hacking, and reverse engineering in general, please join the PSX.Dev Discord server: [![Discord](https://img.shields.io/discord/642647820683444236)](https://discord.gg/QByKPpH)

## When?
The library can be seen in an alpha state at the moment, and is actively being developed. The next immediate features should include:

- [ ] Proper GPU DMA chaining
- [ ] Memory card access
- [ ] Better CDRom support
- [ ] Better sound support
- [ ] Better input support
