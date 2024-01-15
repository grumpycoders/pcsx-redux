## PCSX-Redux Support library

This library contains a few functions that are used by the PCSX-Redux emulator. It is a collections of standalone functions that are not specific to the emulator itself. The library is written in C++ and is meant to be used in a pick-and-choose fashion. The library is not meant to be used as a whole, but rather as a collection of functions that can be used in other projects. Some pieces are header-only, while others require compilation of some C++ files. Usually, if compilation is required, it will be with the same base name as the header file.

Very little external dependencies are required. They will be documented in a per-file basis below.

## License

The code in this folder is licensed under the terms of the MIT license.

## Contents

### Fully independent files

* `circular.h` - A thread-safe circular buffer implementation.
* `coroutine.h` - Support file for C++20 coroutines.
* `djbhash.h` - A simple hash function implementation, with compile-time string hashing.
* `eventbus.h` - An immediate-mode event bus implementation.
* `opengl.h` - A few helpers for OpenGL.
* `polyfills.h` - Provides missing C++ features for Apple platforms.
* `sjis_conv.h` & `sjis_conv.cc` - A Shift-JIS to UTF-8 conversion implementation.

### Files with external dependencies
* `bezier.h` - A simple bezier curve implementation and associated helpers. Requires ImGui for the math vector classes.
* `binstruct.h` - A binary serialization library with full compile-time reflection. See the tests for examples. Depends on [typestring](https://github.com/irrequietus/typestring) and the `File` class abstraction from this library.
* `imgui-helpers.h` - A few helpers for ImGui.
* `md5.h` & `md5.cc` - An MD5 hash implementation.
* `protobuf.h` - A reflective, header-only protobuf implementation. Depends on [typestring](https://github.com/irrequietus/typestring).
* `settings.h` - A reflective settings system. Depends on [json](https://github.com/nlohmann/json), [Lua](https://www.lua.org/), [typestring](https://github.com/irrequietus/typestring), and the File class abstraction from this library.
* `slice.h` - Holds an abstraction of data view or storage.

### The `File` abstraction.
This abstraction provides an extremely versatile way to access files. It can be used to access files on the filesystem, in memory, or even in a zip archive. The various portions of the abstraction are:

* `file.h` & `file.cc`- The base class for the abstraction. It provides the majority of the functionalities. It also provides a few helpers.
* `container-file.h` & `container-file.cc` - Provides C++-containers like access to a `File` object abstraction. This allows to use a `File` object in a range-based for loop, for example.
* `mem4g.h` & `mem4g.cc` - Provides a 4GB sparse memory space. This is useful to simulate a memory space for a console, for example, with the safety of a sparse container.
* `stream-file.h` - Provides a `File` object abstraction for a C++ stream. This allows to use a `File` object as a `std::ifstream`, for example.
* `zfile.h` & `zfile.cc` - Provides a filter `File` object abstraction for zlib-compressed data streams. Allows for reads and writes operations.
* `zip.h` & `zip.cc` - Provides a `File` object abstraction for a zip archive. Allows for reads and writes operations, as well as listing the contents of the archive. Each file in the archive is represented by a `File` object abstraction.

### Intrusive containers
These files are providing [intrusive containers](https://www.codeofhonor.com/blog/avoiding-game-crashes-related-to-linked-lists) for modern C++. They are meant to be used with classes deriving from the nodes types using the [Curiously recurring template pattern](https://en.wikipedia.org/wiki/Curiously_recurring_template_pattern). See the tests for some examples.

* `list.h` - An intrusive doubly-linked list implementation. Compatible with C++ range-based for loops.
* `hashtable.h` - An intrusive hash table implementation. Compatible with C++ range-based for loops.
* `tree.h` - An intrusive interval tree implementation. Compatible with C++ range-based for loops.
