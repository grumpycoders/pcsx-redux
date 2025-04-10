# PSYQo Lua

PSYQo Lua is a component of the PCSX-Redux project that integrates the Lua scripting language with PSYQo applications. It provides a streamlined way to leverage Lua's powerful scripting capabilities in your PlayStation applications.

## Features

### Automatic Lua VM Integration

PSYQo Lua automatically links the Lua virtual machine into your project, handling all the necessary build configurations and dependencies, while setting up the necessary glue between the Lua VM and the rest of PSYQo.

### C++ Wrapper for Lua API

The library provides an idiomatic C++ wrapper around the standard Lua C API, offering a modern C++ interfaces that reduce boilerplate code typically associated with Lua scripting.

### Example Implementation

A complete working example is provided in the [examples/hello](examples/hello) folder, demonstrating:

- How to initialize the Lua environment
- Loading and executing Lua scripts
- Exchanging data between C++ and Lua
- Registering C++ functions for use in Lua scripts

## Getting Started

To use PSYQo Lua in your project:

1. Include the PSYQo Lua library in your Makefile:
    ```makefile
    include path/to/psyqo-lua/psyqo-lua.mk
    ```

1. Include the necessary headers:
   ```cpp
   #include "psyqo-lua/lua.hh"
   ```

2. Create a Lua VM in your application:
   ```cpp
   psyqo::Lua L;
   ```

3. Start using Lua in your PlayStation application with the C++ wrapper:
   ```cpp
   L.loadBuffer("print('Hello, PSYQo Lua!')");
   L.pcall(0, 0);
   ```

See the example in [examples/hello](examples/hello) for a more detailed implementation.
