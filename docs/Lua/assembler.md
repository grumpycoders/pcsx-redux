# Inline assembler

There is a Lua API for an inline MIPS assembler.

One can instantiate an assembler with `PCSX.Assembler.New()`, which will keep all the state of the assembler. The assembler can be used to assemble a string of MIPS code, and then compile it to memory or a file.

The object has the following methods:
- `:parse(code)` will parse the string `code` and assemble it. It will return the assembler object itself, so it can be chained with the compile methods. The parser is fairly simple, but it should be enough for most cases. The parser should handle all of the basic MIPS instructions, all of the PS1's GTE opcodes, and many pseudo-instructions. It will also handle labels. The parser is more lenient than normal MIPS assemblers, and will accept some invalid syntax, but it will throw an error if it can't parse the code.
- `:compileToUint32Table(baseAddress)` will compile the assembled code to a table of `uint32_t` values. This is useful for debugging, but not very useful for actually running the code. The `baseAddress` is the address that the code will be loaded at, in order to handle relative jumps.
- `:compileToMemory(memory, baseAddress, memoryStartAddress)` will compile the assembled code to an indexable memory object, such as an ffi array. The memory object must be at least as large as the assembled code. The memory object will be modified in-place. The `baseAddress` is the address that the code will be loaded at, in order to handle relative jumps. The `memoryStartAddress` is the address that the memory object starts at.
- `:compileToFile(file, baseAddress, fileStartAddress)` will compile the assembled code to a file object. The file object must be at least as large as the assembled code. The file object will be modified in-place. The `baseAddress` is the address that the code will be loaded at, in order to handle relative jumps. The `fileStartAddress` is an optional argument which defaults to 0, and is the address that the file object starts at. Using a 0-based file address is relevant when using with the `PCSX.getMemoryAsFile()` function, or when using a `Support.mem4g()` File object.
