# Background

When Sony released their PlayStation 1 SDK long ago, the compiler, linker and provided libraries were all using a proprietary format for the binary objects files.
This format uses a sort of bytecode in lieu of a hierarchical file format, like ELF or COFF.

# The tool

This tool is performing a very verbose parsing of an input object file compiled with ccpsx, and can emit an ELF object file compatible with modern toolchains.
The point of the conversion is to provide viable libraries to be used with an off the shelf compiler such as gcc or clang.

# Caveats

Not all of the particularities of the input format is convertible to the new ELF format, at least, not without an opiniated ldscript. Fortunately, with the whole of
the official Sony libraries, the only sorts of object files that fails conversion are the various crt0, which would also require a very opiniated ldscript too.
The user is then compelled to provide their own crt0 and ldscript of their choice. Such files can be found [here](https://github.com/grumpycoders/pcsx-redux/tree/main/src/mips).

