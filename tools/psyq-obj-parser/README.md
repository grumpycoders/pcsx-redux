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

# Compatibility

Beside the crt0 object files as specified above, all of the original libraries seem to be parsing and converting proeprly. There has been however no effort done in trying to support anything else beside these libraries, as writing code blindly without testing it isn't a good methodology. Instead, the code will error out for any of the cases that haven't been seen before. As a result, converting object files produced by ccpsx for any other type of libraries or development may or may not work. Please contact the author to expose such object files in order to get them tested and implemented properly.

# Usage

```
Arguments: input.obj [input2.obj...] [-h] [-v] [-d] [-n] [-p prefix] [-o output.o]
  input.obj      mandatory: specify the input psyq LNK object file.
  -h             displays this help information and exit.
  -v             turns on verbose mode for the parser.
  -d             displays the parsed input file.
  -n             use "none" ABI instead of Linux.
  -p prefix      use this prefix for local symbols.
  -o output.o    tries to dump the parsed psyq LNK file into an ELF file;
                 can only work with a single input file.
```

Due to the command line parser, the input files need to be before any switch is applied. There can be more than one input file, and they will all be parsed one after the other.
However, you can only specify a single input file if you want to specify an output file. 

The verbose mode for the parser is really raw, and will mainly be useful if you're trying to debug a parsing error of the input bytestream.

The display option will be a bit more sophisticated, and will dump the internal structures of the tool after it finished parsing the whole input file.

The generated ELF file will have the "linux" ABI set in its headers, but it might be desirable to use "none" instead, which is what the "-n" toggle does.

And finally, when the parser is emitting relocations in the output ELF file, it will generate local names. These can be useful when doing reverse engineering on the generated ELF files. You can alter the prefix of these symbols using the "-p" option.

# Inner workings

Most of the opcodes in the input bytestream will be translatable literally into the output ELF file with no alteration. There are still a few things that won't work straight however, and that need some special care.

## Sections

The input bytestream doesn't really have any information about the section types. The conversion will be done based on the section name. The recognized section names are ".text", ".rdata", ".data", ".bss", and ".sbss". Any other section name will make the conversion fail.

The input file can have mixed uninitialized and initialized data in a single section, which isn't really something that can happen in an ELF file. The conversion will fill non-bss sections with zeroes if the input has unitialized data in them.

## Symbols

The input bytestream doesn't hold any sorts of hints about the input symbol's type, and some symbols have size information. The converted symbol will therefore have no type information, will always be global, and will have a size of of either zero, or what was specified in the input file.

There are three types of symbols that are recognized by the parser:

- Imports
  - These are global symbols that are imported inside the current object file. They don't have any information beside their names.
- Exports
  - These are global symbols that are exported from the object file. They will have an offset relative to the start of a section.
- Unallocated
  - These are the technically global symbols that are exported from the object file, and are associated with a section, but they don't have any specific location, only a size. It's then technically up to the linker to actually allocate them in the final section where it's supposed to be going, but this isn't a feature from the ELF format. As a result, the conversion will allocate them into the local section instead, while respecting the section's desired alignment data. This may result in a differently packed aggregation of these variables.

## Relocations

The relocation system is what's the most complicated to convert to ELF, due to the differences between the original and the ELF formats.

Only the following relocations are recognized and supported:

- REL32
- REL26
- HI16
- LO16

The REL32 is for an absolute 32 bits offset which will be a full pointer. The REL26 is for the typical `j` or `jal` target address. The HI16/LO16 relocations can potentially be more problematic, and deserve some explanation. These technically ought to be used only for two patterns:

```mips
lui   rt, %hi(symbol)
addiu rt, %lo(symbol)
```

```mips
lui   rt, %hi(symbol)
lw    rd, %lo(symbol)(rt)
```

In both cases, the final offset is computed by the MIPS cpu using a normal addition, which means that there can be an overflow happening, if the high bit of the LO16 portion is set. In this case, the HI16 portion needs to account for this, and has to prepare for the overflow.

The gnu ELF linker will do the right thing if the HI/LO relocations are stored in pair, which seems to be what the input libraries from Sony do, while using the addend pattern. But this means that this pattern cannot work:

```mips
lui   rt, %hi(symbol)
ori   rt, %lo(symbol)
```

The bytestream from the sections will also contain information inside the bytes that need relocating. These cannot stay as is, since the GNU linker will add them with the relocation target, and therefore needs to be mutated to work properly. One very specific system that the input file will sometimes do is request a relocation with an offset relative to an imported target symbol. This last part is absolutely not supported by the ELF format. Luckily, using the addend system, we can adjust this properly. All in all, it means we are mutating the bytestream to either write zeros in there, or write the addend from the imported symbol. When doing this with a HI/LO pair, we try to match them to properly compute the final addend.
