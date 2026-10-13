## PCSX-Redux SupportPSX library

This library contains a few functions that are used by the PCSX-Redux emulator. It is a collections of standalone functions that are not specific to the emulator itself, but are aimed at being used in the context of the PlayStation 1. The library is written in C++ and is meant to be used in a pick-and-choose fashion. The library is not meant to be used as a whole, but rather as a collection of functions that can be used in other projects. Some pieces are header-only, while others require compilation of some C++ files. Usually, if compilation is required, it will be with the same base name as the header file.

Very little external dependencies are required. They will be documented in a per-file basis below.

## License

The code in this folder is licensed under the terms of the MIT license, with one exception: `mdec-decoder.h` & `mdec-decoder.cc` are GPLv2 or later, as they carry the emulator's MDEC decoder, which derives from PCSX-df.

## Contents

* `adpcm.h` & `adpcm.cc` - Provides a simple ADPCM encoder. It is a re-creation of the original encvag.dll from Sony's development kit for the PlayStation 1, and is meant to produce similar results with a similar API.
* `binloader.h` & `binloader.cc` - Loads a PlayStation 1 binary file from a `File` abstraction to another `File` abstraction. The binary file can be of the following formats:
  * PlayStation 1 executable file (needs the "PS-X EXE" signature)
  * ELF
  * CPE
  * PSF
  * MiniPSF
* `iec-60908b.h` & `iec-60908b.cc` - Provides iec-60908b helpers and encoders for MODE2 discs, such as the ones used by the PlayStation 1.
* `mdec-decoder.h` & `mdec-decoder.cc` - **GPLv2 or later, unlike the rest of this folder.** The MDEC's decode half: run-level stream and uploaded tables in, 24-bit or 15-bit pixels out, bit-exact with the emulator's MDEC, which uses it. Depends on `dct.h` & `dct.cc` for the standard quant table.
* `ps1-packer.h` & `ps1-packer.cc` - Provides a function to pack a PlayStation 1 executable file into a self-decompressing executable file. The resulting file can be loaded directly into the PlayStation 1 memory and executed. Supports multiple encoding methods.
