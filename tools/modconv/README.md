# MODCONV
This folder contains a modern recreation of the MODCONV.EXE software, which is used to convert MOD files to HIT files. The original software was [provided by Hitmen](http://hitmen.c02.at/html/psx_tools.html), without source code.

This version has been written from scratch, without reverse engineering, as the file format is fairly simple to understand. This means that the output files will be slightly different from the original software.

Its purpose is to convert [MOD files](https://en.wikipedia.org/wiki/Module_file) to HIT files, which can then be played by the [modplayer library available](https://github.com/grumpycoders/pcsx-redux/tree/main/src/mips/modplayer) in the PCSX-Redux project.

## Usage
```sh
modconv input.mod [-s output.smp] [-a amp] -o output.hit
```

## Arguments
| Argument | Type | Description |
|-|-|-|
| input.mod | mandatory | Specify the input mod file. |
| -o output.hit | mandatory | Name of the output file. |
| -s output.smp | optional | Name of the output samples data file. |
| -a amp | optional | Amplification factor. Default is 175. |
| -h | optional | Show help. |

If the `-s` argument is not provided, the sample data will be written to the .hit file itself, and can be loaded with the `MOD_Load` function from the modplayer library or the old Hitmen implementation. If the `-s` argument is provided, the sample data will be written into a separate file. Both will need to be loaded with the `MOD_LoadEx` function from the modplayer library, and is not backwards compatible with the old Hitmen implementation. This allows the user to have a simple way to unload the samples data from the main ram after the call to `MOD_LoadEx`, only keeping the .hit file in memory.
