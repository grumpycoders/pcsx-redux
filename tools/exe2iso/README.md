# EXE2ISO
This tool takes a ps-exe and creates a bootable iso from it. The output is a standards
conformant ISO9660 image with a single `PSX.EXE;1` file in its root directory, built with
the same ISO9660 authoring code as the rest of PCSX-Redux. It boots in emulators, on real
hardware, and on ODEs. The sectors carry proper EDC/ECC, so PC tools that expect a valid
ISO9660 filesystem will read it just fine.

## arguments

Usage: exe2iso input.ps-exe [-license file] [-nopad] -o output.bin
| Argument | Type | Description |
|-|-|-|
| input.ps-exe | mandatory | Specify the input ps-exe file. |
| -o output.bin | mandatory | Name of the output file. |
| -license file | optional | Use this license file. Some emulators will want a proper license to recognize the disk. Also, Japanese consoles require a valid Japanese license to boot a disk properly. The file can either be from the official sdk, or a valid iso file from an existing game. |
| -nopad | optional | Don't append the 150 trailing blank sectors. Padding is on by default: real drives read ahead past the last data sector, so a couple of seconds of blank sectors keep the mechacon from choking near the end of the disc when burning the image. The padding sits past the end of the volume, so it's physical only and doesn't affect the filesystem. |
