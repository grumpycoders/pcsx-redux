# OpenBIOS

## Purpose of this project

There are several goals from the code in this directory.

### Educational

Writing an emulator requires extensive knowledge of the machine being emulated. The BIOS of the PlayStation is part of it, and is obviously required to boot the machine and start games. This work is done so that both the author and the reader can perfect their understanding of its internals.

As a result, the code written here tries to be as close as possible to the original, bugs, quirks and all included. You may notice some anti-patterns while reading the code, like buffer overflows or arithmetic mistakes. They are intentional, and a direct reflection of what the retail BIOS does. Some of these bugs are weird enough that it's difficult to infer the original buggy C code, while still understanding the general intent. Some of these bugs are severe enough that they have been fixed, but mentions are usually added to explain what changed and why.

Note that the generated binary will be nowhere close to the original rom this is inspired from. This is caused by several different factors: codestyle isn't identical for a start, and some optimizations have been put in place still, such as the way syscalls are being issued. Linking order will also throw off some of the mappings. And finally, today's compilers generate much smarter code than before. So the same C code won't generate the same assembly code for two different compilers. There is also some dead or duplicated code in there that'd be useless or meaningless to reproduce. Finally, the shell itself is radically different.

### Ease of distribution

While dumping an original PlayStation disc is something that is fairly easy to do for anyone using any sort of compact disc reader connected to a personal computer, dumping the bios of a retail machine, while not impossible, is a somewhat harder feat. As a result, people are often relying on bios dumps done by third party people, which ought to be considered copyright violation. Also, some emulators have a "HLE" bios, which creates a maintenance burden for each emulator, as well as being a complex mix of LLE and HLE code.

### Testing

Any recent project needs automated testing. Having source code available for all parts of the emulator will improve testing availability and test coverage, hopefully, for both the emulator, and the bios code.

## Building

The currently supported build method for this project requires docker. You can use the `dockermake.sh` script at the root of the repository as a replacement for the `make` command, and use the `Makefile` present here. Under Windows, the `build.bat` can be used. If using [Visual Studio Code](https://code.visualstudio.com/), one can use the task "make_openbios" to compile: CTRL-P then `task make_openbios` to compile.

It is also possible to build using any PS1 compatible compiler, but this isn't the current method used in the CI, so it's mostly untested. Check [PSYQo's getting started](../psyqo/GETTING_STARTED.md) document to install such toolchain in case docker isn't an acceptable solution to build this project.

The result of the compilation should be a file called `openbios.elf` that contains all useful debugging symbols, and a file called `openbios.bin` which can be used in emulators or even burned to a chip and placed on a retail console.

The Makefile features several toggles to mutate the way the compilation works. Don't forget to run `make clean` prior to try a different set of compilation options.
 - `BUILD=SmallDebug` will produce a working, yet somewhat debuggable version of the code.
 - `BOOT=cart` will produce a rom that's flashable on cheat carts like the action replay. This will disable booting from a cart, since it'd otherwise obviously lead to an infinite boot.
 - `EMBED_PSEXE=binary.ps-exe` will make the bios embed the specified ps-exe binary, and run it before running the shell.
 - `FASTBOOT=true` will skip running the shell and try booting the CD-Rom immediately. The code will not attempt re-reading the CD-Rom if inserted after booting.
 - `INSTALL_TTY_CONSOLE=true` will make OpenBIOS install its tty driver, instead of the null driver. The driver will be the same as the DTL-H2000 console, which is simpler than the default DUART driver from the retail bios.

## Status

This subproject is fairly functional and usable. OpenBIOS does almost all the same things as the retail BIOS does when booting, and implements most of its features. [Many games](https://docs.google.com/spreadsheets/d/1UNGs7uYb8viAbm7YJaf1CR4dkgX7ZzntUdcowGsjcVc/edit?usp=sharing) are booting and working properly with this code. It can be used in emulators or on the real console, either while replacing the rom chip, or by using the "cart" build and programming the flash chip of a cheat cart with the result.

Please feel free to report bugs encountered while using this project.

## Organization

The BIOS is split in two major parts: the low level code for the bios itself, and the shell, which is the binary that's being loaded into memory at boot time by the bios, to display the SONY sound and logo, and has a small utility menu for playing audio discs, or shuffling around memory cards.

While the first part is the main one that's being targeted here, the second one hasn't been reversed, and fully replaced with a completely different project. This may change in the future, but this isn't currently the focus of this project.

The original code was most likely chunked into several sub-projects, that were all linked together like a giant patchwork. This approach is less readable, and for this reason, we're not going to do this. However this will result in the ROM/RAM split to be less obvious, and slower at times than the original. Tuning of the hot functions is eventually required.

The startup point for the ROM version is the function `_reset` located in [`boot/boot.s`](boot/boot.s). The rom cart version is the function `_cartBoot` in the same file.

## Direction

The primary repository for this project is a subdirectory of PCSX-Redux at the moment, because building, testing and integration as a single bloc of code is much more practical than separate repositories. If the need arise however, it should be possible to move it as a separate repository elsewhere. There is currently a [buildable read-only mirror available](https://github.com/pcsx-redux/nugget/tree/main/openbios).

## Technicalities

The code has been rewritten based off the reverse engineering of a dump of the BIOS of an american SCPH-7001 machine. MD5sum: 1e68c231d0896b7eadcad1d7d8e76129

The ghidra database for it is currently being hosted on a server, alongside a few other pieces of software being reversed. Contact one of the authors if you want access.

## Commentary

The retail PlayStation BIOS code is a constellation of bugs and bad design. It is very obvious the code has been written hastily, likely by different teams having little to no communication with each other, under heavy time pressure. The fact that the retail console boots at all is nothing short of a miracle. Half of the provided libc in the A0 table is buggy. The BIOS code is barely able to initialize the CD-Rom, and read the game's binary off of it to boot it; anything beyond that will be crippled with bugs. And this only is viable if you respect a very strict method to create your CD-Rom. The memory card and gamepad code is a steaming-hot heap of human excrement. The provided GPU stubs are inefficient at best. The only sane thing that any software running on the PlayStation ought to do is to immediately disable interrupts, grab the function pointer located at 0x00000310 for `FlushCache`, in order put it inside a wrapper that disables interrupts before calling it, and then trash the whole memory to install its own code. The only reason `FlushCache` is required from the retail code is because since the function will unplug the main memory bus off the CPU in order to work, it HAS to run from the 0xbfc0 memory map, which will still be connected. Anything else from the retail code is virtually useless, and shouldn't be relied upon. That being said, doing so will prevent tools from functioning properly, like cheat software, unirom, or even emulators that are sniffing the kernel to do debugging and reporting.

## Legality

*Disclaimer: the author is not a lawyer, and the following statement hasn't been reviewed by a professional of the law, so the rest of this document cannot be taken as legal advice.*

As explained above, this code has been written using disassembly and reverse engineering of a retail bios the author dumped from a second hand console. The same exact methodology was employed by Connectix for their PS1 bios. The conclusion of [their lawsuit](https://en.wikipedia.org/wiki/Sony_Computer_Entertainment,_Inc._v._Connectix_Corp.), and that of [Sega v. Accolade](https://en.wikipedia.org/wiki/Sega_Enterprises,_Ltd._v._Accolade,_Inc.) seems to indicate that this project here follows and is impacted by the same doctrine.
