![Debugger screenshot](https://pcsx-redux.consoledev.net/images/debugger1.png)


|Platform|Build status|
|--------|------------|
|Windows build|[![Build Status](https://dev.azure.com/grumpycoders/pcsx-redux/_apis/build/status/grumpycoders.pcsx-redux?branchName=main)](https://dev.azure.com/grumpycoders/pcsx-redux/_build/latest?definitionId=1&branchName=main)|
|Linux build|[![CircleCI](https://circleci.com/gh/grumpycoders/pcsx-redux.svg?style=svg)](https://circleci.com/gh/grumpycoders/pcsx-redux)|
|MacOS build|[![macOS CI](https://github.com/grumpycoders/pcsx-redux/workflows/macOS%20CI/badge.svg?branch=main)](https://github.com/grumpycoders/pcsx-redux/actions?query=workflow%3A%22macOS+CI%22+branch%3Amain)|

[![Discord](https://img.shields.io/discord/567975889879695361)](https://discord.gg/KG5uCqw)

# PCSX-Redux

## What?
This is yet another fork of the Playstation Emulator, PCSX. While the work here is very much in progress, the goal is roughly the following:

 - Bring the codebase to more up to date code standards.
 - Get rid of the plugin system and create a single monolithic codebase that handles all aspects of the playstation emulation.
 - Write everything on top of SDL/OpenGL3+/ImGui for portability and readability.
 - Improve the debugging experience.
 - Improve the rendering experience.

## Where?
There are currently regular builds of pcsx-redux for Windows, available here: https://install.appcenter.ms/orgs/grumpycoders/apps/pcsx-redux/distribution_groups/public

## How?
The code is meant to be built using very modern compilers. Also it's still fairly experimental, and lots of things can break. If you still want to proceed, here are instructions to build it on Linux, MacOS and Windows. The code now comes in two big parts: the emulator itself, and [OpenBIOS](https://github.com/grumpycoders/pcsx-redux/tree/main/src/mips/openbios), which can be used as an alternative to the retail, copyright protected BIOS.

### Getting sources
The only location for the source is [on github](https://github.com/grumpycoders/pcsx-redux/). Clone recursively, as the project uses submodules: `git clone https://github.com/grumpycoders/pcsx-redux.git --recursive`.

### Windows
Install [Visual Studio 2019 Community Edition](https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=Community&rel=16). Open the file `vsprojects\pcsx-redux.sln`, select `pcsx-redux -> pcsx-redux`, right click, `Set as Startup Project`, and hit `F7` to build. The project follows the open-and-build paradigm with no extra step, so no specific dependency ought to be needed, as [NuGet](https://www.nuget.org/) will take care of downloading them automatically for you on the first build.

Note: If you get an error saying `hresult e_fail has been returned from a call to a com component`, you might need to delete the .suo file in vsproject/vs, restart Visual Studio and retry.

### Linux
Run `./dockermake.sh`. You need [docker](https://en.wikipedia.org/wiki/Docker_(software)) for this to work. You will also need a few libraries on your system for this to work. Check the [Dockerfile](https://github.com/grumpycoders/pcsx-redux/blob/main/tools/build/Dockerfile#L22) for a list of library packages to install.

#### GNU/Linux Dependencies

 - Debian derivatives :

```bash
sudo apt-get install -y git make pkg-config clang-11 g++-10 g++-mipsel-linux-gnu libavcodec-dev libavformat-dev libavutil-dev libfreetype-dev libglfw3-dev libsdl2-dev libswresample-dev libuv1-dev zlib1g-dev
```

 - Arch derivatives :

```bash
sudo pacman -S clang git make pkg-config ffmpeg libuv zlib sdl2 glfw-x11 curl xorg-server-xvfb
```
The mipsel environment can be installed from [AUR](https://wiki.archlinux.org/index.php/Aur) : [cross-mipsel-linux-gnu-binutils](https://aur.archlinux.org/packages/cross-mipsel-linux-gnu-binutils/) and [cross-mipsel-linux-gnu-gcc](https://aur.archlinux.org/packages/cross-mipsel-linux-gnu-gcc/) using your [AURhelper](https://wiki.archlinux.org/index.php/AUR_helpers) of choice:

```bash
trizen -S cross-mipsel-linux-gnu-binutils cross-mipsel-linux-gnu-gcc
```
You can then just enter the 'pcsx-redux' directory and compile without using docker with `make`.

Building OpenBIOS on Linux can be done with `./dockermake.sh -C src/mips/openbios`, or using the `g++-mipsel-linux-gnu` package with `make -C src/mips/openbios`. If you have a different mips compiler, you'll need to override some variables, such as `PREFIX=mipsel-none-elf FORMAT=elf32-littlemips`.

### MacOS
You need MacOS Catalina with the latest XCode to build, as well as a few [homebrew](https://brew.sh/) packages. Run the [brew installation script](https://github.com/grumpycoders/pcsx-redux/blob/main/.github/scripts/install-brew-dependencies.sh) to get all the necessary dependencies. Simply run `make` to build.

Compiling OpenBIOS will require a mips compiler, that you can generate using the following commands:
```bash
brew install ./tools/macos-mips/mipsel-none-elf-binutils.rb
brew install ./tools/macos-mips/mipsel-none-elf-gcc.rb
```

Then, you can compile OpenBIOS using `make -C ./src/mips/openbios`.

## Who?
I used to contribute to the PCSX codebase. It is very likely that a sourceforge account of mine still has write access to the old cvs repository for PCSX. A long time ago, I contributed the telnet debugger, and the parallel port support. This means I am fairly familiar with this codebase, and I am also ashamed of the contributions I have done 15+ years ago, as one should.

## Why?
When Sony released the Playstation mini recently, I came to realize two things: first, the state of the Playstation emulation isn't that great, and second, the only half-decent debugging tool still available for this console is that old telnet debugger I wrote eons ago, while other emulators out there for other consoles gained a lot of debugging superpowers. I think it was time for the Playstation emulation to get to better standards with regards to debuggability. I also felt I had a responsability to cleaning up some of the horrors I've introduced myself in the codebase long ago, and that made me cry a little looking at them. Hopefully, I got better at programming. Hopefully.

## Status?
The codebase still requires a lot of cleanup, and the current product isn't properly usable yet. Despite that, a lot can already be achieved using the product in its current state.

### What works?
- x86 dynarec
- interpreted CPU
- software GPU
- VRAM viewer and debugger
- fully featured MIPS debugger
- memory cards
- XBox controller support
- save states

### What still requires some work?
- GLSL GPU
- proper SPU multithreaded code
- save state slots
- memory card manager
- better customization
- more generic dynarec
- ...

[![Redux definition](https://pbs.twimg.com/media/ENJhNwGWwAEbrGb?format=jpg)](https://twitter.com/MerriamWebster/status/1212357808026341376)
