![Debugger screenshot](https://pcsx-redux.consoledev.net/images/debugger1.png)

<a href='https://ko-fi.com/nicolasnoble' target='_blank'><img height='35' style='border:0px;height:46px;' src='https://az743702.vo.msecnd.net/cdn/kofi3.png?v=0' border='0' alt='Buy Me a Coffee at ko-fi.com' />

|Platform|Build status|Download|
|--------|------------|--------|
|Windows x64 build|[![Windows x64 CI](https://dev.azure.com/grumpycoders/pcsx-redux/_apis/build/status/grumpycoders.pcsx-redux?branchName=main)](https://dev.azure.com/grumpycoders/pcsx-redux/_build/latest?definitionId=1&branchName=main)|[Windows Intel 64-bits](https://distrib.app/pub/org/pcsx-redux/project/dev-win-x64)|
|Linux x64 build|[![Linux x64 CI](https://github.com/grumpycoders/pcsx-redux/workflows/Linux%20CI/badge.svg?branch=main)](https://github.com/grumpycoders/pcsx-redux/actions?query=workflow%3A%22Linux+CI%22+branch%3Amain)|[Linux Intel 64-bits (AppImage)](https://distrib.app/pub/org/pcsx-redux/project/dev-linux-x64)|
|MacOS x64 build|[![MacOS x64 CI](https://github.com/grumpycoders/pcsx-redux/workflows/macOS%20CI/badge.svg?branch=main)](https://github.com/grumpycoders/pcsx-redux/actions?query=workflow%3A%22macOS+CI%22+branch%3Amain)|[MacOS Intel](https://distrib.app/pub/org/pcsx-redux/project/dev-macos-x64)|

To discuss this emulator specifically, please join our Discord server:

[![Discord](https://discord.com/api/guilds/567975889879695361/widget.png?style=banner2)](https://discord.gg/KG5uCqw)

To discuss PlayStation 1 development, hacking, and reverse engineering in general, please join the PSX.Dev Discord server:

[![Discord](https://discord.com/api/guilds/642647820683444236/widget.png?style=banner2)](https://discord.gg/QByKPpH)

# PCSX-Redux

## What?
The PCSX-Redux project is a collection of tools, research, hardware design, and libraries aiming at development and reverse engineering on the PlayStation 1. The core product itself, PCSX-Redux, is yet another fork of the Playstation emulator, PCSX. While the work here is very much in progress, the goal is roughly the following:

 - Bring the codebase to more up to date code standards.
 - Get rid of the plugin system and create a single monolithic codebase that handles all aspects of the playstation emulation.
 - Write everything on top of OpenGL3+/ImGui for portability and readability.
 - Improve the debugging experience.
 - Improve the rendering experience.

Please consult [the documentation pages](https://pcsx-redux.consoledev.net) for more information on the emulator itself.

The [tools](tools) directory contains a few tools that can be used to work with PlayStation 1 software. The [wiki](https://github.com/grumpycoders/pcsx-redux/wiki) directory contains a few research information that are not directly related to the emulator itself. The [mips](src/mips) directory contains various pieces of code targeting the PlayStation 1, and importantly, the OpenBIOS project, which is a MIPS R3000A BIOS implementation that can be used to boot PlayStation 1 games without the need for a retail BIOS. And the [hardware](hardware) directory contains various hardware designs that can be used with the PlayStation 1.

## Where?
|Download page|
|--------|
|[Windows Intel 64-bits](https://distrib.app/pub/org/pcsx-redux/project/dev-win-x64)|
|[Windows Intel 64-bits CLI](https://distrib.app/pub/org/pcsx-redux/project/dev-win-cli-x64)|
|[Linux Intel 64-bits (AppImage)](https://distrib.app/pub/org/pcsx-redux/project/dev-linux-x64)|
|[MacOS Intel](https://distrib.app/pub/org/pcsx-redux/project/dev-macos-x64)|

### Note:
The macOS version of PCSX-Redux is not currently signed with a developer certificate so you may see a security warning when opening the application.

If you see a dialog with the message:

> “PCSX-Redux” can’t be opened because Apple cannot check it for malicious software.

You can allow the application to run by doing either of the following. You only need to do this once for freshly downloaded copies of PCSX-Redux.

- Right-click the app and select Open. This signals an explicit decision on your part that you really want to open it, and adds a new "Open" button to the security warning dialog.

- Alternatively, go to macOS Settings > Privacy & Security. Scroll down to see a section that will let you allow the app.

## How?
The code is meant to be built using very modern compilers. Also it's still fairly experimental, and lots of things can break. If you still want to proceed, here are instructions to build it on Linux, MacOS and Windows. The code now comes in two big parts: the emulator itself, and [OpenBIOS](https://github.com/grumpycoders/pcsx-redux/tree/main/src/mips/openbios), which can be used as an alternative to the retail, copyright protected BIOS.

### Getting sources
The only location for the source is [on GitHub](https://github.com/grumpycoders/pcsx-redux/).
Clone recursively, as the project uses submodules:
```
git clone --recursive https://github.com/grumpycoders/pcsx-redux.git
```

### Windows
Install [Visual Studio 2022 Community Edition](https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=Community&rel=16) using the `Desktop development with C++` workload. Open the file `vsprojects\pcsx-redux.sln`, select `pcsx-redux -> pcsx-redux`, right click, `Set as Startup Project`, and hit `F7` to build. The project follows the open-and-build paradigm with no extra step, so no specific dependency ought to be needed, as [NuGet](https://www.nuget.org/) will take care of downloading them automatically for you on the first build.

Note: If you get an error saying `hresult e_fail has been returned from a call to a com component`, you might need to delete the .suo file in vsproject/vs, restart Visual Studio and retry.

If you want to compile OpenBIOS or other PS1 software, you need to install a MIPS toolchain on Windows. You can do this by copy-pasting the following into a command prompt:

```powershell
powershell -c "& { iwr -UseBasicParsing https://bit.ly/mips-ps1 | iex }"
```

Then, open a new command prompt, and type the following:

```
mips install 14.1.0
```

To manually install this script, you can download it from [here](https://bit.ly/mips-ps1), and then install it with the following command:

```powershell
powershell -ExecutionPolicy Unrestricted -File mips.ps1 self-install C:\path\to\destination
```

You can leave the installation path blank to install the script in the Application Data folder.

Once the toolchain is installed, you can compile OpenBIOS using `make -C src/mips/openbios`.

### Linux
Run `./dockermake.sh appimage`. You need [docker](https://en.wikipedia.org/wiki/Docker_(software)) for this to work. This will create an [AppImage](https://appimage.org/) file, called `PCSX-Redux-HEAD-x86_64.AppImage`, which a self-hosted binary containing all of its required dependencies. Alternatively, if you do not want to use Docker, you can also simply install the dependencies listed below and run `make`.

#### GNU/Linux Dependencies

If you're only interested in compiling psx code, you can simply clone the pcsx-redux repo, then install `g++-mipsel-linux-gnu cpp-mipsel-linux-gnu binutils-mipsel-linux-gnu` then follow the instructions in `/pcsx-redux/src/mips/psyq/README.md` to convert the PsyQ libraries. You might find them pre-compiled online.

 - Debian derivatives ( for full emulator compilation ):

```bash
sudo apt-get install -y build-essential git make pkg-config clang g++ g++-mipsel-linux-gnu cpp-mipsel-linux-gnu binutils-mipsel-linux-gnu libcapstone-dev libfreetype-dev libavcodec-dev libavformat-dev libavutil-dev libcurl4-openssl-dev libglfw3-dev libswresample-dev libuv1-dev zlib1g-dev
```

 - Arch derivatives :

The `pcsx-redux-git` package can be installed from the AUR using your AUR helper of choice (e.g., paru):

```bash
paru -S pcsx-redux-git
```

Alternatively, the following steps describe how to install dependencies and compile manually:

```bash
sudo pacman -S --needed capstone clang git make pkg-config ffmpeg libuv zlib glfw-x11 curl xorg-server-xvfb imagemagick
```
The mipsel environment can be installed from [AUR](https://wiki.archlinux.org/index.php/Aur) : [cross-mipsel-linux-gnu-binutils](https://aur.archlinux.org/packages/cross-mipsel-linux-gnu-binutils/) and [cross-mipsel-linux-gnu-gcc](https://aur.archlinux.org/packages/cross-mipsel-linux-gnu-gcc/) using your [AURhelper](https://wiki.archlinux.org/index.php/AUR_helpers) of choice:

```bash
trizen -S cross-mipsel-linux-gnu-binutils cross-mipsel-linux-gnu-gcc
```
You can then just enter the 'pcsx-redux' directory and compile without using docker with `make`.

Building OpenBIOS on Linux can be done with `./dockermake.sh -C src/mips/openbios`, or using the `g++-mipsel-linux-gnu` package with `make -C src/mips/openbios`. If you have a different mips compiler, you'll need to override some variables, such as `PREFIX=mipsel-none-elf FORMAT=elf32-littlemips`.

### MacOS
You need MacOS Catalina or later with the latest XCode to build, as well as a few [homebrew](https://brew.sh/) packages. Run the [brew installation script](https://github.com/grumpycoders/pcsx-redux/blob/main/.github/scripts/install-brew-dependencies.sh) to get all the necessary dependencies. Simply run `make` to build.

Compiling OpenBIOS will require a mips compiler, that you can generate using the following commands:
```bash
brew install ./tools/macos-mips/mipsel-none-elf-binutils.rb
brew install ./tools/macos-mips/mipsel-none-elf-gcc.rb
```

Then, you can compile OpenBIOS using `make -C ./src/mips/openbios`.

## Who?
I used to contribute to the PCSX codebase. It is very likely that a sourceforge account of mine still has write access to the old cvs repository for PCSX. A long time ago, I contributed the telnet debugger, and the parallel port support. This means I am fairly familiar with this codebase, and I am also ashamed of the contributions I have done 15+ years ago, as one should.

Since the inception of this codebase, several people have contributed to it. Please refer to the [AUTHORS](AUTHORS) file for a (hopefully) exhaustive list.

## Why?
When Sony released the Playstation Classic recently, I came to realize two things: first, the state of the Playstation emulation isn't that great, and second, the only half-decent debugging tool still available for this console is that old telnet debugger I wrote eons ago, while other emulators out there for other consoles gained a lot of debugging superpowers. I think it was time for the Playstation emulation to get to better standards with regards to debuggability. I also felt I had a responsability to cleaning up some of the horrors I've introduced myself in the codebase long ago, and that made me cry a little looking at them. Hopefully, I got better at programming. Hopefully.

## Status?
The codebase still requires a lot of cleanup, and while the product is usable in its current state and lots can be achieved with it, there is still ways to go for reaching the first stable release. If you want to help with localization, you can find the translation project [on transifex](https://www.transifex.com/grumpycoders/pcsx-redux/languages/).

### What works?
- Dynamic Recompiler (x86-64, experimental arm64 support)
- interpreted CPU
- software GPU
- OpenGL GPU (highly experimental, still in active development)
- support for visual enhancements:
  - Linear and nearest neighbour filtering (Software and OpenGL renderer)
  - Rendering in true colour (Results in better colours, OpenGL renderer only)
  - Antialiasing (Implemented via MSAA, OpenGL renderer only)
  - Ability to optionally render polygons as wireframe or as vertices (Helps with debugging, OpenGL renderer only)
  - Hopefully more to come in the feature, such as upscaling, integer scaling, PGXP, and more
- VRAM viewer and debugger
- fully featured MIPS debugger
- memory cards
- memory card manager
- XBox controller support
- digital and analog controller emulation, Playstation Mouse emulation
- Lua scripting
- SPU debugger
- in-app shader editor and built-in crt-lottes shader
- customizable UI
- save states

### What still requires some work?
- fix remaining OpenGL renderer bugs (No mask bit emulation, missing commands, etc) and add more graphics enhancements
- proper SPU multithreaded code
- better customization
- more generic dynarec
- hook more emulator functions to Lua
- see [TODO](TODO.md) for more

[![Redux definition](https://pbs.twimg.com/media/ENJhNwGWwAEbrGb?format=jpg)](https://twitter.com/MerriamWebster/status/1212357808026341376)
