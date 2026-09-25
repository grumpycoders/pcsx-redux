# Compiling PCSX-Redux

## Getting the sources
The only location for the source is [on github](https://github.com/grumpycoders/pcsx-redux/). Clone recursively, as the project uses submodules: 

`git clone https://github.com/grumpycoders/pcsx-redux.git --recursive`.

The PlayStation side of the code, which includes [OpenBIOS](./openbios.md), PSYQo, and the MIPS tests, lives in its own repository, [nugget](https://github.com/pcsx-redux/nugget), which is mounted as a submodule at `src/mips`. Nugget has submodules of its own, so the clone needs to be recursive for it to be complete.

If you already have a checkout, run the following after pulling, so that new or moved submodules get fetched:

```bash
git submodule update --init --recursive
```

## Windows

Install [Visual Studio 2026 Community Edition](https://visualstudio.microsoft.com/vs/community/) using the `Desktop development with C++` workload, and the `C++ Clang tools for Windows` component, as some of the projects use the ClangCL toolset.   
Open the file `vsprojects\pcsx-redux.sln`, select `pcsx-redux -> pcsx-redux`, right click, `Set as Startup Project`, and hit `F7` to build.  
The project follows the open-and-build paradigm with no extra step, so no specific dependency ought to be needed, as [NuGet](https://www.nuget.org/)
will take care of downloading them automatically for you on the first build.

Note: If you get an error saying `hresult e_fail has been returned from a call to a com component`, you might need to delete the .suo file in vsproject/vs, restart Visual Studio and retry.

#### Openbios

Using [Visual Studio Code](https://code.visualstudio.com/), one can use the task "make_openbios" to compile: CTRL-P then `task make_openbios` to compile.

## Linux

### Compiling with Docker

Run `./dockermake.sh`. You need [docker](https://en.wikipedia.org/wiki/Docker_(software)) for this to work.
```bash
# Debian derivative; Ubuntu, Mint...
sudo apt install docker.io
# Arch derivative; Manjaro...
sudo pacman -S docker
```

You will also need a few libraries on your system for this to work. 
Check the [Dockerfile](https://github.com/grumpycoders/pcsx-redux/blob/main/tools/build/Dockerfile#L41-L51) for a list of library packages to install.

### Compiling with make

 - Debian derivatives ( for full emulator compilation ):

```bash
sudo apt-get install -y build-essential git make pkg-config clang g++ libcapstone-dev libfreetype-dev libavcodec-dev libavformat-dev libavutil-dev libcurl4-openssl-dev libsdl3-dev libswresample-dev libuv1-dev zlib1g-dev
```

 - Arch derivatives :

```bash
sudo pacman -S capstone clang git make pkg-config ffmpeg freetype2 libuv zlib sdl3 curl xorg-server-xvfb
```

You can then just enter the 'pcsx-redux' directory and compile without using docker with `make`.

If you have a different mips compiler, you'll need to override the `PREFIX` and `FORMAT` variables, which default to `PREFIX=mipsel-none-elf FORMAT=elf32-littlemips`.  

#### Openbios

Building [OpenBIOS](./openbios.md) on Linux can be done with docker : `./dockermake.sh openbios`,  
or using `make`, with a `mipsel-none-elf` toolchain installed (see [below](#getting-the-toolchain-on-gnulinux)) ; `make openbios`.  

### MacOS
You need MacOS Catalina with the latest XCode to build, as well as a few [homebrew](https://brew.sh/) packages.  
Run the [brew installation script](https://github.com/grumpycoders/pcsx-redux/blob/main/.github/scripts/install-brew-dependencies.sh) to get all the necessary dependencies.

Run `make` to build.  

Compiling  [OpenBIOS](./openbios.md) will require a mips compiler, that you can generate using the following commands:  

#### Openbios

```bash
brew install nikitabobko/tap/brew-install-path
brew install-path ./tools/macos-mips/mipsel-none-elf-binutils.rb
brew install-path ./tools/macos-mips/mipsel-none-elf-gcc.rb
```

Then, you can compile  [OpenBIOS](./openbios.md) using `make -C ./src/mips/openbios`.

## Compiling PSX code

If you're only interested in compiling psx code, you can clone the PCSX-Redux repo; 
```bash
git clone https://github.com/grumpycoders/pcsx-redux.git --recursive
```  
then install a mips toolchain and get the converted PsyQ libraries in the `pcsx-redux/src/mips/psyq/` folder as per  [these instructions](https://github.com/pcsx-redux/nugget/blob/main/psyq/README.md).  
The `src/mips` folder is the [nugget](https://github.com/pcsx-redux/nugget) submodule, so it is only populated if the clone was recursive.

You can also [find the pre-compiled converted Psyq libraries online](https://github.com/ABelliqueux/nolibgs_hello_worlds/blob/main/README.md#nugget--psyq-setup).

### Getting the toolchain on Windows

Install the `mips` toolchain manager script by copy-pasting the following into a command prompt:

```cmd
powershell -c "& { iwr -UseBasicParsing https://raw.githubusercontent.com/grumpycoders/pcsx-redux/main/mips.ps1 | iex }"
```

Then, open a new command prompt, and install the toolchain, which will also be added to your `PATH`:

```cmd
mips install 16.2.0
```

You can test it's working by [launching a command prompt](https://www.lifewire.com/how-to-open-command-prompt-2618089) and typing `mipsel-none-elf-gcc.exe --version`. If you get a message like `mipsel-none-elf-gcc (GCC) 16.2.0`, then it's working !

### Getting the toolchain on GNU/Linux 

#### Debian derivative; Ubuntu, Mint...

There's no distribution package for the `mipsel-none-elf` toolchain, so build it from source, from the root of the repository:

```bash
sudo apt-get install -y make wget bzip2 xz-utils bison flex texinfo libgmp-dev libmpfr-dev libmpc-dev
sudo bash tools/linux-mips/spawn-compiler.sh
```
#### Arch derivative; Manjaro...

The mipsel environment can be installed from [AUR](https://wiki.archlinux.org/index.php/Aur) : [mipsel-none-elf-binutils](https://aur.archlinux.org/packages/mipsel-none-elf-binutils/) and [mipsel-none-elf-gcc](https://aur.archlinux.org/packages/mipsel-none-elf-gcc/) using your [AURhelper](https://wiki.archlinux.org/index.php/AUR_helpers) of choice:

```bash
trizen -S mipsel-none-elf-binutils mipsel-none-elf-gcc
```
