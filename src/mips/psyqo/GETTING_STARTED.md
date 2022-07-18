# The toolchain
In order to develop for the PlayStation1 using the PSYQo library, a modern C++ toolchain is required. There are several different toolchains available for the PS1, but the PSYQo library is designed to work with at least gcc 10 targeting mips I. Here are some installation methods available:

## Linux
### Debian derivatives:

```bash
sudo apt-get install -y make g++-mipsel-linux-gnu
```

### Arch derivatives:
The mipsel environment can be installed from [AUR](https://wiki.archlinux.org/index.php/Aur) : [cross-mipsel-linux-gnu-binutils](https://aur.archlinux.org/packages/cross-mipsel-linux-gnu-binutils/) and [cross-mipsel-linux-gnu-gcc](https://aur.archlinux.org/packages/cross-mipsel-linux-gnu-gcc/) using your [AURhelper](https://wiki.archlinux.org/index.php/AUR_helpers) of choice:

```bash
trizen -S cross-mipsel-linux-gnu-binutils cross-mipsel-linux-gnu-gcc
```

### All other flavors of Unix environments:
[This script](https://github.com/grumpycoders/pcsx-redux/blob/main/tools/linux-mips/spawn-compiler.sh) will spawn a working mips toolchain.

## MacOS

Using [Homebrew](https://brew.sh/), you can install the mips toolchain after downloading [these two scripts](https://github.com/grumpycoders/pcsx-redux/tree/main/tools/macos-mips) (or cloning the whole PCSX-Redux repository).

```bash
brew install ./tools/macos-mips/mipsel-none-elf-binutils.rb
brew install ./tools/macos-mips/mipsel-none-elf-gcc.rb
```

## Windows

It is possible to install a mips toolchain on Windows by first running the following command:

```cmd
powershell -c "& { iwr -UseBasicParsing https://raw.githubusercontent.com/grumpycoders/pcsx-redux/main/mips.ps1 | iex }"
```

The computer might need to be rebooted after the installation of this script.

Next, run the following command to install the proper toolchain and its dependencies:

```cmd
mips install 12.1.0
```

## Docker
For users who don't want to modify their environments, it is possible to use [Docker](https://www.docker.com/) to run the mips toolchain. There are to scripts provided at the root of this repository, called `dockermake.sh` for Unix users and `dockermake.bat` for Windows users.

These scripts will behave like the `make` command, running in the same directory where the command was run. It'll be in a Linux environment with an adequate mips toolchain to use.

# Creating a project.

The canonical method to use `PSYQo` is to use the [nugget](https://github.com/pcsx-redux/nugget) repository as a submodule for your own project, say in the `third_party` directory. You can create a `hello.cpp` file at the root of your directory that's a copy of [the example hello world](examples/hello/hello.cpp). Doing a simple code drop of the nugget repository is also acceptable.

Here's how to get all this going. The commands are aimed at Unix environments, but the spirit of what's going on should be very simple to understand for Windows too.

First, let's create a folder for your project:

```bash
mkdir hello
cd hello
```

Then, initialize the git repository:
```bash
git init
```

And then, let's add nugget as a submodule:
```bash
git submodule add https://github.com/pcsx-redux/nugget.git third_party/nugget
```

Now, download [the example hello world](examples/hello/hello.cpp) and drop it in your project folder.

Finally, create a `Makefile` at the root of your project, which follows the following structure:

```makefile
# The name of the binary to be created.
TARGET = hello
# The type of the binary to be created - ps-exe is most common.
TYPE = ps-exe

# The list of sources files to compile within the binary.
SRCS = \
hello.cpp \

# Setting the minimum version of the C++. C++-17 is the minimum required version by PSYQo.
CXXFLAGS = -std=c++20

# This will activate the PSYQo library and the rest of the toolchain.
include third_party/nugget/psyqo.mk
```

Once done, you can simply run `make` (or use the `dockermake` script) in your project root to create the application. This should create the binary called `hello.ps-exe`, which you can then run in the emulator of your choice, or on the real hardware using for example [unirom](https://github.com/JonathanDotCel/unirom8_bootdisc_and_firmware_for_ps1) and [nops](https://github.com/JonathanDotCel/NOTPSXSerial).

See the [examples](examples) directory for more complex project structures you can use. Since the examples are subfolders of the psyqo library, their `Makefile`s will have a different method to include the file `psyqo.mk`, but that's otherwise the only difference.

If a more complex build system is required, compiling PSYQo itself is very simple, and should be straightforward to integrate. Refer to the [Makefile](Makefile) for what to do exactly.

# IDE integration
The recommended IDE is [Visual Studio Code](https://code.visualstudio.com/). The [clangd](https://marketplace.visualstudio.com/items?itemName=llvm-vs-code-extensions.vscode-clangd) extension is configured within PSYQo, and will provide valuable IDE features such as completion or code navigation. It is also possible to debug PSYQo binaries, using the [Native Debug](https://marketplace.visualstudio.com/items?itemName=webfreak.debug) extension. See the [PCSX-Redux's launch.json](https://github.com/grumpycoders/pcsx-redux/blob/main/.vscode/launch.json) for some examples.

# Build options
When using the `psyqo.mk` file, you can specify build options for the PSYQo library and your binary. It is possible to specify the following options:

- `make BUILD=Release`  
This is the default build, and will enable a release build of the library and your binary. It will be fast and small, but debugging will be hard.
- `make BUILD=Debug`  
This will enable a full debug build of the library and your binary. It will be slow and bloated, but debugging will be very easy.
- `make BUILD=SmallDebug`  
This will enable a debug build of the library and your binary with still some optimizations. Debugging is possible, but will be hindered at times. It is the best compromise if debugging is needed while retaining some speed and small code footprint.
- `make BUILD=LTO`  
This will enable a release build of the library and your binary with [LTO](https://gcc.gnu.org/wiki/LinkTimeOptimization) enabled. It will be really fast and really small, but debugging will be impossible.

# Further reading
Moving on to the [Concepts](CONCEPTS.md) page is the next step in understanding how the library functions. The library itself is also thoroughly documented, and the [nugget website](https://pcsx-redux.github.io/nugget/) has a render of the doxygen documentation.

To discuss PlayStation1's development, hacking, and reverse engineering in general, please join the PSX.Dev Discord server: [![Discord](https://img.shields.io/discord/642647820683444236)](https://discord.gg/QByKPpH)
