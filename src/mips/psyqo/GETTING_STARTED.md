# The toolchain
In order to develop for the PlayStation1 using the PSYQo library, a modern C++ toolchain is required. There are several different toolchains available for the PS1, but the PSYQo library is designed to work with at least gcc 10 targeting mips I. Here are some installation methods available:

## Linux
### Debian derivatives:

```bash
sudo apt-get install -y make g++-mipsel-linux-gnu
```

### Arch derivatives:
The `pcsx-redux-git` package can be installed from the AUR using your AUR helper of choice (e.g., paru):

```bash
paru -S pcsx-redux-git
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

The PSYQo library is designed to be used linked in with your own project. If you have your own build system, you simply need to build every `.cpp` file in the `src` directory. The root of the `psyqo` directory should be added to the include search path when compiling.

There are some helpers to do this using `make`. The canonical method to use `PSYQo` is to use the [nugget](https://github.com/pcsx-redux/nugget) repository as a submodule for your own project, say in the `third_party` directory. You can create a `hello.cpp` file at the root of your directory that's a copy of [the example hello world](examples/hello/hello.cpp).

Then, create a `Makefile` at the root of your project, which follows the following structure:

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

Once done, you can simply run `make` (or use the `dockermake` script) in your project root to create the application.

See the [examples](examples) directory for more complex project structures you can use. Since the examples are subfolders of the psyqo library, their `Makefile`s will have a different method to include the file `psyqo.mk`, but that's otherwise the only difference.
