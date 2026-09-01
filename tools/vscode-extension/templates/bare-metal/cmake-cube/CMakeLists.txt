
cmake_minimum_required(VERSION 3.25)

# Set the path to the toolchain file, which will configure CMake to use the MIPS
# toolchain rather than its default compiler and proceed in turn to execute
# setup.cmake.
set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_LIST_DIR}/ps1-bare-metal/cmake/toolchain.cmake")

# Tell CMake about the project. The VERSION, DESCRIPTION and HOMEPAGE_URL fields
# are optional, but the project name and LANGUAGES field should be present.
project(
    {{projectName}}
    LANGUAGES    C CXX ASM
    VERSION      1.0.0
    DESCRIPTION  "PSX.Dev project template"
    HOMEPAGE_URL "https://github.com/grumpycoders/pcsx-redux"
)

# Set up compiler flags, initialize the Python environment used to run the
# scripts in the tools directory and define some helper macros.
include(ps1-bare-metal/cmake/setup.cmake)
include(ps1-bare-metal/cmake/tools.cmake)

# Build a "common" library containing basic support code and link it by default
# into every executable.
add_library(
    common OBJECT
    ps1-bare-metal/src/libc/clz.s
    ps1-bare-metal/src/libc/crt0.c
    ps1-bare-metal/src/libc/cxxsupport.cpp
    ps1-bare-metal/src/libc/malloc.c
    ps1-bare-metal/src/libc/misc.c
    ps1-bare-metal/src/libc/setjmp.s
    ps1-bare-metal/src/libc/string.c
    ps1-bare-metal/src/libc/string.s
    ps1-bare-metal/src/ps1/cache.s
    ps1-bare-metal/src/vendor/printf.c
)
target_include_directories(
    common PUBLIC
    ps1-bare-metal/src
    ps1-bare-metal/src/libc
)
link_libraries(common)

# Compile the main executable; you may add more source files by listing them
# here. The addPS1Executable() macro is defined in tools.cmake and automatically
# takes care of converting the built ELF file into a PS1 executable (.psexe)
# which can run be run on emulators or real hardware.
addPS1Executable(
    {{projectName}}
    src/font.c
    src/gpu.c
    src/main.c
    src/trig.c
)

# Convert the font spritesheet to a 4bpp texture and palette, then embed them
# into the executable. The convertImage() and addBinaryFile() macros are defined
# in tools.cmake and setup.cmake respectively. You may call them multiple times
# to embed other images or data into the binary.
convertImage(assets/font.png 4 fontTexture.dat fontPalette.dat)
addBinaryFile({{projectName}} fontTexture "${PROJECT_BINARY_DIR}/fontTexture.dat")
addBinaryFile({{projectName}} fontPalette "${PROJECT_BINARY_DIR}/fontPalette.dat")
