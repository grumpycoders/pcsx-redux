
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

# Locate a working Python installation in order to run the scripts in the tools
# directory.
find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)

# Build a "common" library containing basic support code. We are going to link
# this library into our executable.
add_library(
    common OBJECT
    ps1-bare-metal/src/libc/crt0.c
    ps1-bare-metal/src/libc/cxxsupport.cpp
    ps1-bare-metal/src/libc/malloc.c
    ps1-bare-metal/src/libc/memset.s
    ps1-bare-metal/src/libc/misc.c
    ps1-bare-metal/src/libc/misc.s
    ps1-bare-metal/src/libc/string.c
    ps1-bare-metal/src/vendor/printf.c
)
target_include_directories(
    common PUBLIC
    ps1-bare-metal/src
    ps1-bare-metal/src/libc
)

# Define a helper function to embed the contents of a file into the executable.
function(addBinaryFile target name path)
    set(_file "${PROJECT_BINARY_DIR}/includes/${target}_${name}.s")
    cmake_path(ABSOLUTE_PATH path OUTPUT_VARIABLE _path)

    # Generate an assembly listing that uses the .incbin directive to embed the
    # file and add it to the executable's list of source files. This may look
    # hacky, but it works and lets us easily customize the symbol name (i.e. the
    # name of the "array" that will contain the file's data).
    file(
        CONFIGURE
        OUTPUT  "${_file}"
        CONTENT [[
.section .data.${name}, "aw"
.balign 8

.global ${name}
.type ${name}, @object
.size ${name}, (${name}_end - ${name})

${name}:
    .incbin "${_path}"
${name}_end:
]]
        ESCAPE_QUOTES
        NEWLINE_STYLE LF
    )

    target_sources(${target} PRIVATE "${_file}")
    set_source_files_properties("${_file}" PROPERTIES OBJECT_DEPENDS "${_path}")
endfunction()

# Create the main executable. You may add more source files by listing them
# here, or other images or files by adding calls to addBinaryFile().
add_executable(
    {{projectName}}
    src/font.c
    src/gpu.c
    src/main.c
    src/trig.c
)
target_link_libraries({{projectName}} PRIVATE common)

addBinaryFile({{projectName}} fontTexture assets/fontTexture.dat)
addBinaryFile({{projectName}} fontPalette assets/fontPalette.dat)

# Add a step to run convertExecutable.py after the executable is compiled in
# order to convert it into a PS1 executable. By default all custom commands run
# from the build directory, so paths to files in the source directory must be
# prefixed with ${PROJECT_SOURCE_DIR}.
add_custom_command(
    TARGET     {{projectName}} POST_BUILD
    BYPRODUCTS {{projectName}}.psexe
    COMMAND
        "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/ps1-bare-metal/tools/convertExecutable.py"
        "$<TARGET_FILE:{{projectName}}>" {{projectName}}.psexe
    VERBATIM
)
