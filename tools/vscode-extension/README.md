# PSX.Dev VSCode extension

This extension provides support for development of PlayStation 1 software. It lets you easily install various tools and libraries, as well as some templates for new projects.

In order to show the tools and templates panels, type the following in the **Ctrl-Shift-P** command palette: `PSX.Dev: Show panel`.

For more information on the tools and libraries, please refer to the [PSX.Dev website](https://psx.dev/). Also feel free to join the [Discord server](https://discord.gg/QByKPpH) for support.

The panel will have the ability to install the tools on the most popular platforms, but there's definitely corner cases when it won't work. When manual installation is required, either look at the homepage provided for each tool, or check the [installation instructions](https://github.com/grumpycoders/pcsx-redux/blob/main/src/mips/psyqo/GETTING_STARTED.md) provided in the documentation. Additionally, the TOOLS panel can leverage [Linuxbrew](https://docs.brew.sh/Homebrew-on-Linux) to install dependencies on an unsupported Linux platform.

### Known issues / limitations

- The extension is currently only targeting Windows, Linux Ubuntu, Arch Linux, and MacOS. It may work on more platforms, but it's not guaranteed, and won't be as automated as it is on the supported platforms.
- Only Windows and Linux Ubuntu have been thoroughly tested for now.
- The extension will not work from the browser as it requires running external tools. It may work in a remote SSH session, but it's not been tested.
- Linux requires libfuse2 to be installed, for AppImages like the PCSX-Redux dependency to work.
- The PCSX-Redux workflow won't check for system-wide installations, and will always install the dependency locally.

### Changelog

- 0.3.9
  - Fixed cube psyqo template's null pointer exception.
  - Improved MacOS mips toolchain installation process.
- 0.3.8
  - Added automatic setup of Python virtual environments in order to reflect the changes in ps1-bare-metal.
  - Fixed compile_flags.txt in template file.
  - Added psyqo cube example.
  - Added download support for Darwin ARM64 (M1/M2/etc) for PCSX-Redux.
- 0.3.7
  - Bumping gcc to 14.2.0
  - Bumping binutils to 2.43
- 0.3.6
  - Bumping gcc to 14.1.0.
- 0.3.5
  - Bumping binutils to 2.42
  - Changing the way the PCSX-Redux dependency is installed, from AppCenter to AppDistrib.
- 0.3.4
  - Added CMake bare-metal templates.
  - Added support for detecting and installing CMake and Python.
  - Added the CMake Tools and MIPS Assembly extensions.
- 0.3.3
  - Adding Net Yaroze template.
  - Refactored the template panel page a bit.
- 0.3.2
  - Fixing PSYQo's template.
- 0.3.1
  - Fixing EASTL paths in PSYQo template for Unix-like systems.
- 0.3.0
  - Overhauled template system.
- 0.2.8
  - Adding main page button to update submodules.
  - Creating categories for templates.
- 0.2.7
  - Adding c_cpp_properties.json to the templates.
  - Bumping Windows mips toolchain to 13.2.0.
- 0.2.6
  - Bumping gcc to 13.2.0.
  - Bumping binutils to 2.41
  - Bumping gdb to 13.2.0
  - Preventing creating projects with spaces in the path.
- 0.2.5
  - Bumping gcc to 13.1.0.
- 0.2.4
  - Fixing MacOS installation of GDB and PCSX-Redux.
  - Fixing templates, trying to call gdb.exe instead of gdb-multiarch.exe on Windows.
- 0.2.3
  - Fixing MacOS installation of GNU Make trying to install gdb-multiarch instead.
- 0.2.2
  - Added commands `Restore Psy-Q`, `Show PCSX-Redux Settings`, and `Update Modules`.
  - Added support for clangd in the templates.
  - Small fix to PSYQo template.
- 0.2.1
  - Initial public release
