# PSX.Dev VSCode extension

This extension provides support for development of PlayStation 1 software. It lets you easily install various tools and libraries, as well as some templates for new projects.

In order to show the tools and templates panels, type the following in the **Ctrl-Shift-P** command palette: `PSX.Dev: Show panel`.

For more information on the tools and libraries, please refer to the [PSX.Dev website](https://psx.dev/). Also feel free to join the [Discord server](https://discord.gg/QByKPpH) for support.

The panel will have the ability to install the tools on the most popular platforms, but there's definitely corner cases when it won't work. When manual installation is required, either look at the homepage provided for each tool, or check the [installation instructions](https://github.com/grumpycoders/pcsx-redux/blob/main/src/mips/psyqo/GETTING_STARTED.md) provided in the documentation. Additionally, the TOOLS panel can leverage [Linuxbrew](https://docs.brew.sh/Homebrew-on-Linux) to install dependencies on an unsupported Linux platform.

### Known issues / limitations

- The extension is currently only targeting Windows, Linux Ubuntu, Arch Linux, and MacOS. It may work on more platforms, but it's not guaranteed, and won't be as automated as it is on the supported platforms.
- Only Windows and Linux Ubuntu have been thoroughly tested for now.
- The extension will not work from the browser as it requires running external tools. It may work in a remote SSH session, but it's not been tested.
- The PCSX-Redux dependency is currently only available on x86_64 platforms, and may possibly work on M1/M2 Macs.
- Linux requires libfuse2 to be installed, for AppImages like the PCSX-Redux dependency to work.
- The PCSX-Redux workflow won't check for system-wide installations, and will always install the dependency locally.

### Changelog

- 0.2.3
  - Fixing MacOS installation of GNU Make trying to install gdb-multiarch instead.
- 0.2.2
  - Added commands `Restore Psy-Q`, `Show PCSX-Redux Settings`, and `Update Modules`.
  - Added support for clangd in the templates.
  - Small fix to PSYQo template.
- 0.2.1
  - Initial public release
