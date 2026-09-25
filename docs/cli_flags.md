# Command Line Flags

You can launch `pcsx-redux` with the following command line parameters:

**The parsing code doesn't care about the number of dashes in the parameter's flag, so '-' can be used as well as '--', or any number of dashes.**

| Flag | Meaning |
| :- | :- |
| `-dumpproto` | Dump the protobuf schemas for PCSX-Redux on stdout and exit immediately. |
| `-version` | Print the version information as JSON on stdout and exit immediately. |
| `-no-ui` | Run without the graphical user interface, using a text interface instead. Implies `-stdout` and `-lua_stdout`. |
| `-cli` | Same as `-no-ui`, and also implies `-safe`. |
| `-run` | Begin execution immediately on startup. |
| `-stdout` | Redirect log output to stdout. |
| `-lua_stdout` | Redirect Lua's console output to stdout. |
| `-logfile` | Specify a file to log output to. |
| `-bios` | Specify a BIOS file. |
| `-testmode` | Interpret [internal API](mips_api.md)'s `pcsx_exit()` command as a request to exit the emulator instead of pausing, and close the emulator. Implies `-safe`, `-no-gui-log`, and will also disable first chance exceptions. If no BIOS could be loaded, the emulator exits with code -1 (255 on POSIX systems) right after the "No BIOS loaded" message, instead of halting. Use only when doing unit testing. |
| `-exe` | Load a PSX exe. |
| `-loadexe` | Load a PSX exe. |
| `-iso` | Load a PSX disk image (iso, bin/cue). |
| `-loadiso` | Load a PSX disk image (iso, bin/cue). |
| `-disk` | Load a PSX disk image (iso, bin/cue). |
| `-memcard1` | Specify a memory card file to use as memory card slot 1. |
| `-memcard2` | Specify a memory card file to use as memory card slot 2. |
| `-pcdrv` | Enable the pcdrv device interface. (Access PC filesystem through SIO). |
| `-no-pcdrv` | Disable the pcdrv device interface. Will change the saved setting. |
| `-pcdrvbase` | Specify base directory for pcdrv. |
| `-safe` | Resets configuration to defaults. |
| `-resetui` | Resets the UI to its defaults. |
| `-noshaders` | Displays the emulated output without going through the output shaders. |
| `-noupdate` | Disables the automatic update checks. |
| `-viewports` | Enables ImGui viewports, allowing windows to be dragged outside of the main window. Enabled by default except on Linux. |
| `-no-viewports` | Disables ImGui viewports. |
| `-kiosk` | Enables kiosk mode, disabling UI interaction. Will change the saved setting. |
| `-no-kiosk` | Disables kiosk mode, allowing the user to interact with the UI. Will change the saved setting. |
| `-interpreter` | Use the interpreter CPU core. |
| `-dynarec` | Use the dynamic recompiler CPU core. |
| `-openglgpu` | Use the OpenGL GPU renderer. Will change the saved setting. |
| `-softgpu` | Use the software GPU renderer. Will change the saved setting. |
| `-8mb` | Emulates 8MB of RAM instead of 2MB. Will change the saved setting. |
| `-2mb` | Emulates 2MB of RAM. Will change the saved setting. |
| `-debugger` | Activates the debugger. Will change the saved setting. |
| `-no-debugger` | Deactivates the debugger. Will change the saved setting. |
| `-fastboot` | Skips the BIOS logo and boot animation. Will change the saved setting. |
| `-no-fastboot` | Shows the BIOS logo and boot animation. Will change the saved setting. |
| `-gdb` | Activates the gdb server. Will change the saved setting. |
| `-no-gdb` | Deactivates the gdb server. Will change the saved setting. |
| `-gdb-port` | Sets the TCP port the gdb server is listening on. Will change the saved setting. |
| `-webserver` | Activates the [web server](web_server.md). Will change the saved setting. |
| `-no-webserver` | Deactivates the web server. Will change the saved setting. |
| `-webserver-port` | Sets the TCP port the web server is listening on. Will change the saved setting. |
| `-trace` | Activates the CPU trace logging. Will change the saved setting. |
| `-no-trace` | Deactivates the CPU trace logging. Will change the saved setting. |
| `-no-gui-log` | Fully disables logs to be sent to the GUI. |
| `-archive` | Specifies a .zip file to load for the `Support.extra.dofile` function. |
| `-dofile` | Specifies a Lua file to load through the `Support.extra.dofile` function. |
| `-exec` | Specifies a Lua string to execute. |
| `-luacov` | Enables Lua code coverage report. Requires the `luacov` Lua module to be installed. |
| `-portable` | Enables portable mode. Settings and saves are stored in the current directory, or in the directory given as an optional argument to this flag. See [Where your data lives](#where-your-data-lives). |
| `-no-portable` | Disables portable mode, overriding any of the automatic detections described below. |

## Missing files

Before anything starts, the files given to `-bios`, `-iso`, `-loadiso`, `-disk`, `-exe`, `-loadexe` and `-archive` must exist, and `-pcdrvbase` must be a directory. Otherwise the emulator prints one line per missing path on stderr and exits with code 1. A missing `-bios` file is an error: the OpenBIOS fallback only applies to a BIOS set in the configuration.

`-memcard1` and `-memcard2` are not checked, since missing memory cards are created on demand. Neither is `-dofile`, which is looked up through `-archive`.

## Where your data lives

Settings, memory cards and save states go in one of two places.

**Normally** they go in a per-user directory: `%APPDATA%\pcsx-redux` on Windows and
`$HOME/.config/pcsx-redux` everywhere else, macOS included. It is created on first run.

**In portable mode** they go in the portable directory instead, which is the current
directory unless something else set it. Portable mode turns on when any of these is true:

- `-portable` was passed;
- a `pcsx.json` exists in the current directory;
- a `pcsx.json` exists next to the executable, in which case the portable directory is
  the executable's directory and not the current one;
- the emulator is being run out of its own source tree.

`-no-portable` turns it off again.

The current directory is not always the directory holding the binary. A shortcut with its
own start-in, a file association on a disc image, or a frontend will each hand the emulator
something else. For a portable install that follows the binary, put the `pcsx.json` next to
it; then the launch directory stops mattering.
