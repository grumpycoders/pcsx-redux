
# PSX.Dev

Welcome to your new PSX.Dev project!

In order to build your project, open the command palette (Ctrl+Shift+P) and run
the "PSX.Dev: Build Debug" command, or the "PSX.Dev: Build Release" command to
build it in release mode (enabling additional optimizations that would interfere
with debugging). You can also use the "PSX.Dev: Clean" command to delete all
built files, which is useful when switching between debug and release builds.
All three commands are additionally available as VS Code tasks, which you can
find by selecting the "Tasks: Run Task" command.

If you wish to build the project manually or outside of VS Code, you may open a
terminal in the project's root directory and run one of the following commands:

```bash
{{^isCMake}}
# Build in debug mode
make BUILD=Debug

# Build in release mode
make

# Delete all built files
make clean
{{/isCMake}}
{{#isCMake}}
# Prepare for a debug build
cmake --preset debug

# Prepare for a release build
cmake --preset release

# Prepare for a size-optimized release build
cmake --preset min-size-release

# Run the build
cmake --build build

# Delete all built files
cmake --build build -t clean
{{/isCMake}}
```

And finally, you can debug your project through the PCSX-Redux emulator by
pressing F5. You will first need to have a GDB server running in the background,
which you can do by running the "PSX.Dev: Launch PCSX-Redux" command. Please
note that debugging won't work unless the recommended tools are installed.

The main PSX.Dev panel may be opened at any time by pressing Ctrl+Shift+P and
running the "PSX.Dev: Show panel" command, in order to get all of the relevant
documentation and links from the TEMPLATES tab.
