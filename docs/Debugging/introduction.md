# Debugging with PCSX-Redux

PCSX-Redux has strong debugging capabilities. It has a [built-in GDB server](gdb-server.md), which allows you to connect to it with a GDB client, such as gdb itself when targeting MIPS, a vscode connector, IDA Pro, or Ghidra, and debug the MIPS CPU. See [debugging with Ghidra](ghidra.md) for more information on debugging with Ghidra.

There are also built-in debugging tools, available in the Debug menu. Most of the CPU debugging features will require switching the Dynarec off from the Emulation configuration menu, as the Dynarec is not compatible with the debugging features. Additionally, the debugger needs to be enabled, also in the Emulation configuration menu.

The GPU debugging tools can work with the Dynarec enabled, and thus will be much faster than when the interpreter is used.