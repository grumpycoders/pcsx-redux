# PCSX-Redux's Lua API

PCSX-Redux features a Lua API that's available through either a direct Lua console, or a Lua editor, both available through the Debug menu.

## Lua engine
The Lua engine that's being used is LuaJIT 2.1.0-beta3. The [Lua 5.1 user manual](https://www.lua.org/manual/5.1/) and [LuaJIT user manual](https://luajit.org/extensions.html) are recommended reads. In particular, the bindings heavily make use of LuaJIT's FFI capabilities, which allows for direct memory access within the emulator's process. This means there is little protection against dramatic crashes the LuaJIT FFI engine can cause into the emulator's process, and the user must pay extra attention while manipulating FFI objects. Despite that, the code tries as much as possible to sandbox what the Lua code does, and will prevent crashes on any recoverable exception, including OpenGL and ImGui exceptions.

## Lua console
All of the messages coming from Lua should display into the Lua console directly. The input text there is a single line execution, so the user can type one-liner Lua statements and get an immediate result.

## Lua editor
The editor allows for more complex, multi-line statements to be written, such as complete functions. The editor will by default auto save its contents on the disc under the filename `pcsx.lua`, which can potentially be a problem if the last statement typed crashed the emulator, as it'll be reloaded on the next startup. It might become necessary to either edit the file externally, or simply delete it to recover from this state.

The auto-execution of the editor permits for rapid development loop, with immediate feedback of what's done.

## API

### Basic Lua
The [LuaJIT extensions](https://luajit.org/extensions.html) are fully loaded, and can be used globally. Most of the [standard Lua libraries](https://www.lua.org/manual/5.1/manual.html#5) are loaded, and are usable. The `require` keyword however doesn't exist at the moment. As a side-effect of Luv, [Lua-compat-5.3](https://github.com/keplerproject/lua-compat-5.3) is loaded.

### Dear ImGui
A good portion of [ImGui](https://github.com/ocornut/imgui) is bound to the Lua environment, and it's possible for the Lua code to emit arbitrary widgets through ImGui. It is advised to consult the [user manual](https://pthom.github.io/imgui_manual_online/manual/imgui_manual.html) of ImGui in order to properly understand how to make use of it. The list of current bindings can be found [within the source code](https://github.com/grumpycoders/pcsx-redux/blob/main/third_party/imgui_lua_bindings/imgui_iterator.inl). Some usage examples will be provided within the case studies.

### OpenGL
OpenGL is bound directly to the Lua API through FFI bindings, loosely inspired and adapted from [LuaJIT-OpenCL](https://github.com/malkia/luajit-opencl
). Some usage examples can be seen in the CRT-Lottes shader configuration page.

### Luv
For network access and interaction, PCSX-Redux uses libuv internally, and this is exposed to the Lua API through [Luv](https://github.com/luvit/luv)

### Zlib
The Zlib C-API is exposed through [FFI bindings](https://github.com/luapower/zlib).

### PCSX-Redux

#### ImGui interaction
PCSX-Redux will periodically try to call the Lua function `DrawImguiFrame` to allow the Lua code to draw some widgets on screen. The function will be called exactly once per actual UI frame draw, which, when the emulator is running, will correspond to the emulated GPU's vsync. If the function throws an exception however, it will be disabled until recompiled with new code.

#### Memory and registers
The Lua code can access the emulated memory and registers directly through some FFI bindings:

- `PCSX.getMemPtr()` will return a `cdata[uint8_t*]` representing up to 8MB of emulated memory. This can be written to, but careful about the emulated i-cache in case code is being written to.
- `PCSX.getRomPtr()` will return a `cdata[uint8_t*]` representing up to 512kB of the BIOS memory space. This can be written to.
- `PCSX.getScratchPtr()` will return a `cdata[uint8_t*]` representing up to 1kB for the scratchpad memory space.
- `PCSX.getRegisters()` will return a structured cdata representing all the registers present in the CPU:

```c
typedef union {
    struct {
        uint32_t r0, at, v0, v1, a0, a1, a2, a3;
        uint32_t t0, t1, t2, t3, t4, t5, t6, t7;
        uint32_t s0, s1, s2, s3, s4, s5, s6, s7;
        uint32_t t8, t9, k0, k1, gp, sp, s8, ra;
        uint32_t lo, hi;
    } n;
    uint32_t r[34];
} psxGPRRegs;

typedef union {
    uint32_t r[32];
} psxCP0Regs;

typedef union {
    uint32_t r[32];
} psxCP2Data;

typedef union {
    uint32_t r[32];
} psxCP2Ctrl;

typedef struct {
    psxGPRRegs GPR;
    psxCP0Regs CP0;
    psxCP2Data CP2D;
    psxCP2Ctrl CP2C;
    uint32_t pc;
} psxRegisters;
```

#### Execution flow
The Lua code has the following 4 API functions available to it in order to control the execution flow of the emulator:

- `PCSX.pauseEmulator()`
- `PCSX.resumeEmulator()`
- `PCSX.softResetEmulator()`
- `PCSX.hardResetEmulator()`

#### Breakpoints
If the debugger is activated, and while using the interpreter, the Lua code can insert powerful breakpoints using the following API:

```lua
PCSX.addBreakpoint(address, type, width, cause, invoker)
```

**Important**: the return value of this function will be an object that represents the breakpoint itself. If this object gets garbage collected, the corresponding breakpoint will be removed. Thus it is important to store it somewhere that won't get garbage collected right away.

The only mandatory argument is `address`, which will by default place an execution breakpoint at the corresponding address. The second argument `type` is an enum which can be represented by one of the 3 following strings: `'Exec'`, `'Read'`, `'Write'`, and will set the breakpoint type accordingly. The third argument `width` is the width of the breakpoint, which indicates how many bytes should intersect from the base address with operations done by the emulated CPU in order to actually trigger the breakpoint. The fourth argument `cause` is a string that will be displayed in the logs about why the breakpoint triggered. It will also be displayed in the Breakpoint Debug UI. And the fifth and final argument `invoker` is a Lua function that will be called whenever the breakpoint is triggered. By default, this will simply call `PCSX.pauseEmulator()`. If the invoker returns `false`, the breakpoint will be permanently removed.

The returned object will have a few methods attached to it:

- `:disable()`
- `:enable()`
- `:isEnabled()`
- `:remove()`

A removed breakpoint will no longer have any effect whatsoever, and none of its methods will do anything. Remember it is possible for the user to still manually remove a breakpoint from the UI.
