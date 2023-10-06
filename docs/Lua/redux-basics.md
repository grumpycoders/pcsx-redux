# Redux basic API

## Settings
All of the settings are exposed to Lua via the `PCSX.settings` table. It contains pseudo-tables that are reflections of the internal objects, and can be used to read and write the settings. The exact list of settings can vary quickly over time, so making a full list here would be fruitless. It is possible however to traverse the settings using `pprint` for example. The semantic of the settings is the same as from within the GUI, with the same caveats. For example, disabling the dynamic recompiler requires a reboot of the emulator.

## ImGui interaction
PCSX-Redux will periodically try to call the Lua function `DrawImguiFrame` to allow the Lua code to draw some widgets on screen. The function will be called exactly once per actual UI frame draw, which, when the emulator is running, will correspond to the emulated GPU's vsync. If the function throws an exception however, it will be disabled until recompiled with new code.

## Events Engine interaction & Execution Contexts
LuaJIT C callbacks aren't called from a safe execution context that can allow for coroutine resuming, and luv's execution context doesn't have any error handling.

It is possible to defer executing code to the main loop of PCSX-Redux, which can (a) resume coroutines and (b) execute code in a safe context. The function `PCSX.nextTick(func)` will execute the given function in the next main loop iteration. Here's some examples of how to use it:

```lua
    local captures = {}
    captures.current = coroutine.running()
    captures.callback = function()
        PCSX.nextTick(function()
            captures.callback:free()
            coroutine.resume(captures.current)
        end)
    end
    captures.callback = ffi.cast('void (*)()', captures.callback)
    -- use the C callback somewhere...
```

```lua
function createClient(ip, port)
  client = luv.new_tcp()

  luv.tcp_connect(client, ip, port, function (err)
    PCSX.nextTick(function()
      assert(not err, err)

      luv.read_start(client, function (err, chunk)
        PCSX.nextTick(function()
          pprint("received at client", {err=err, chunk=chunk})
          assert(not err, err)
          if chunk then
            -- do something with the client
          else
            luv.close(client)
          end
        end)
      )

      pprint("writing from client")
      luv.write(client, "Hello")
      luv.write(client, "World")

    end
  end)
  return client
end
```

Of course, this can also delay processing significantly, as the main loop is usually bound to the speed of the UI, which can mean up to 20ms of delay.

## Constants
The table `PCSX.CONSTS` contains numerical constants used throughout the rest of the API. Keeping an up to date list here is too exhausting, and it's simpler to print them using `pprint(PCSX.CONSTS)`.

## Pads
You can access the pads API through `PCSX.SIO0.slots[s].pads[p]` where `s` is the slot number and `p` is the pad number, both indexed from 1, Lua-style. So `PCSX.SIO0.slots[1].pads[1]` accesses the first pad, and `PCSX.SIO0.slots[2].pads[1]` accesses the second pad.

Each Pad table has the following functions:

```lua
getButton(button)     -- Returns true if the specified button is pressed.
setOverride(button)   -- Overrides the specified button.
clearOverride(button) -- Clears the override for the specified button.
setAnalogMode(bool)   -- Sets or clears the analog mode of this pad.
map()                 -- Forces the pad to be remapped. Useful after changing pad settings.
```

The button constants can be found in `PCSX.CONSTS.PAD.BUTTON`.

You can for instance press the button Down on the first pad using the following code:

```lua
PCSX.SIO0.slots[1].pads[1].setOverride(PCSX.CONSTS.PAD.BUTTON.DOWN)
```

## Execution flow
The Lua code has the following API functions available to it in order to control the execution flow of the emulator:

 - `PCSX.pauseEmulator()`
 - `PCSX.resumeEmulator()`
 - `PCSX.softResetEmulator()`
 - `PCSX.hardResetEmulator()`

It's also possible to manipulate savestates using the following functions:

 - `PCSX.createSaveState()    -- returns a slice representing the savestate`
 - `PCSX.loadSaveState(slice)`
 - `PCSX.loadSaveState(file)`

Additionally, the following function returns a string containing the .proto file used to serialize the savestate:

 - `PCSX.getSaveStateProtoSchema()`

Note that the actual savestates made from the UI are gzip-compressed, but the functions above don't compress or decompress the data, so if trying to reload a savestate made from the UI, it'll need to be decompressed first, possibly through the zReader File object.

Overall, this means the following is possible:

```lua
local compiler = require('protoc').new()
local pb = require('pb')

local state = PCSX.createSaveState()
compiler:load(PCSX.getSaveStateProtoSchema())

local decodedState = pb.decode('SaveState', Support.sliceToPBSlice(state))
print(string.format('%08x', decodedState.registers.pc))
```

## Messages
The globals `print` and `printError` are available, and will display logs in the Lua Console. You can also use `PCSX.log` to display a line in the general Log window. All three functions should behave the way you'd expect from the normal `print` function in mainstream Lua.

## GUI
You can move the cursor within the assembly window and the first memory view using the following functions:

- `PCSX.GUI.jumpToPC(pc)`
- `PCSX.GUI.jumpToMemory(address[, width])`

## GPU
You can take a screenshot of the current view of the emulated display using the following:

- `PCSX.GPU.takeScreenShot()`

This will return a struct that has the following fields:
```c
struct ScreenShot {
    Slice data;
    uint16_t width, height;
    enum { BPP_16, BPP_24 } bpp;
};
```

The `Slice` will contain the raw bytes of the screenshot data. It's meant to be written out using the `:writeMoveSlice()` method on a `File` object. The `width` and `height` will be the width and height of the screenshot, in pixels. The `bpp` will be either `BPP_16` or `BPP_24`, depending on the color depth of the screenshot. The size of the `data` Slice will be `height * width` multiplied by the number of bytes per pixel, depending on the `bpp`.

## Miscellaneous

- `PCSX.quit([code])` schedules the emulator to quit. It's not instantaneous, and will only quit after the current block of Lua code has finished executing, which will be before the next main loop iteration. The `code` parameter is optional, and will be the exit code of the emulator. If not specified, it'll default to 0.
