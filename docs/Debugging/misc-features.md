# Misc Features

## Mapping breakpoints

PCSX-Redux has a feature that allows mapping the memory of the console while the software is running, and to set breakpoints on the mapped memory. This can for instance help in finding codepath when performing certain activities when running code.

First, map the kind of action you want to discover, such as executing code, reading memory, or writing memory. Then, run the code for some time without performing the specific action you want to discover. Finally, activate the map breakpoint mode, and then perform the action you want to discover. The breakpoint should be triggered when the action is performed.

For example, say that in a game, you want to know what code is executed when you press the "X" button. First, check the `Map execution` checkbox. Then, run the game for a while without pressing the "X" button. This will map enough of the memory that's being run in a normal way. Finally, activate the `Break on execution map` checkbox, and press the "X" button. If the game takes a new codepath that hasn't been executed yet, the breakpoint should be triggered.

Breakpoints are always checked before mapping the memory, so it's safe to keep both checkboxes on at the same time.

Click the `Clear maps` button to zero out all of the maps, when starting anew.

## ISO browser file viewer

In the ISO browser (`Debug > CD-Rom > Show Iso Browser`), right-clicking a file offers `View`, next to `Extract`, `Replace` and `Hex Edit`. It opens a `View - <file>` window with up to two tabs:

  * `TIM` : only present when the file parses as a TIM image. Shows its bpp, size and VRAM position, with a `palette` slider when the CLUT holds more than one palette.
  * `Raw image` : decodes the file as 1, 2, 4, 8, 16 or 24 bpp pixels, with `width`, `height (0 = fit)` and `header bytes` set by hand. 16 bpp is read as PlayStation 15-bit colour, 1 to 8 bpp as greyscale.

Both tabs have a `zoom` slider. The viewers are written in Lua and loaded from `resources/fileviewers.lua`; if that file is missing or fails to load, the `View` item does not appear.

## CPU trace dump

### Setup

In PCSX-Redux, make sure `Debug > Show logs` is enabled.

In the 'Logs' window, hide all logs : `Displayed > Hide all`

To avoid unnecessary noise, you can also skip ISR during CPU traces : `Special > Skip ISR during CPU traces`

![Hide all logs](images/pcsx_cpu_dump_hide.png)
![Skip ISR during CPU traces](images/pcsx_cpu_dump_isr.png)

### Begin dump

To dump the CPU traces, launch pcsx-redux with the following command :

```bash
pcsx-redux -stdout -logfile log.txt
# Alternatively, you can use -stdout on its own and pipe the output to a file.
pcsx-redux -stdout >> log.txt
```

You can use [additional flags](../cli_flags.md) to launch an executable/disk image in one go, e.g :

```bash
pcsx-redux -stdout -logfile tst.log -iso image.cue -run
```

### Source 

[https://discord.com/channels/642647820683444236/663664210525290507/882608398993063997](https://discord.com/channels/642647820683444236/663664210525290507/882608398993063997)
