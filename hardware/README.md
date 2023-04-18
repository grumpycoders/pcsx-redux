# Hardware

This directory contains various hardware mods and addons for the PlayStation 1. The PCBs have been designed using Eagle, and pre-rendered gerber files are provided. When applicable, [jlcpcb](https://jlcpcb.com) build files are provided (BoM and assembly CSV files).

Some of these designs have been thoroughly documented [in the wiki](https://github.com/grumpycoders/pcsx-redux/wiki).

* [MC-Breakout](MC-Breakout) - A breakout board for the PlayStation 1's memory card slot. This board is made to fit directly into the slot without a case, and provides a simple header to connect to the memory card slot's signals.

* [PIO-Breakout](PIO-Breakout) - A breakout board for the PlayStation 1's parallel I/O port. This board is designed to function as a pass-through, which can then be used to sniff the parallel I/O port's signals when connecting another flash cart to it.

* [PIO-Dev](PIO-Dev) - A development board for the PlayStation 1's parallel I/O port. The board has [extensive documentation](https://github.com/grumpycoders/pcsx-redux/wiki/PIODev-Board) on the wiki.

* [PowerReplayUSB](PowerReplayUSB) - An easy to build mod for the popular and readily available [Power Replay Flash Cart](https://www.aliexpress.com/w/wholesale-ps1-power-replay.html) which adds USB support to it. The USB support is provided by the [FT232H](https://ftdichip.com/products/ft232hq/) chip, and [unirom](https://unirom.github.io/) has support for it. There is a [USB-C alternative](PowerReplayUSBC) available as well.
