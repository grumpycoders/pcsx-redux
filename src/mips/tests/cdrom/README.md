# CDRom tests

This directory contains tests for the CDRom controller of the PS1. They are assuming that there is a CD inserted in the drive, and the lid is closed. At the moment, they do not rely on a certain CD, but they will in the future.

The tests are written in C, and are compiled using the [MIPS GCC toolchain](../../psyqo/GETTING_STARTED.md#the-toolchain). The tests are compiled using the `make` command, and the resulting binary needs to be run on systems that have an ANSI console connected.

The tests are checking two things: proper results from the CDRom controller, and approximate timings. The former are exact value checks, and will always reproduce properly on the real hardware. The latter are approximate value checks, and will usually only reproduce properly on the real hardware if the CD is inserted in the drive, the lid is closed, and the drive has been settled for a few seconds, but may still be flaky on the real hardware.

The code is commented to explain what is being tested, and why. The tests are also written to be as self-contained as possible, so that they can be easily copied and modified to test other things.

All in all, these tests are overdoing it in terms of state and feature tests, and over aggressive. PS1 games most definitely do not need this level of accuracy, but this controller is so finicky that it is better to be safe than sorry. An emulator able to pass these tests ought to be able to run anything, as long as the main CPU timings are somewhat accurate.

A word on timings: the timings are measured using the hblank timer, which is usually pretty easy to get right in terms of accuracy. However, many games will have busy wait loop when talking to the controller, or race conditions between sending commands. This means that if the CPU runs too slow or too quickly, bugs will surface. If the emulator is passing the timing tests, but games are failing, it is likely that the CPU emulation speed accuracy is at fault here, not the controller's.
