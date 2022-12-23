# CDRom tests

This directory contains tests for the CDRom controller of the PS1. They are assuming that there is a CD inserted in the drive, and the lid is closed. At the moment, they do not rely on a certain CD, but they will in the future.

The tests are written in C, and are compiled using the [MIPS GCC toolchain](../../psyqo/GETTING_STARTED.md#the-toolchain). The tests are compiled using the `make` command, and the resulting binary needs to be run on systems that have an ANSI console connected.

The tests are checking two things: proper results from the CDRom controller, and approximate timings. The former are exact value checks, and will always reproduce properly on the real hardware. The latter are approximate value checks, and will usually only reproduce properly on the real hardware if the CD is inserted in the drive, the lid is closed, and the drive has been settled for a few seconds, but may still be flaky on the real hardware.

The code is commented to explain what is being tested, and why. The tests are also written to be as self-contained as possible, so that they can be easily copied and modified to test other things.
