|Platform|Build status|
|--------|------------|
|Windows build|[![Build Status](https://dev.azure.com/grumpycoders/pcsx-redux/_apis/build/status/grumpycoders.pcsx-redux?branchName=master)](https://dev.azure.com/grumpycoders/pcsx-redux/_build/latest?definitionId=1&branchName=master)|
|Linux build|[![CircleCI](https://circleci.com/gh/grumpycoders/pcsx-redux.svg?style=svg)](https://circleci.com/gh/grumpycoders/pcsx-redux)|
|MacOS build|![macOS CI](https://github.com/grumpycoders/pcsx-redux/workflows/macOS%20CI/badge.svg?branch=master)]|

# PCSX-Redux

## What?
This is yet another fork of the Playstation Emulator, PCSX. While the work here is very much in progress, the goal is roughly the following:

 - Bring the codebase to more up to date code standards.
 - Get rid of the plugin system and create a single monolithic codebase that handles all aspects of the playstation emulation.
 - Write everything on top of SDL/OpenGL3+/ImGui for portability and readability.
 - Improve the debugging experience.
 - Improve the rendering experience.

## Who?
I used to contribute to the PCSX codebase. It is very likely that a sourceforge account of mine still has write access to the old cvs repository for PCSX. A long time ago, I contributed the telnet debugger, and the parallel port support. This means I am fairly familiar with this codebase, and I am also ashamed of the contributions I have done 15+ years ago, as one should.

## Why?
When Sony released the Playstation mini recently, I came to realize two things: first, the state of the Playstation emulation isn't that great, and second, the only half-decent debugging tool still available for this console is that old telnet debugger I wrote eons ago, while other emulators out there for other consoles gained a lot of debugging superpowers. I think it was time for the Playstation emulation to get to better standards with regards to debuggability. I also felt I had a responsability to cleaning up some of the horrors I've introduced myself in the codebase long ago, and that made me cry a little looking at them. Hopefully, I got better at programming. Hopefully.

## Status?
The codebase still requires a lot of cleanup, and the current product isn't properly usable yet. Despite that, a lot can already be achieved using the product in its current state.

### What works?
- x86 dynarec
- interpreted CPU
- software GPU
- VRAM viewer and debugger
- fully featured MIPS debugger
- memory cards
- XBox controller support
- save states

### What still requires some work?
- GLSL GPU
- proper SPU multithreaded code
- save state slots
- memory card manager
- HLE bios
- ...

![Redux definition](https://pbs.twimg.com/media/ENJhNwGWwAEbrGb?format=jpg)
