List of things to still do here, in no particular order.

- New GPU code
  - Stop using a pure software GPU, and write a GLSL GLES3.0 one instead.
  - Heavily clean up GPU command parser code.
  - Re-add iCatbutler's PGXP stuff.
  - Add a GPU logger / debugger.
  - Properly integrate IRQ control.
  - Better framerate control with SPU pushback.

- SPU cleanup
  - Properly support CDDA/XA volume settings.
  - Reduce latency.
  - Fix XA decoding.
  - Properly integrate IRQ control.

- Memory mapper
  - Properly support RAM_SIZE hardware register to dynamically resize the machine's memory.
  - Support the DTL-H2x00 secondary BIOS SRAM region.
  - Throw away the current parallel port support.

- Scripting
  - Add a scripting engine (LuaJIT).
  - Bind most of the emulator functions to it.
  - Bind parallel port card system to it, so to have a flexible cart management system.
  - Bind ImGui to it.

- Tooling
  - Integrate dosbox-x.
  - Bind the DTL-H2000 ports to it.

- File operations
  - Get a better generic async file operation system going on.
  - Clean up file operations overall.

- CDRom improvementts
  - Cleanup the tracks system heavily.
  - Add an iso converter.
  - Add an iso hasher / verifier.
  - Add a lookup to redump.org.

- Debugger
  - Add a gdb serial protocol server.

- CPU
  - Support CPU hotswap (interpreted / dynarec)
  - Either make the dynarec generic (using a third party JIT engine), or create x64, arm and ppc versions out of the current x86 one.
  - Properly support exceptions in the interpreted CPU:
    - AdEL
    - AdES
    - IBE
    - DBE
    - RI
    - CpU
    - Ov
   - Add Cop0 debug support.
 
- Integrate [EventBus](https://github.com/gelldur/EventBus)
  - Decouple a lot of the existing classes for the low-hanging fruits such as pause, start, reset, etc.
