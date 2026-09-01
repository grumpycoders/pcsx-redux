List of things to still do here, in no particular order.

- GPU
  - Re-add iCatbutler's PGXP stuff.
  - Properly integrate IRQ control.

- SPU cleanup
  - Properly support CDDA/XA volume settings.
  - Reduce latency.
  - Fix XA decoding.
  - Properly integrate IRQ control.

- Memory mapper
  - Properly support RAM_SIZE hardware register to dynamically resize the machine's memory.
  - Support the DTL-H2x00 secondary BIOS SRAM region.

- Scripting
  - Bind more emulator functions to Lua.
  - Bind parallel port card system to it, so to have a flexible cart management system.

- Tooling
  - Integrate dosbox-x.
  - Bind the DTL-H2x00 ports to it.

- CDRom improvementts
  - Add an iso converter.
  - Add a lookup to redump.org.

- CPU
  - Support CPU hotswap (interpreted / dynarec)
  - Either make the dynarec generic (using a third party JIT engine), or create arm and ppc versions out of the current x86-64 one.
 
- EventBus
  - Decouple a lot of the existing classes for the low-hanging fruits such as pause, start, reset, etc.

- Visualizers
  - Add a memory read / write / exec timestamp visualizer, ala ICU64.
