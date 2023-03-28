# Memory and registers
The Lua code can access the emulated memory and registers directly through some FFI bindings:

- `PCSX.getMemPtr()` will return a `cdata[uint8_t*]` representing up to 8MB of emulated memory. This can be written to, but careful about the emulated i-cache in case code is being written to.
- `PCSX.getParPtr()` will return a `cdata[uint8_t*]` representing up to 512kB of the EXP1/Parallel port memory space. This can be written to.
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
