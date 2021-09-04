# Mips API

## Description

Pcsx-redux has a special API that mips binaries can use : 

```cpp
static __inline__ void pcsx_putc(int c) { *((volatile char* const)0x1f802080) = c; }
static __inline__ void pcsx_debugbreak() { *((volatile char* const)0x1f802081) = 0; }
static __inline__ void pcsx_exit(int code) { *((volatile int16_t* const)0x1f802082) = code; }
static __inline__ void pcsx_message(const char* msg) { *((volatile char* const)0x1f802084) = msg; }

static __inline__ int pcsx_present() { return *((volatile uint32_t* const)0x1f802080) == 0x58534350; }
```
Source : [https://github.com/grumpycoders/pcsx-redux/blob/main/src/mips/common/hardware/pcsxhw.h#L31-L36](https://github.com/grumpycoders/pcsx-redux/blob/main/src/mips/common/hardware/pcsxhw.h#L31-L36)

The API needs [DEV8/EXP2](https://psx-spx.consoledev.net/expansionportpio/#exp2-post-registers) (1f802000 to 1f80207f), which holds the hardware register for the bios POST status, to be expanded to 1f8020ff.  
Thus the need to use a custom `crt0.s` if you plan on running your code on real hardware.  
The default file provided with the [Nugget+PsyQ](https://github.com/pcsx-redux/nugget) development environment does that:  

```nasm
_start:
    lw    $t2, SBUS_DEV8_CTRL
    lui   $t0, 8
    lui   $t1, 1
_check_dev8:
    bge   $t2, $t0, _store_dev8
    nop
    b     _check_dev8
    add   $t2, $t1
_store_dev8:
    sw    $t2, SBUS_DEV8_CTRL
```
Source : [https://github.com/grumpycoders/pcsx-redux/blob/main/src/mips/common/crt0/crt0.s#L36-L46](https://github.com/grumpycoders/pcsx-redux/blob/main/src/mips/common/crt0/crt0.s#L36-L46)

## Functions

The following functions are available :

| Function | Usage |
| :- | :- | 
|`pcsx_putc(int c)` | Print ASCII character with code `c` to console/stdout. | 
|`pcsx_debugbreak()` | Break execution ( Pause emulation ). | 
|`pcsx_exit(int code)` | Exit emulator and forward `code` as exit code. | 
|`pcsx_message(const char* msg)` | Create a UI dialog displaying `msg` | 
|`pcsx_present()` | Returns 1 if code is running in pcsx-redux |

Example of a UI dialog created with `pcsx_message()` :  

![pcsx_message() in action](./images/pcsx_message.png)
