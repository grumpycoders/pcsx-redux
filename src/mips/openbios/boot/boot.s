.include "hwregs.inc"

    .section .boot,"ax",@progbits
    .align 2
    .global _reset
    .type _reset, @function

_reset:
    // set bios memory bus width and speed
    li    $t0, (0x13 << 16) | 0x243f
    sw    $t0, SBUS_DEV2_CTRL

    // this may be here to let the hardware pick up the new bus settings
    // before moving on with the actual code.
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

