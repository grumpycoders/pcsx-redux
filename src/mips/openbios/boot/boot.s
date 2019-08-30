    .section .boot,"ax",@progbits
    .align 2
    .global _reset
    .type _reset, @function
_reset:
    li    $t0, (0x13 << 16) | 0x243f
    sw    $t0, 0x1f801010
