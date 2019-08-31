.include "hwregs.inc"

    .section .boot, "ax", @progbits
    .align 2
    .global _reset
    .type _reset, @function

_reset:
    // set bios memory bus width and speed.
    li    $t0, (19 << 16) | 0x243f
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

    // jumping over the interrupt vector.
    j     _boot


    .section .text, "ax", @progbits
    .align 2
    .global _boot
    .type _boot, @function

_boot:
    // initializing all of the buses now
    li    $t0, 0x31125
    sw    $t0, SBUS_COM_CTRL

    li    $t0, 0x1f000000
    sw    $t0, SBUS_DEV0_ADDR

    li    $t0, 0x1f802000
    sw    $t0, SBUS_DEV8_ADDR

    li    $t0, (19 << 16) | 0x243f
    sw    $t0, SBUS_DEV0_CTRL

    li    $t0, 0x200931e1
    sw    $t0, SBUS_DEV4_CTRL

    li    $t0, 0x20843
    sw    $t0, SBUS_DEV5_CTRL

    li    $t0, 0x3022
    sw    $t0, SBUS_DEV1_CTRL

    li    $t0, 0x70777
    sw    $t0, SBUS_DEV8_CTRL

    // clearing out all registers
    move  $1, $0
    move  $2, $0
    move  $3, $0
    move  $4, $0
    move  $5, $0
    move  $6, $0
    move  $7, $0
    move  $8, $0
    move  $9, $0
    move  $10, $0
    move  $11, $0
    move  $12, $0
    move  $13, $0
    move  $14, $0
    move  $15, $0
    move  $16, $0
    move  $17, $0
    move  $18, $0
    move  $19, $0
    move  $20, $0
    move  $21, $0
    move  $22, $0
    move  $23, $0
    move  $24, $0
    move  $25, $0
    move  $26, $0
    move  $27, $0
    move  $28, $0
    move  $29, $0
    move  $30, $0
    move  $31, $0

    // initializing cache
    li    $t0, 0x804
    sw    $t0, CACHE_CTRL

    li    $t1, 0x10000
    mtc0  $t1, $12
    nop
    nop

    move  $t0, $0
    li    $t2, 0x1000

cache_init_1:
    sw    $0, 0x00($t0)
    sw    $0, 0x10($t0)
    sw    $0, 0x20($t0)
    sw    $0, 0x30($t0)
    sw    $0, 0x40($t0)
    sw    $0, 0x50($t0)
    sw    $0, 0x60($t0)
    sw    $0, 0x70($t0)
    addi  $t0, 0x80
    bne   $t0, $t2, cache_init_1

    mtc0  $0, $12
    nop

    li    $t0, 0x800
    sw    $t0, CACHE_CTRL

    mtc0  $t1, $12
    nop
    nop

    move  $t0, $0
    li    $t2, 0x1000

cache_init_2:
    sw    $0, 0x00($t0)
    sw    $0, 0x04($t0)
    sw    $0, 0x08($t0)
    sw    $0, 0x0c($t0)
    sw    $0, 0x10($t0)
    sw    $0, 0x14($t0)
    sw    $0, 0x18($t0)
    sw    $0, 0x1c($t0)
    sw    $0, 0x20($t0)
    sw    $0, 0x24($t0)
    sw    $0, 0x28($t0)
    sw    $0, 0x2c($t0)
    sw    $0, 0x30($t0)
    sw    $0, 0x34($t0)
    sw    $0, 0x38($t0)
    sw    $0, 0x3c($t0)
    sw    $0, 0x40($t0)
    sw    $0, 0x44($t0)
    sw    $0, 0x48($t0)
    sw    $0, 0x4c($t0)
    sw    $0, 0x50($t0)
    sw    $0, 0x54($t0)
    sw    $0, 0x58($t0)
    sw    $0, 0x5c($t0)
    sw    $0, 0x60($t0)
    sw    $0, 0x64($t0)
    sw    $0, 0x68($t0)
    sw    $0, 0x6c($t0)
    sw    $0, 0x70($t0)
    sw    $0, 0x74($t0)
    sw    $0, 0x78($t0)
    sw    $0, 0x7c($t0)
    addi  $t0, 0x80
    bne   $t0, $t2, cache_init_2

    mtc0  $0, $12
    nop

    li    $t0, 0xa0000000
    lw    $t1, 0($t0)
    lw    $t1, 0($t0)
    lw    $t1, 0($t0)
    lw    $t1, 0($t0)
    lw    $t1, 0($t0)
    lw    $t1, 0($t0)
    lw    $t1, 0($t0)
    lw    $t1, 0($t0)
    nop

    li    $t0, 0x1e988
    sw    $t0, CACHE_CTRL

    // ensuring cop0 is fully reset
    mtc0  $0, $7
    nop
    mtc0  $0, $3
    nop
    mtc0  $0, $5
    nop
    mtc0  $0, $6
    nop
    mtc0  $0, $9
    nop
    mtc0  $0, $11
    nop
    mtc0  $0, $12
    nop
    mtc0  $0, $13
    nop

    // now we are ready for a typical crt0
    la    $t0, __data_start
    la    $t1, __data_end
    la    $t2, __rom_data_start

    beq   $t0, $t1, data_copy_skip

data_copy:
    lw    $t3, 0($t0)
    sw    $t3, 0($t2)
    addiu $t0, 4
    addiu $t2, 4
    bne   $t0, $t1, data_copy

data_copy_skip:
    la    $t0, __bss_start
    la    $t1, __bss_end

    beq   $t0, $t1, bss_init_skip

bss_init:
    sw    $0, 0($t0)
    addiu $t0, 4
    bne   $t0, $t1, bss_init

bss_init_skip:

    // technically have to set $gp, but we are not using it, so, not
    la    $sp, __sp
    move  $fp, $sp

    li    $t0, 0xb88
    sw    $t0, RAM_SIZE

    jal   main

stop:
    b     stop
