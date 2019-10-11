.set push
.set noreorder
.set noat

#include <mipsregs.h>

.text

// sizeof() == 0x3C(60)
#define ExecInfo_entry 0x00 // Address of program entry-point.
#define ExecInfo_init_gp 0x04 // SCE only.  Initial value the "gp" register is set to.  0 for PS-X EXE.
#define ExecInfo_text_addr 0x08 // Memory address to which the .text section is loaded.
#define ExecInfo_text_size 0x0C // Size of the .text section in the file and memory.
#define ExecInfo_data_addr 0x10 // SCE only.  Memory address to which the .data section is loaded.  0 for PS-X EXE.
#define ExecInfo_data_size 0x14 // SCE only.  Size of the .data section in the file and memory.  0 for PS-X EXE.
#define ExecInfo_bss_addr 0x18 // Memory address of the .bss section.  .bss is initialized by Exec().
#define ExecInfo_bss_size 0x1C // Size of the .bss section in memory.
#define ExecInfo_stack_addr 0x20 // Memory address pointing to the bottom(lowest address) of the stack. BIOS replaces
                          // with "STACK" parameter of "SYSTEM.CNF" file.
#define ExecInfo_stack_size 0x24 // Size of the stack.  Can be 0.
#define ExecInfo_saved_sp 0x28 // Used by BIOS Exec() function to preserve the "sp" register.
#define ExecInfo_saved_fp 0x2C // Used by BIOS Exec() function to preserve the "fp" register.
#define ExecInfo_saved_gp 0x30 // Used by BIOS Exec() function to preserve the "gp" register.
#define ExecInfo_saved_ra 0x34 // Used by BIOS Exec() function to preserve the "ra" register.
#define ExecInfo_saved_s0 0x38 // Used by BIOS Exec() function to preserve the "s0" register.

.global Exec2
.type Exec2, @function
.ent Exec2
Exec2:        
                    sw      s0, ExecInfo_saved_s0(a0)
                    or      s0, zero, a0
                    sw      ra, ExecInfo_saved_ra(s0)
                    sw      sp, ExecInfo_saved_sp(s0)
                    sw      fp, ExecInfo_saved_fp(s0)
                    lw      t0, ExecInfo_bss_size(s0)
                    sw      gp, ExecInfo_saved_gp(s0)

                    beqz    t0, _no_bss

                    lw      t1, ExecInfo_bss_addr(s0)
                    nop
_bss_clear_loop:                         
                    addiu   t0, t0, -4
                    sw      zero, 0(t1)
                    bgtz    t0, _bss_clear_loop
                    addiu   t1, t1, 4

_no_bss:                                 
                    lw      t0, ExecInfo_stack_addr(s0)
                    nop
                    beqz    t0, _no_stack
                    nop

                    lw      t1, ExecInfo_stack_size(s0)
                    nop
                    add     t0, t1
                    move    sp, t0
                    move    fp, sp


_no_stack:                               
                    lw      t3, ExecInfo_entry(s0)
                    lw      gp, ExecInfo_init_gp(s0)
                    move    a0, a1
                    jalr    t3
                    move    a1, a2

                    lw      ra, ExecInfo_saved_ra(s0)
                    lw      sp, ExecInfo_saved_sp(s0)
                    lw      fp, ExecInfo_saved_fp(s0)
                    lw      gp, ExecInfo_saved_gp(s0)
                    lw      s0, ExecInfo_saved_s0(s0)
                    jr      ra
                    li      v0, 1
.end Exec2
