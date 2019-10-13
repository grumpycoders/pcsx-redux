/*
# _____     ___   __      ___ ____
#  ____|   |        |    |        | |____|
# |     ___|     ___| ___|    ____| |    \
#-----------------------------------------------------------------------
#
# "exec.h" for PS1.
#
*/

#ifndef _EXEC_H
#define _EXEC_H

#ifdef __cplusplus
extern "C" {
#endif

/* Executable file types returned by LoadEx() */
enum { ExecTypeUNK = 0, ExecTypePSX = 1, ExecTypeSCE = 2, ExecTypeECO = 3, ExecTypeCPE = 4 };

// sizeof() == 0x3C(60)
typedef struct st_ExecInfo {
    uint32_t entry;       // 0x00 : Address of program entry-point.
    uint32_t init_gp;     // 0x04 : SCE only.  Initial value the "gp" register is set to.  0 for PS-X EXE.
    uint32_t text_addr;   // 0x08 : Memory address to which the .text section is loaded.
    uint32_t text_size;   // 0x0C : Size of the .text section in the file and memory.
    uint32_t data_addr;   // 0x10 : SCE only.  Memory address to which the .data section is loaded.  0 for PS-X EXE.
    uint32_t data_size;   // 0x14 : SCE only.  Size of the .data section in the file and memory.  0 for PS-X EXE.
    uint32_t bss_addr;    // 0x18 : Memory address of the .bss section.  .bss is initialized by Exec().
    uint32_t bss_size;    // 0x1C : Size of the .bss section in memory.
    uint32_t stack_addr;  // 0x20 : Memory address pointing to the bottom(lowest address) of the stack. BIOS replaces
                          // with "STACK" parameter of "SYSTEM.CNF" file.
    uint32_t stack_size;  // 0x24 : Size of the stack.  Can be 0.
    uint32_t saved_sp;    // 0x28 : Used by BIOS Exec() function to preserve the "sp" register.
    uint32_t saved_fp;    // 0x2C : Used by BIOS Exec() function to preserve the "fp" register.
    uint32_t saved_gp;    // 0x30 : Used by BIOS Exec() function to preserve the "gp" register.
    uint32_t saved_ra;    // 0x34 : Used by BIOS Exec() function to preserve the "ra" register.
    uint32_t saved_s0;    // 0x38 : Used by BIOS Exec() function to preserve the "s0" register.
} ExecInfo;

// sizeof() == 0x88(136)
typedef struct st_EXE_Header {
    uint8_t magic[8];         // 0x00-0x07 : "PS-X EXE"(retail) or "SCE EXE"(???)
    uint32_t text_off;        // 0x08 : SCE only.  Offset of the start of the .text section in the file. 0 for PS-X EXE.
    uint32_t data_off;        // 0x0C : SCE only.  Offset of the start of the .text section in the file. 0 for PS-X EXE.
    struct st_ExecInfo exec;  // 0x10-0x4B
    char license[60];         // 0x4C-0x87
    uint8_t __pad[1912];      // 0x88-0x7FF
} EXE_Header;

int Exec2(ExecInfo* exec, uint32_t arg0, uint32_t arg1);

#ifdef __cplusplus
}
#endif

#endif /* _EXEC_H */
