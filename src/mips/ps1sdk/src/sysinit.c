typedef struct ROMCallTable_st
{
    void (*SysInitKMem)(void);
    void (*CopyKCallA0Table)(void);
    void (*InstallInterruptDispatch)(void);
    int (*alloc_something)(int count);
    int (*SetEventConfig)(uint32_t evcb);
    int (*SetTCBConfig)(uint32_t tcb);
    void (*_96_init)(void);
    int (*ValidatePIOShell)(void);
    void (*ParseSetupFile)(void *raw_cnf, SystemConf *cfg, char *bootFileName);
    void (*KernelSetup)(void);
    // NOTE: This points to the STUB for the Exec kcall. NOT the "Exec" function itself.
    int (*stub_Exec)(ExecInfo* exec, uint32_t stack_addr, uint32_t stack_size);
    SystemConf *config;
    void (*init_some_events)(void);
} ROMCallTable;

void SystemInit(int rem96)
{

}
.text:00000028                 lhu     date_code, 0xBFC00102
.text:00000030                 li      $v1, 8
.text:00000034                 andi    date_code, 0xFFFF
.text:00000038                 move    x, $zero
.text:0000003C
.text:0000003C _l1:                                     # CODE XREF: SystemInit+54↓j
.text:0000003C                 sll     $a1, x, 1        # a1 = i * 2
.text:00000040                 sll     x, 3             # x *= 8
.text:00000044                 srl     $a0, date_code, 28
.text:00000048                 addu    x, $a1, x
.text:0000004C                 addiu   $v1, -1
.text:00000050                 addu    x, $a0, x
.text:00000054                 bnez    $v1, _l1
.text:00000058                 sll     date_code, 4
