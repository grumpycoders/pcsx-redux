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
