#define C0_BPC      $3
#define C0_BDA      $5
#define C0_DCIC     $7
#define C0_BADVADDR $8
#define C0_BDAM     $9
#define C0_BPCM     $11
#define C0_STATUS   $12
#define C0_CAUSE    $13
#define C0_EPC      $14
#define C0_PRID     $15

// set a breakpoint on data access
// addr: The address to trigger on.
// addr_mask: The mask used when comparing addresses.
// ctrl - bitmask of access types to trigger on.
//  C0_DCIC_DR: Data Read
//  C0_DCIC_DW: Data Write
void dbg_set_bpda(uint32_t addr, uint32_t addr_mask, uint32_t ctrl)
{
    register uint32_t cur_DCIC;

    cur_dcic = C0_get_DCIC(); // get the current value of DCIC
    C0_set_DCIC(0); // set DCIC to 0 temporarily to ensure all breakpoints are disabled.

    C0_set_BDA(addr & addr_mask); // set BDA with the address on which to set the breakpoint.
    C0_set_BDAM(addr_mask); // set BDAM with the address mask used to determine which bits to compare in the address.
    
    cur_DCIC &= ~(C0_DCIC_DR | C0_DCIC_DW); // clear the Data Read and Data Write bits. 

    cur_DCIC |= (C0_DCIC_TR | C0_DCIC_DAE | C0_DCIC_DE); // set the "Trap", "Data Access" and "Debug" enable bits.
    cur_DCIC |= ctrl & (C0_DCIC_DR | C0_DCIC_DW);
    C0_set_DCIC(cur_DCIC);    
}

// set a breakpoint on program counter
// addr: The address to trigger on.
// addr_mask: The mask used when comparing addresses.
void dbg_set_bppc(uint32_t addr, uint32_t addr_mask)
{
    register uint32_t cur_DCIC;

    cur_dcic = C0_get_DCIC(); // get the current value of DCIC
    C0_set_DCIC(0); // set DCIC to 0 temporarily to ensure all breakpoints are disabled.

    C0_set_BPC(addr & addr_mask); // set BDA with the address on which to set the breakpoint.
    C0_set_BPCM(addr_mask); // set BDAM with the address mask used to determine which bits to compare in the address.
    
    cur_DCIC |= (C0_DCIC_TR | C0_DCIC_PCE | C0_DCIC_DE); // set the "Trap", "Program Counter" and "Debug" enable bits.
    cur_DCIC |= C0_DCIC_DR;
    C0_set_DCIC(cur_DCIC);    
}

