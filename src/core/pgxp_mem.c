#include "pgxp_mem.h"
#include "pgxp_cpu.h"
#include "pgxp_gte.h"
#include "pgxp_value.h"

PGXP_value Mem[3 * 2048 * 1024 / 4];  // mirror 2MB in 32-bit words * 3
const u32 UserMemOffset = 0;
const u32 ScratchOffset = 2048 * 1024 / 4;
const u32 RegisterOffset = 2 * 2048 * 1024 / 4;
const u32 InvalidAddress = 3 * 2048 * 1024 / 4;

void PGXP_InitMem() { memset(Mem, 0, sizeof(Mem)); }

void PGXP_Init() {
    PGXP_InitMem();
    PGXP_InitCPU();
    PGXP_InitGTE();
}

char* PGXP_GetMem() {
    return (char*)(Mem);  // Config.PGXP_GTE ? (char*)(Mem) : NULL;
}

/*  Playstation Memory Map (from Playstation doc by Joshua Walker)
0x0000_0000-0x0000_ffff		Kernel (64K)
0x0001_0000-0x001f_ffff		User Memory (1.9 Meg)

0x1f00_0000-0x1f00_ffff		Parallel Port (64K)

0x1f80_0000-0x1f80_03ff		Scratch Pad (1024 bytes)

0x1f80_1000-0x1f80_2fff		Hardware Registers (8K)

0x1fc0_0000-0x1fc7_ffff		BIOS (512K)

0x8000_0000-0x801f_ffff		Kernel and User Memory Mirror (2 Meg) Cached
0x9fc0_0000-0x9fc7_ffff		BIOS Mirror (512K) Cached

0xa000_0000-0xa01f_ffff		Kernel and User Memory Mirror (2 Meg) Uncached
0xbfc0_0000-0xbfc7_ffff		BIOS Mirror (512K) Uncached
*/
void ValidateAddress(u32 addr) {
    int* pi = NULL;

    if ((addr >= 0x00000000) && (addr <= 0x007fffff)) {
    }  // Kernel + User Memory x 8
    else if ((addr >= 0x1f000000) && (addr <= 0x1f00ffff)) {
    }  // Parallel Port
    else if ((addr >= 0x1f800000) && (addr <= 0x1f8003ff)) {
    }  // Scratch Pad
    else if ((addr >= 0x1f801000) && (addr <= 0x1f802fff)) {
    }  // Hardware Registers
    else if ((addr >= 0x1fc00000) && (addr <= 0x1fc7ffff)) {
    }  // Bios
    else if ((addr >= 0x80000000) && (addr <= 0x807fffff)) {
    }  // Kernel + User Memory x 8 Cached mirror
    else if ((addr >= 0x9fc00000) && (addr <= 0x9fc7ffff)) {
    }  // Bios Cached Mirror
    else if ((addr >= 0xa0000000) && (addr <= 0xa07fffff)) {
    }  // Kernel + User Memory x 8 Uncached mirror
    else if ((addr >= 0xbfc00000) && (addr <= 0xbfc7ffff)) {
    }  // Bios Uncached Mirror
    else if (addr == 0xfffe0130) {
    }  // Used for cache flushing
    else {
        //	*pi = 5;
    }
}

u32 PGXP_ConvertAddress(u32 addr) {
    u32 memOffs = 0;
    u32 paddr = addr;

    ValidateAddress(addr);

    switch (paddr >> 24) {
        case 0x80:
        case 0xa0:
        case 0x00:
            // RAM further mirrored over 8MB
            paddr = ((paddr & 0x7FFFFF) % 0x200000) >> 2;
            paddr = UserMemOffset + paddr;
            break;
        default:
            if ((paddr >> 20) == 0x1f8) {
                if (paddr >= 0x1f801000) {
                    //	paddr = ((paddr & 0xFFFF) - 0x1000);
                    //	paddr = (paddr % 0x2000) >> 2;
                    paddr = ((paddr & 0xFFFF) - 0x1000) >> 2;
                    paddr = RegisterOffset + paddr;
                    break;
                } else {
                    // paddr = ((paddr & 0xFFF) % 0x400) >> 2;
                    paddr = (paddr & 0x3FF) >> 2;
                    paddr = ScratchOffset + paddr;
                    break;
                }
            }

            paddr = InvalidAddress;
            break;
    }

#ifdef GTE_LOG
        // GTE_LOG("PGXP_Read %x [%x] |", addr, paddr);
#endif

    return paddr;
}

PGXP_value* GetPtr(u32 addr) {
    addr = PGXP_ConvertAddress(addr);

    if (addr != InvalidAddress) return &Mem[addr];
    return NULL;
}

PGXP_value* ReadMem(u32 addr) { return GetPtr(addr); }

void ValidateAndCopyMem(PGXP_value* dest, u32 addr, u32 value) {
    PGXP_value* pMem = GetPtr(addr);
    if (pMem != NULL) {
        Validate(pMem, value);
        *dest = *pMem;
        return;
    }

    *dest = PGXP_value_invalid_address;
}

void ValidateAndCopyMem16(PGXP_value* dest, u32 addr, u32 value, int sign) {
    u32 validMask = 0;
    psx_value val, mask;
    PGXP_value* pMem = GetPtr(addr);
    if (pMem != NULL) {
        mask.d = val.d = 0;
        // determine if high or low word
        if ((addr % 4) == 2) {
            val.w.h = value;
            mask.w.h = 0xFFFF;
            validMask = VALID_1;
        } else {
            val.w.l = value;
            mask.w.l = 0xFFFF;
            validMask = VALID_0;
        }

        // validate and copy whole value
        MaskValidate(pMem, val.d, mask.d, validMask);
        *dest = *pMem;

        // if high word then shift
        if ((addr % 4) == 2) {
            dest->x = dest->y;
            dest->lFlags = dest->hFlags;
            dest->compFlags[0] = dest->compFlags[1];
        }

        // truncate value
        dest->y = (dest->x < 0) ? -1.f * sign : 0.f;  // 0.f;
        dest->hFlags = 0;
        dest->value = value;
        dest->compFlags[1] = VALID;  // iCB: High word is valid, just 0
        return;
    }

    *dest = PGXP_value_invalid_address;
}

void WriteMem(PGXP_value* value, u32 addr) {
    PGXP_value* pMem = GetPtr(addr);

    if (pMem) *pMem = *value;
}

void WriteMem16(PGXP_value* src, u32 addr) {
    PGXP_value* dest = GetPtr(addr);
    psx_value* pVal = NULL;

    if (dest) {
        pVal = &dest->value;
        // determine if high or low word
        if ((addr % 4) == 2) {
            dest->y = src->x;
            dest->hFlags = src->lFlags;
            dest->compFlags[1] = src->compFlags[0];
            pVal->w.h = (u16)src->value;
        } else {
            dest->x = src->x;
            dest->lFlags = src->lFlags;
            dest->compFlags[0] = src->compFlags[0];
            pVal->w.l = (u16)src->value;
        }

        // overwrite z/w if valid
        if (src->compFlags[2] == VALID) {
            dest->z = src->z;
            dest->compFlags[2] = src->compFlags[2];
        }

        // dest->valid = dest->valid && src->valid;
        dest->gFlags |= src->gFlags;  // inherit flags from both values (?)
    }
}
