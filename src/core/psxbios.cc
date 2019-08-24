/***************************************************************************
 *   Copyright (C) 2007 Ryan Schultz, PCSX-df Team, PCSX team              *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

/*
 * Internal simulated HLE BIOS.
 */

#include "core/psxbios.h"
#include "core/gpu.h"
#include "core/misc.h"
#include "core/pad.h"
#include "core/psxhw.h"

// clang-format off
static const char *A0names[] = {
    "open",    "lseek",    "read",    "write",      // 00
    "close",   "ioctl",    "exit",    "sys_a0_07",  // 04
    "getc",    "putc",     "todigit", "atof",       // 08
    "strtoul", "strtol",   "abs",     "labs"        // 0c
    "atoi",    "atol",     "atob",    "setjmp",     // 10
    "longjmp", "strcat",   "strncat", "strcmp",     // 14
    "strncmp", "strcpy",   "strncpy", "strlen",     // 18
    "index",   "rindex",   "strchr",  "strrchr"     // 1c
    "strpbrk", "strspn",   "strcspn", "strtok",     // 20
    "strstr",  "toupper",  "tolower", "bcopy",      // 24
    "bzero",   "bcmp",     "memcpy",  "memset",     // 28
    "memmove", "memcmp",   "memchr",  "rand",       // 2c
    "srand",   "qsort",    "strtod",  "malloc",     // 30
    "free",    "lsearch",  "bsearch", "calloc",     // 34
    "realloc", "InitHeap", "_exit",   "getchar",    // 38
    "putchar", "gets",     "puts",    "printf",     // 3c

    "sys_a0_40",         "LoadTest",                "Load",              "Exec",             // 40
    "FlushCache",        "InstallInterruptHandler", "GPU_dw",            "mem2vram",         // 44
    "SendGPUStatus",     "GPU_cw",                  "GPU_cwb",           "SendPackets",      // 48
    "sys_a0_4c",         "GetGPUStatus",            "GPU_sync",          "sys_a0_4f",        // 4c
    "sys_a0_50",         "LoadExec",                "GetSysSp",          "sys_a0_53",        // 50
    "_96_init()",        "_bu_init()",              "_96_remove()",      "sys_a0_57",        // 54
    "sys_a0_58",         "sys_a0_59",               "sys_a0_5a",         "dev_tty_init",     // 58
    "dev_tty_open",      "sys_a0_5d",               "dev_tty_ioctl",     "dev_cd_open",      // 5c
    "dev_cd_read",       "dev_cd_close",            "dev_cd_firstfile",  "dev_cd_nextfile",  // 60
    "dev_cd_chdir",      "dev_card_open",           "dev_card_read",     "dev_card_write",   // 64
    "dev_card_close",    "dev_card_firstfile",      "dev_card_nextfile", "dev_card_erase",   // 68
    "dev_card_undelete", "dev_card_format",         "dev_card_rename",   "dev_card_6f",      // 6c

    "_bu_init",          "_96_init",   "_96_remove",     "sys_a0_73",         // 70
    "sys_a0_74",         "sys_a0_75",  "sys_a0_76",      "sys_a0_77",         // 74
    "_96_CdSeekL",       "sys_a0_79",  "sys_a0_7a",      "sys_a0_7b",         // 78
    "_96_CdGetStatus",   "sys_a0_7d",  "_96_CdRead",     "sys_a0_7f",         // 7c
    "sys_a0_80",         "sys_a0_81",  "sys_a0_82",      "sys_a0_83",         // 80
    "sys_a0_84",         "_96_CdStop", "sys_a0_86",      "sys_a0_87",         // 84
    "sys_a0_88",         "sys_a0_89",  "sys_a0_8a",      "sys_a0_8b",         // 88
    "sys_a0_8c",         "sys_a0_8d",  "sys_a0_8e",      "sys_a0_8f",         // 8c
    "sys_a0_90",         "sys_a0_91",  "sys_a0_92",      "sys_a0_93",         // 90
    "sys_a0_94",         "sys_a0_95",  "AddCDROMDevice", "AddMemCardDevide",  // 94

    "DisableKernelIORedirection", "EnableKernelIORedirection", "sys_a0_9a",     "sys_a0_9b",      // 98
    "SetConf",                    "GetConf",                   "sys_a0_9e",     "SetMem",         // 9c
    "_boot",                      "SystemError",               "EnqueueCdIntr", "DequeueCdIntr",  // a0
    "sys_a0_a4",                  "ReadSector",                "get_cd_status", "bufs_cb_0",      // a4
    "bufs_cb_1",                  "bufs_cb_2",                 "bufs_cb_3",     "_card_info",     // a8
    "_card_load",                 "_card_auto",                "bufs_cd_4",     "sys_a0_af",      // ac
    "sys_a0_b0",                  "sys_a0_b1",                 "do_a_long_jmp", "sys_a0_b3",      // b0
};

static const char *B0names[] = {
    "SysMalloc",      "sys_b0_01",             "sys_b0_02",   "sys_b0_03",            // 00
    "sys_b0_04",      "sys_b0_05",             "sys_b0_06",   "DeliverEvent",         // 04
    "OpenEvent",      "CloseEvent",            "WaitEvent",   "TestEvent",            // 08
    "EnableEvent",    "DisableEvent",          "OpenTh",      "CloseTh",              // 0c
    "ChangeTh",       "sys_b0_11",             "InitPAD",     "StartPAD",             // 10
    "StopPAD",        "PAD_init",              "PAD_dr",      "ReturnFromException",  // 14
    "ResetEntryInt",  "HookEntryInt",          "sys_b0_1a",   "sys_b0_1b",            // 18
    "sys_b0_1c",      "sys_b0_1d",             "sys_b0_1e",   "sys_b0_1f",            // 1c
    "UnDeliverEvent", "sys_b0_21",             "sys_b0_22",   "sys_b0_23",            // 20
    "sys_b0_24",      "sys_b0_25",             "sys_b0_26",   "sys_b0_27",            // 24
    "sys_b0_28",      "sys_b0_29",             "sys_b0_2a",   "sys_b0_2b",            // 28
    "sys_b0_2c",      "sys_b0_2d",             "sys_b0_2e",   "sys_b0_2f",            // 2c
    "sys_b0_30",      "sys_b0_31",             "open",        "lseek",                // 30
    "read",           "write",                 "close",       "ioctl",                // 30
    "exit",           "sys_b0_39",             "getc",        "putc",                 // 30
    "getchar",        "putchar",               "gets",        "puts",                 // 3c
    "cd",             "format",                "firstfile",   "nextfile",             // 40
    "rename",         "delete",                "undelete",    "AddDevice",            // 40
    "RemoteDevice",   "PrintInstalledDevices", "InitCARD",    "StartCARD",            // 40
    "StopCARD",       "sys_b0_4d",             "_card_write", "_card_read",           // 4c
    "_new_card",      "Krom2RawAdd",           "sys_b0_52",   "sys_b0_53",            // 50
    "_get_errno",     "_get_error",            "GetC0Table",  "GetB0Table",           // 50
    "_card_chan",     "sys_b0_59",             "sys_b0_5a",   "ChangeClearPAD",       // 50
    "_card_status",   "_card_wait"                                                    // 5c
};
// clang-format on

static const char *C0names[] = {
    "InitRCnt",           "InitException",     "SysEnqIntRP",      "SysDeqIntRP",             // 00
    "get_free_EvCB_slot", "get_free_TCB_slot", "ExceptionHandler", "InstallExeptionHandler",  // 04
    "SysInitMemory",      "SysInitKMem",       "ChangeClearRCnt",  "SystemError",             // 08
    "InitDefInt",         "sys_c0_0d",         "sys_c0_0e",        "sys_c0_0f",               // 0c
    "sys_c0_10",          "sys_c0_11",         "InstallDevices",   "FlushStfInOutPut",        // 10
    "sys_c0_14",          "_cdevinput",        "_cdevscan",        "_circgetc",               // 14
    "_circputc",          "ioabort",           "sys_c0_1a",        "KernelRedirect",          // 18
    "PatchAOTable",       "GetDeviceStatus"                                                   // 1c
};

const char *PCSX::Bios::getA0name(uint8_t call) {
    unsigned count = sizeof(A0names) / sizeof(A0names[0]);
    if (call < count) {
        return A0names[call];
    } else {
        return nullptr;
    }
}
const char *PCSX::Bios::getB0name(uint8_t call) {
    unsigned count = sizeof(B0names) / sizeof(B0names[0]);
    if (call < count) {
        return B0names[call];
    } else {
        return nullptr;
    }
}
const char *PCSX::Bios::getC0name(uint8_t call) {
    unsigned count = sizeof(C0names) / sizeof(C0names[0]);
    if (call < count) {
        return C0names[call];
    } else {
        return nullptr;
    }
}

//#define r0 (PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.r0)
#define at (PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.at)
#define v0 (PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.v0)
#define v1 (PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.v1)
#define a0 (PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.a0)
#define a1 (PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.a1)
#define a2 (PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.a2)
#define a3 (PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.a3)
#define t0 (PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.t0)
#define t1 (PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.t1)
#define t2 (PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.t2)
#define t3 (PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.t3)
#define t4 (PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.t4)
#define t5 (PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.t5)
#define t6 (PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.t6)
#define t7 (PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.t7)
#define t8 (PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.t8)
#define t9 (PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.t9)
#define s0 (PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.s0)
#define s1 (PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.s1)
#define s2 (PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.s2)
#define s3 (PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.s3)
#define s4 (PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.s4)
#define s5 (PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.s5)
#define s6 (PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.s6)
#define s7 (PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.s7)
#define k0 (PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.k0)
#define k1 (PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.k1)
#define gp (PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.gp)
#define sp (PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.sp)
#define fp (PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.s8)
#define ra (PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.ra)
#define pc0 (PCSX::g_emulator.m_psxCpu->m_psxRegs.pc)

#define Ra0 (assert(PSXM(a0) != NULL), (char *)PSXM(a0))
#define Ra1 (assert(PSXM(a1) != NULL), (char *)PSXM(a1))
#define Ra2 (assert(PSXM(a2) != NULL), (char *)PSXM(a2))
#define Ra3 (assert(PSXM(a3) != NULL), (char *)PSXM(a3))
#define Rv0 (assert(PSXM(v0) != NULL), (char *)PSXM(v0))
#define Rsp (assert(PSXM(sp) != NULL), (char *)PSXM(sp))

class BiosImpl : public PCSX::Bios {
    typedef struct {
        uint32_t desc;
        int32_t status;
        int32_t mode;
        uint32_t fhandler;
    } EvCB[32];

    enum {
        EvStUNUSED = 0x0000,
        EvStWAIT = 0x1000,
        EvStACTIVE = 0x2000,
        EvStALREADY = 0x4000,

        EvMdINTR = 0x1000,
        EvMdNOINTR = 0x2000,
    };

    typedef struct {
        int32_t next;
        int32_t func1;
        int32_t func2;
        int32_t pad;
    } SysRPst;

    typedef struct {
        int32_t status;
        int32_t mode;
        uint32_t reg[32];
        uint32_t func;
    } TCB;

    typedef struct {
        uint32_t _pc0;
        uint32_t gp0;
        uint32_t t_addr;
        uint32_t t_size;
        uint32_t d_addr;
        uint32_t d_size;
        uint32_t b_addr;
        uint32_t b_size;
        uint32_t S_addr;
        uint32_t s_size;
        uint32_t _sp, _fp, _gp, ret, base;
    } EXEC;

    struct DIRENTRY {
        char name[20];
        int32_t attr;
        int32_t size;
        uint32_t next;
        int32_t head;
        char system[4];
    };

    typedef struct {
        char name[32];
        uint32_t mode;
        uint32_t offset;
        uint32_t size;
        uint32_t mcfile;
    } FileDesc;

    uint32_t *s_jmp_int = NULL;
    int *s_pad_buf = NULL;
    char *s_pad_buf1 = NULL, *s_pad_buf2 = NULL;
    int s_pad_buf1len, s_pad_buf2len;

    uint32_t s_regs[35];
    EvCB *s_Event;
    EvCB *s_HwEV;  // 0xf0
    EvCB *s_EvEV;  // 0xf1
    EvCB *s_RcEV;  // 0xf2
    EvCB *s_UeEV;  // 0xf3
    EvCB *s_SwEV;  // 0xf4
    EvCB *s_ThEV;  // 0xff
    uint32_t *s_heap_addr = NULL;
    uint32_t *s_heap_end = NULL;
    uint32_t s_SysIntRP[8];
    int s_CardState = -1;
    TCB s_Thread[8];
    int s_CurThread = 0;
    FileDesc s_FDesc[32];
    uint32_t s_card_active_chan = 0;

    bool m_hleSoftCall = false;

    inline void softCall(uint32_t pc) {
        pc0 = pc;
        ra = 0;

        m_hleSoftCall = true;

        while (pc0 != 0) PCSX::g_emulator.m_psxCpu->ExecuteHLEBlock();

        m_hleSoftCall = false;
    }

    inline void softCall2(uint32_t pc) {
        uint32_t sra = ra;
        pc0 = pc;
        ra = 0;

        m_hleSoftCall = true;

        while (pc0 != 0) PCSX::g_emulator.m_psxCpu->ExecuteHLEBlock();
        ra = sra;

        m_hleSoftCall = false;
    }

    inline void DeliverEvent(uint32_t ev, uint32_t spec) {
        if (s_Event[ev][spec].status != EvStACTIVE) return;

        //  s_Event[ev][spec].status = EvStALREADY;
        if (s_Event[ev][spec].mode == EvMdINTR) {
            softCall2(s_Event[ev][spec].fhandler);
        } else
            s_Event[ev][spec].status = EvStALREADY;
    }

    inline void SaveRegs() {
        memcpy(s_regs, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r, 32 * 4);
        s_regs[32] = PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.lo;
        s_regs[33] = PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.hi;
        s_regs[34] = PCSX::g_emulator.m_psxCpu->m_psxRegs.pc;
    }

    inline void LoadRegs() {
        memcpy(PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r, s_regs, 32 * 4);
        PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.lo = s_regs[32];
        PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.hi = s_regs[33];
    }

    /*                                           *
    //                                           *
    //                                           *
    //               System calls A0             */

    void psxBios_abs() {  // 0x0e
        if ((int32_t)a0 < 0)
            v0 = -(int32_t)a0;
        else
            v0 = a0;
        pc0 = ra;
    }

    void psxBios_labs() {  // 0x0f
        psxBios_abs();
    }

    void psxBios_atoi() {  // 0x10
        int32_t n = 0, f = 0;
        char *p = (char *)Ra0;

        for (;; p++) {
            switch (*p) {
                case ' ':
                case '\t':
                    continue;
                case '-':
                    f++;
                case '+':
                    p++;
            }
            break;
        }

        while (*p >= '0' && *p <= '9') {
            n = n * 10 + *p++ - '0';
        }

        v0 = (f ? -n : n);
        pc0 = ra;
    }

    void psxBios_atol() {  // 0x11
        psxBios_atoi();
    }

    void psxBios_setjmp() {  // 0x13
        uint32_t *jmp_buf = (uint32_t *)Ra0;
        int i;

        PSXBIOS_LOG("psxBios_%s\n", A0names[0x13]);

        jmp_buf[0] = ra;
        jmp_buf[1] = sp;
        jmp_buf[2] = fp;
        for (i = 0; i < 8; i++)  // s0-s7
            jmp_buf[3 + i] = PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[16 + i];
        jmp_buf[11] = gp;

        v0 = 0;
        pc0 = ra;
    }

    void psxBios_longjmp() {  // 0x14
        uint32_t *jmp_buf = (uint32_t *)Ra0;
        int i;

        PSXBIOS_LOG("psxBios_%s\n", A0names[0x14]);

        ra = jmp_buf[0];         /* ra */
        sp = jmp_buf[1];         /* sp */
        fp = jmp_buf[2];         /* fp */
        for (i = 0; i < 8; i++)  // s0-s7
            PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[16 + i] = jmp_buf[3 + i];
        gp = jmp_buf[11]; /* gp */

        v0 = a1;
        pc0 = ra;
    }

    void psxBios_strcat() {  // 0x15
        char *p1 = (char *)Ra0, *p2 = (char *)Ra1;

        PSXBIOS_LOG("psxBios_%s: %s, %s\n", A0names[0x15], Ra0, Ra1);

        while (*p1++)
            ;
        --p1;
        while ((*p1++ = *p2++) != '\0')
            ;

        v0 = a0;
        pc0 = ra;
    }

    void psxBios_strncat() {  // 0x16
        char *p1 = (char *)Ra0, *p2 = (char *)Ra1;
        int32_t n = a2;

        PSXBIOS_LOG("psxBios_%s: %s (%x), %s (%x), %d\n", A0names[0x16], Ra0, a0, Ra1, a1, a2);

        while (*p1++)
            ;
        --p1;
        while ((*p1++ = *p2++) != '\0') {
            if (--n < 0) {
                *--p1 = '\0';
                break;
            }
        }

        v0 = a0;
        pc0 = ra;
    }

    void psxBios_strcmp() {  // 0x17
        char *p1 = (char *)Ra0, *p2 = (char *)Ra1;

        PSXBIOS_LOG("psxBios_%s: %s (%x), %s (%x)\n", A0names[0x17], Ra0, a0, Ra1, a1);

        while (*p1 == *p2++) {
            if (*p1++ == '\0') {
                v0 = 0;
                pc0 = ra;
                return;
            }
        }

        v0 = (*p1 - *--p2);
        pc0 = ra;
    }

    void psxBios_strncmp() {  // 0x18
        char *p1 = (char *)Ra0, *p2 = (char *)Ra1;
        int32_t n = a2;

        PSXBIOS_LOG("psxBios_%s: %s (%x), %s (%x), %d\n", A0names[0x18], Ra0, a0, Ra1, a1, a2);

        while (--n >= 0 && *p1 == *p2++) {
            if (*p1++ == '\0') {
                v0 = 0;
                pc0 = ra;
                return;
            }
        }

        v0 = (n < 0 ? 0 : *p1 - *--p2);
        pc0 = ra;
    }

    void psxBios_strcpy() {  // 0x19
        char *p1 = (char *)Ra0, *p2 = (char *)Ra1;
        while ((*p1++ = *p2++) != '\0')
            ;

        v0 = a0;
        pc0 = ra;
    }

    void psxBios_strncpy() {  // 0x1a
        char *p1 = (char *)Ra0, *p2 = (char *)Ra1;
        int32_t n = a2, i;

        for (i = 0; i < n; i++) {
            if ((*p1++ = *p2++) == '\0') {
                while (++i < n) {
                    *p1++ = '\0';
                }
                v0 = a0;
                pc0 = ra;
                return;
            }
        }

        v0 = a0;
        pc0 = ra;
    }

    void psxBios_strlen() {  // 0x1b
        char *p = (char *)Ra0;
        v0 = 0;
        while (*p++) v0++;
        pc0 = ra;
    }

    void psxBios_index() {  // 0x1c
        char *p = (char *)Ra0;

        do {
            if (*p == a1) {
                v0 = a0 + (p - (char *)Ra0);
                pc0 = ra;
                return;
            }
        } while (*p++ != '\0');

        v0 = 0;
        pc0 = ra;
    }

    void psxBios_rindex() {  // 0x1d
        char *p = (char *)Ra0;

        v0 = 0;

        do {
            if (*p == a1) v0 = a0 + (p - (char *)Ra0);
        } while (*p++ != '\0');

        pc0 = ra;
    }

    void psxBios_strchr() {  // 0x1e
        psxBios_index();
    }

    void psxBios_strrchr() {  // 0x1f
        psxBios_rindex();
    }

    void psxBios_strpbrk() {  // 0x20
        char *p1 = (char *)Ra0, *p2 = (char *)Ra1, *scanp, c, sc;

        while ((c = *p1++) != '\0') {
            for (scanp = p2; (sc = *scanp++) != '\0';) {
                if (sc == c) {
                    v0 = a0 + (p1 - 1 - (char *)Ra0);
                    pc0 = ra;
                    return;
                }
            }
        }

        // BUG: return a0 instead of NULL if not found
        v0 = a0;
        pc0 = ra;
    }

    void psxBios_strspn() {  // 0x21
        char *p1, *p2;

        for (p1 = (char *)Ra0; *p1 != '\0'; p1++) {
            for (p2 = (char *)Ra1; *p2 != '\0' && *p2 != *p1; p2++)
                ;
            if (*p2 == '\0') break;
        }

        v0 = p1 - (char *)Ra0;
        pc0 = ra;
    }

    void psxBios_strcspn() {  // 0x22
        char *p1, *p2;

        for (p1 = (char *)Ra0; *p1 != '\0'; p1++) {
            for (p2 = (char *)Ra1; *p2 != '\0' && *p2 != *p1; p2++)
                ;
            if (*p2 != '\0') break;
        }

        v0 = p1 - (char *)Ra0;
        pc0 = ra;
    }

    void psxBios_strtok() {  // 0x23
        char *pcA0 = (char *)Ra0;
        char *pcRet = strtok(pcA0, (char *)Ra1);
        if (pcRet)
            v0 = a0 + pcRet - pcA0;
        else
            v0 = 0;
        pc0 = ra;
    }

    void psxBios_strstr() {  // 0x24
        char *p = (char *)Ra0, *p1, *p2;

        while (*p != '\0') {
            p1 = p;
            p2 = (char *)Ra1;

            while (*p1 != '\0' && *p2 != '\0' && *p1 == *p2) {
                p1++;
                p2++;
            }

            if (*p2 == '\0') {
                v0 = a0 + (p - (char *)Ra0);
                pc0 = ra;
                return;
            }

            p++;
        }

        v0 = 0;
        pc0 = ra;
    }

    void psxBios_toupper() {  // 0x25
        v0 = (int8_t)(a0 & 0xff);
        if (v0 >= 'a' && v0 <= 'z') v0 -= 'a' - 'A';
        pc0 = ra;
    }

    void psxBios_tolower() {  // 0x26
        v0 = (int8_t)(a0 & 0xff);
        if (v0 >= 'A' && v0 <= 'Z') v0 += 'a' - 'A';
        pc0 = ra;
    }

    void psxBios_bcopy() {  // 0x27
        char *p1 = (char *)Ra1, *p2 = (char *)Ra0;
        while ((int32_t)a2-- > 0) *p1++ = *p2++;

        pc0 = ra;
    }

    void psxBios_bzero() {  // 0x28
        char *p = (char *)Ra0;
        while ((int32_t)a1-- > 0) *p++ = '\0';

        pc0 = ra;
    }

    void psxBios_bcmp() {  // 0x29
        char *p1 = (char *)Ra0, *p2 = (char *)Ra1;

        if (a0 == 0 || a1 == 0) {
            v0 = 0;
            pc0 = ra;
            return;
        }

        while ((int32_t)a2-- > 0) {
            if (*p1++ != *p2++) {
                v0 = *p1 - *p2;  // BUG: compare the NEXT byte
                pc0 = ra;
                return;
            }
        }

        v0 = 0;
        pc0 = ra;
    }

    void psxBios_memcpy() {  // 0x2a
        char *p1 = (char *)Ra0, *p2 = (char *)Ra1;
        while ((int32_t)a2-- > 0) *p1++ = *p2++;

        v0 = a0;
        pc0 = ra;
    }

    void psxBios_memset() {  // 0x2b
        char *p = (char *)Ra0;
        while ((int32_t)a2-- > 0) *p++ = (char)a1;
        a2 = 0;
        v0 = a0;
        pc0 = ra;

        pc0 = ra;
    }

    void psxBios_memmove() {  // 0x2c
        char *p1 = (char *)Ra0, *p2 = (char *)Ra1;

        if (p2 <= p1 && p2 + a2 > p1) {
            a2++;  // BUG: copy one more byte here
            p1 += a2;
            p2 += a2;
            while ((int32_t)a2-- > 0) *--p1 = *--p2;
        } else {
            while ((int32_t)a2-- > 0) *p1++ = *p2++;
        }

        v0 = a0;
        pc0 = ra;
    }

    void psxBios_memcmp() {  // 0x2d
        psxBios_bcmp();
    }

    void psxBios_memchr() {  // 0x2e
        char *p = (char *)Ra0;

        while ((int32_t)a2-- > 0) {
            if (*p++ != (int8_t)a1) continue;
            v0 = a0 + (p - (char *)Ra0 - 1);
            pc0 = ra;
            return;
        }

        v0 = 0;
        pc0 = ra;
    }

    void psxBios_rand() {  // 0x2f
        uint32_t s = psxMu32(0x9010) * 1103515245 + 12345;
        v0 = (s >> 16) & 0x7fff;
        psxMu32ref(0x9010) = SWAP_LEu32(s);
        pc0 = ra;
    }

    void psxBios_srand() {  // 0x30
        psxMu32ref(0x9010) = SWAP_LEu32(a0);
        pc0 = ra;
    }

    uint32_t qscmpfunc, qswidth;

    inline int qscmp(char *a, char *b) {
        uint32_t sa0 = a0;

        a0 = sa0 + (a - (char *)PSXM(sa0));
        a1 = sa0 + (b - (char *)PSXM(sa0));

        softCall2(qscmpfunc);

        a0 = sa0;
        return (int32_t)v0;
    }

    inline void qexchange(char *i, char *j) {
        char t;
        int n = qswidth;

        do {
            t = *i;
            *i++ = *j;
            *j++ = t;
        } while (--n);
    }

    inline void q3exchange(char *i, char *j, char *k) {
        char t;
        int n = qswidth;

        do {
            t = *i;
            *i++ = *k;
            *k++ = *j;
            *j++ = t;
        } while (--n);
    }

    void qsort_main(char *a, char *l) {
        char *i, *j, *lp, *hp;
        int c;
        unsigned int n;

    start:
        if ((n = l - a) <= qswidth) return;
        n = qswidth * (n / (2 * qswidth));
        hp = lp = a + n;
        i = a;
        j = l - qswidth;
        while (true) {
            if (i < lp) {
                if ((c = qscmp(i, lp)) == 0) {
                    qexchange(i, lp -= qswidth);
                    continue;
                }
                if (c < 0) {
                    i += qswidth;
                    continue;
                }
            }

        loop:
            if (j > hp) {
                if ((c = qscmp(hp, j)) == 0) {
                    qexchange(hp += qswidth, j);
                    goto loop;
                }
                if (c > 0) {
                    if (i == lp) {
                        q3exchange(i, hp += qswidth, j);
                        i = lp += qswidth;
                        goto loop;
                    }
                    qexchange(i, j);
                    j -= qswidth;
                    i += qswidth;
                    continue;
                }
                j -= qswidth;
                goto loop;
            }

            if (i == lp) {
                if (lp - a >= l - hp) {
                    qsort_main(hp + qswidth, l);
                    l = lp;
                } else {
                    qsort_main(a, lp);
                    a = hp + qswidth;
                }
                goto start;
            }

            q3exchange(j, lp -= qswidth, i);
            j = hp -= qswidth;
        }
    }

    void psxBios_qsort() {  // 0x31
        qswidth = a2;
        qscmpfunc = a3;
        qsort_main((char *)Ra0, (char *)Ra0 + a1 * a2);

        pc0 = ra;
    }

    void psxBios_malloc() {  // 0x33
        unsigned int *chunk, *newchunk = NULL;
        unsigned int dsize = 0, csize, cstat;
        int colflag;
        PSXBIOS_LOG("psxBios_%s\n", A0names[0x33]);

        // scan through heap and combine free chunks of space
        chunk = s_heap_addr;
        colflag = 0;
        while (chunk < s_heap_end) {
            // get size and status of actual chunk
            csize = ((uint32_t)*chunk) & 0xfffffffc;
            cstat = ((uint32_t)*chunk) & 1;

            // it's a free chunk
            if (cstat == 1) {
                if (colflag == 0) {
                    newchunk = chunk;
                    dsize = csize;
                    colflag = 1;  // let's begin a new collection of free memory
                } else
                    dsize += (csize + 4);  // add the new size including header
            }
            // not a free chunk: did we start a collection ?
            else {
                if (colflag == 1) {  // collection is over
                    colflag = 0;
                    *newchunk = SWAP_LE32(dsize | 1);
                }
            }

            // next chunk
            chunk = (uint32_t *)((uintptr_t)chunk + csize + 4);
        }
        // if neccessary free memory on end of heap
        if (colflag == 1) *newchunk = SWAP_LE32(dsize | 1);

        chunk = s_heap_addr;
        csize = ((uint32_t)*chunk) & 0xfffffffc;
        cstat = ((uint32_t)*chunk) & 1;
        dsize = (a0 + 3) & 0xfffffffc;

        // exit on uninitialized heap
        if (chunk == NULL) {
            PCSX::g_system->biosPrintf("malloc %x,%x: Uninitialized Heap!\n", v0, a0);
            v0 = 0;
            pc0 = ra;
            return;
        }

        // search an unused chunk that is big enough until the end of the heap
        while ((dsize > csize || cstat == 0) && chunk < s_heap_end) {
            chunk = (uint32_t *)((uintptr_t)chunk + csize + 4);
            csize = ((uint32_t)*chunk) & 0xfffffffc;
            cstat = ((uint32_t)*chunk) & 1;
        }

        // catch out of memory
        if (chunk >= s_heap_end) {
            PCSX::g_system->biosPrintf("malloc %x,%x: Out of memory error!\n", v0, a0);
            v0 = 0;
            pc0 = ra;
            return;
        }

        // allocate memory
        if (dsize == csize) {
            // chunk has same size
            *chunk &= 0xfffffffc;
        } else {
            // split free chunk
            *chunk = SWAP_LE32(dsize);
            newchunk = (uint32_t *)((uintptr_t)chunk + dsize + 4);
            *newchunk = SWAP_LE32((csize - dsize - 4) & 0xfffffffc | 1);
        }

        // return pointer to allocated memory
        v0 = ((unsigned long)chunk - (unsigned long)PCSX::g_emulator.m_psxMem->g_psxM) + 4;
        v0 |= 0x80000000;
        PCSX::g_system->biosPrintf("malloc %x,%x\n", v0, a0);
        pc0 = ra;
    }

    void psxBios_free() {  // 0x34
        PSXBIOS_LOG("psxBios_%s\n", A0names[0x34]);

        PCSX::g_system->biosPrintf("free %x: %x bytes\n", a0, *(uint32_t *)(Ra0 - 4));

        *(uint32_t *)(Ra0 - 4) |= 1;  // set chunk to free
        pc0 = ra;
    }

    void psxBios_calloc() {  // 0x37
        PSXBIOS_LOG("psxBios_%s\n", A0names[0x37]);

        a0 = a0 * a1;
        psxBios_malloc();
        memset(Rv0, 0, a0);
    }

    void psxBios_realloc() {  // 0x38
        uint32_t block = a0;
        uint32_t size = a1;
        PSXBIOS_LOG("psxBios_%s\n", A0names[0x38]);

        a0 = block;
        psxBios_free();
        a0 = size;
        psxBios_malloc();
    }

    /* InitHeap(void *block , int n) */
    void psxBios_InitHeap() {  // 0x39
        unsigned int size;

        PSXBIOS_LOG("psxBios_%s\n", A0names[0x39]);

        if (((a0 & 0x1fffff) + a1) >= 0x200000)
            size = 0x1ffffc - (a0 & 0x1fffff);
        else
            size = a1;

        size &= 0xfffffffc;

        s_heap_addr = (uint32_t *)Ra0;
        s_heap_end = (uint32_t *)((uint8_t *)s_heap_addr + size);
        *s_heap_addr = SWAP_LE32(size | 1);

        PCSX::g_system->biosPrintf("InitHeap %x,%x : %lx %x\n", a0, a1,
                                   (uintptr_t)s_heap_addr - (uintptr_t)PCSX::g_emulator.m_psxMem->g_psxM, size);

        pc0 = ra;
    }

    void psxBios_getchar() {  // 0x3b
        v0 = getchar();
        pc0 = ra;
    }

    void psxBios_printf() {  // 0x3f
        char tmp[1024];
        char tmp2[1024];
        uint32_t save[4];
        char *ptmp = tmp;
        int n = 1, i = 0, j;

        memcpy(save, Rsp, 4 * 4);
        psxMu32ref(sp) = SWAP_LE32((uint32_t)a0);
        psxMu32ref(sp + 4) = SWAP_LE32((uint32_t)a1);
        psxMu32ref(sp + 8) = SWAP_LE32((uint32_t)a2);
        psxMu32ref(sp + 12) = SWAP_LE32((uint32_t)a3);

        while (Ra0[i]) {
            switch (Ra0[i]) {
                case '%':
                    j = 0;
                    tmp2[j++] = '%';
                _start:
                    switch (Ra0[++i]) {
                        case '.':
                        case 'l':
                            tmp2[j++] = Ra0[i];
                            goto _start;
                        default:
                            if (Ra0[i] >= '0' && Ra0[i] <= '9') {
                                tmp2[j++] = Ra0[i];
                                goto _start;
                            }
                            break;
                    }
                    tmp2[j++] = Ra0[i];
                    tmp2[j] = 0;

                    switch (Ra0[i]) {
                        case 'f':
                        case 'F':
                            ptmp += sprintf(ptmp, tmp2, (float)psxMu32(sp + n * 4));
                            n++;
                            break;
                        case 'a':
                        case 'A':
                        case 'e':
                        case 'E':
                        case 'g':
                        case 'G':
                            ptmp += sprintf(ptmp, tmp2, (double)psxMu32(sp + n * 4));
                            n++;
                            break;
                        case 'p':
                        case 'i':
                        case 'u':
                        case 'd':
                        case 'D':
                        case 'o':
                        case 'O':
                        case 'x':
                        case 'X':
                            ptmp += sprintf(ptmp, tmp2, (unsigned int)psxMu32(sp + n * 4));
                            n++;
                            break;
                        case 'c':
                            ptmp += sprintf(ptmp, tmp2, (unsigned char)psxMu32(sp + n * 4));
                            n++;
                            break;
                        case 's':
                            ptmp += sprintf(ptmp, tmp2, (char *)PSXM(psxMu32(sp + n * 4)));
                            n++;
                            break;
                        case '%':
                            *ptmp++ = Ra0[i];
                            break;
                    }
                    i++;
                    break;
                default:
                    *ptmp++ = Ra0[i++];
            }
        }
        *ptmp = 0;

        memcpy(Rsp, save, 4 * 4);

        PCSX::g_system->biosPrintf("%s", tmp);

        pc0 = ra;
    }

    void psxBios_format() {  // 0x41
        if (strcmp(Ra0, "bu00:") == 0 && !PCSX::g_emulator.settings.get<PCSX::Emulator::SettingMcd1>().empty()) {
            PCSX::g_emulator.m_sio->CreateMcd(
                PCSX::g_emulator.settings.get<PCSX::Emulator::SettingMcd1>().string().c_str());
            PCSX::g_emulator.m_sio->LoadMcd(
                1, PCSX::g_emulator.settings.get<PCSX::Emulator::SettingMcd1>().string().c_str());
            v0 = 1;
        } else if (strcmp(Ra0, "bu10:") == 0 && !PCSX::g_emulator.settings.get<PCSX::Emulator::SettingMcd2>().empty()) {
            PCSX::g_emulator.m_sio->CreateMcd(
                PCSX::g_emulator.settings.get<PCSX::Emulator::SettingMcd2>().string().c_str());
            PCSX::g_emulator.m_sio->LoadMcd(
                2, PCSX::g_emulator.settings.get<PCSX::Emulator::SettingMcd2>().string().c_str());
            v0 = 1;
        } else {
            v0 = 0;
        }
        pc0 = ra;
    }

    /*
     *  long Load(char *name, struct EXEC *header);
     */

    void psxBios_Load() {  // 0x42
        EXE_HEADER eheader;

        PSXBIOS_LOG("psxBios_%s: %s, %x\n", A0names[0x42], Ra0, a1);

        if (LoadCdromFile(Ra0, &eheader) == 0) {
            memcpy(Ra1, ((char *)&eheader) + 16, sizeof(EXEC));
            v0 = 1;
        } else
            v0 = 0;

        pc0 = ra;
    }

    /*
     *  int Exec(struct EXEC *header , int argc , char **argv);
     */

    void psxBios_Exec() {  // 43
        EXEC *header = (EXEC *)Ra0;
        uint32_t tmp;

        PSXBIOS_LOG("psxBios_%s: %x, %x, %x\n", A0names[0x43], a0, a1, a2);

        header->_sp = sp;
        header->_fp = fp;
        header->_sp = sp;
        header->_gp = gp;
        header->ret = ra;
        header->base = s0;

        if (header->S_addr != 0) {
            tmp = header->S_addr + header->s_size;
            sp = tmp;
            fp = sp;
        }

        gp = header->gp0;

        s0 = a0;

        a0 = a1;
        a1 = a2;

        ra = 0x8000;
        pc0 = header->_pc0;
    }

    void psxBios_FlushCache() {  // 44
        PSXBIOS_LOG("psxBios_%s\n", A0names[0x44]);

        PCSX::g_emulator.m_psxCpu->m_psxRegs.ICache_valid = false;

        pc0 = ra;
    }

    void psxBios_GPU_dw() {  // 0x46
        int size;
        int32_t *ptr;

        PSXBIOS_LOG("psxBios_%s\n", A0names[0x46]);

        PCSX::g_emulator.m_gpu->writeData(0xa0000000);
        PCSX::g_emulator.m_gpu->writeData((a1 << 16) | (a0 & 0xffff));
        PCSX::g_emulator.m_gpu->writeData((a3 << 16) | (a2 & 0xffff));
        size = (a2 * a3 + 1) / 2;
        ptr = (int32_t *)PSXM(Rsp[4]);  // that is correct?
        do {
            PCSX::g_emulator.m_gpu->writeData(SWAP_LE32(*ptr));
            ptr++;
        } while (--size);

        pc0 = ra;
    }

    void psxBios_mem2vram() {  // 0x47
        int size;

        PCSX::g_emulator.m_gpu->writeData(0xa0000000);
        PCSX::g_emulator.m_gpu->writeData((a1 << 16) | (a0 & 0xffff));
        PCSX::g_emulator.m_gpu->writeData((a3 << 16) | (a2 & 0xffff));
        size = (a2 * a3 + 1) / 2;
        PCSX::g_emulator.m_gpu->writeStatus(0x04000002);
        PCSX::g_emulator.m_hw->psxHwWrite32(0x1f8010f4, 0);
        PCSX::g_emulator.m_hw->psxHwWrite32(0x1f8010f0, PCSX::g_emulator.m_hw->psxHwRead32(0x1f8010f0) | 0x800);
        PCSX::g_emulator.m_hw->psxHwWrite32(0x1f8010a0, Rsp[4]);  // might have a buggy...
        PCSX::g_emulator.m_hw->psxHwWrite32(0x1f8010a4, ((size / 16) << 16) | 16);
        PCSX::g_emulator.m_hw->psxHwWrite32(0x1f8010a8, 0x01000201);

        pc0 = ra;
    }

    void psxBios_SendGPU() {  // 0x48
        PCSX::g_emulator.m_gpu->writeStatus(a0);
        pc0 = ra;
    }

    void psxBios_GPU_cw() {  // 0x49
        PCSX::g_emulator.m_gpu->writeData(a0);
        pc0 = ra;
    }

    void psxBios_GPU_cwb() {  // 0x4a
        int32_t *ptr = (int32_t *)Ra0;
        int size = a1;
        while (size--) {
            PCSX::g_emulator.m_gpu->writeData(SWAP_LE32(*ptr));
            ptr++;
        }

        pc0 = ra;
    }

    void psxBios_GPU_SendPackets() {  // 4b:
        PCSX::g_emulator.m_gpu->writeStatus(0x04000002);
        PCSX::g_emulator.m_hw->psxHwWrite32(0x1f8010f4, 0);
        PCSX::g_emulator.m_hw->psxHwWrite32(0x1f8010f0, PCSX::g_emulator.m_hw->psxHwRead32(0x1f8010f0) | 0x800);
        PCSX::g_emulator.m_hw->psxHwWrite32(0x1f8010a0, a0);
        PCSX::g_emulator.m_hw->psxHwWrite32(0x1f8010a4, 0);
        PCSX::g_emulator.m_hw->psxHwWrite32(0x1f8010a8, 0x010000401);
        pc0 = ra;
    }

    void psxBios_sys_a0_4c() {  // 0x4c GPU relate
        PCSX::g_emulator.m_hw->psxHwWrite32(0x1f8010a8, 0x00000401);
        PCSX::g_emulator.m_gpu->writeData(0x0400000);
        PCSX::g_emulator.m_gpu->writeData(0x0200000);
        PCSX::g_emulator.m_gpu->writeData(0x0100000);

        pc0 = ra;
    }

    void psxBios_GPU_GetGPUStatus() {  // 0x4d
        v0 = PCSX::g_emulator.m_gpu->readStatus();
        pc0 = ra;
    }

#undef s_addr

    void psxBios_LoadExec() {  // 51
        EXEC *header = (EXEC *)PSXM(0xf000);
        uint32_t s_addr, s_size;

        PSXBIOS_LOG("psxBios_%s: %s: %x,%x\n", A0names[0x51], Ra0, a1, a2);
        s_addr = a1;
        s_size = a2;

        a1 = 0xf000;
        psxBios_Load();

        header->S_addr = s_addr;
        header->s_size = s_size;

        a0 = 0xf000;
        a1 = 0;
        a2 = 0;
        psxBios_Exec();
    }

    void psxBios__bu_init() {  // 70
        PSXBIOS_LOG("psxBios_%s\n", A0names[0x70]);

        DeliverEvent(0x11, 0x2);  // 0xf0000011, 0x0004
        DeliverEvent(0x81, 0x2);  // 0xf4000001, 0x0004

        pc0 = ra;
    }

    void psxBios__96_init() {  // 71
        PSXBIOS_LOG("psxBios_%s\n", A0names[0x71]);

        pc0 = ra;
    }

    void psxBios__96_remove() {  // 72
        PSXBIOS_LOG("psxBios_%s\n", A0names[0x72]);

        pc0 = ra;
    }

    void psxBios_SetMem() {  // 9f
        uint32_t newMem = psxHu32(0x1060);

        PSXBIOS_LOG("psxBios_%s: %x, %x\n", A0names[0x9f], a0, a1);

        switch (a0) {
            case 2:
                psxHu32ref(0x1060) = SWAP_LE32(newMem);
                psxMu32ref(0x060) = a0;
                PCSX::g_system->biosPrintf("Change effective memory : %d MBytes\n", a0);
                break;

            case 8:
                psxHu32ref(0x1060) = SWAP_LE32(newMem | 0x300);
                psxMu32ref(0x060) = a0;
                PCSX::g_system->biosPrintf("Change effective memory : %d MBytes\n", a0);

            default:
                PCSX::g_system->biosPrintf("Effective memory must be 2/8 MBytes\n");
                break;
        }

        pc0 = ra;
    }

    void psxBios__card_info() {  // ab
        uint32_t ret;
        PSXBIOS_LOG("psxBios_%s: 0x%x\n", A0names[0xab], a0);

        s_card_active_chan = a0;

        switch (s_card_active_chan) {
            case 0x00:
            case 0x01:
            case 0x02:
            case 0x03:
                ret = PCSX::g_emulator.settings.get<PCSX::Emulator::SettingMcd1>().empty() ||
                              !PCSX::g_emulator.settings.get<PCSX::Emulator::SettingMcd1Inserted>()
                          ? 0x8
                          : 0x2;
                break;
            case 0x10:
            case 0x11:
            case 0x12:
            case 0x13:
                ret = PCSX::g_emulator.settings.get<PCSX::Emulator::SettingMcd2>().empty() ||
                              !PCSX::g_emulator.settings.get<PCSX::Emulator::SettingMcd1Inserted>()
                          ? 0x8
                          : 0x2;
                break;
            default:
                PSXBIOS_LOG("psxBios_%s: UNKNOWN PORT 0x%x\n", A0names[0xab], s_card_active_chan);
                ret = 0x11;
                break;
        }

        DeliverEvent(0x11, 0x2);  // 0xf0000011, 0x0004
        DeliverEvent(0x81, ret);  // 0xf4000001, 0x0004

        v0 = 1;
        pc0 = ra;
    }

    void psxBios__card_load() {  // ac
        PSXBIOS_LOG("psxBios_%s: %x\n", A0names[0xac], a0);

        s_card_active_chan = a0;

        //  DeliverEvent(0x11, 0x2); // 0xf0000011, 0x0004
        DeliverEvent(0x81, 0x2);  // 0xf4000001, 0x0004

        v0 = 1;
        pc0 = ra;
    }

    /* System calls B0 */

    void psxBios_SetRCnt() {  // 02
        PSXBIOS_LOG("psxBios_%s\n", B0names[0x02]);

        a0 &= 0x3;
        if (a0 != 3) {
            uint32_t mode = 0;

            PCSX::g_emulator.m_psxCounters->psxRcntWtarget(a0, a1);
            if (a2 & 0x1000) mode |= 0x050;  // Interrupt Mode
            if (a2 & 0x0100) mode |= 0x008;  // Count to 0xffff
            if (a2 & 0x0010) mode |= 0x001;  // Timer stop mode
            if (a0 == 2) {
                if (a2 & 0x0001) mode |= 0x200;
            }  // System Clock mode
            else {
                if (a2 & 0x0001) mode |= 0x100;
            }  // System Clock mode

            PCSX::g_emulator.m_psxCounters->psxRcntWmode(a0, mode);
        }
        pc0 = ra;
    }

    void psxBios_GetRCnt() {  // 03
        PSXBIOS_LOG("psxBios_%s\n", B0names[0x03]);

        a0 &= 0x3;
        if (a0 != 3)
            v0 = PCSX::g_emulator.m_psxCounters->psxRcntRcount(a0);
        else
            v0 = 0;
        pc0 = ra;
    }

    void psxBios_StartRCnt() {  // 04
        PSXBIOS_LOG("psxBios_%s\n", B0names[0x04]);

        a0 &= 0x3;
        if (a0 != 3)
            psxHu32ref(0x1074) |= SWAP_LE32((uint32_t)((1 << (a0 + 4))));
        else
            psxHu32ref(0x1074) |= SWAP_LEu32(0x1);
        v0 = 1;
        pc0 = ra;
    }

    void psxBios_StopRCnt() {  // 05
        PSXBIOS_LOG("psxBios_%s\n", B0names[0x05]);

        a0 &= 0x3;
        if (a0 != 3)
            psxHu32ref(0x1074) &= SWAP_LE32((uint32_t)(~(1 << (a0 + 4))));
        else
            psxHu32ref(0x1074) &= SWAP_LEu32(~0x1);
        pc0 = ra;
    }

    void psxBios_ResetRCnt() {  // 06
        PSXBIOS_LOG("psxBios_%s\n", B0names[0x06]);

        a0 &= 0x3;
        if (a0 != 3) {
            PCSX::g_emulator.m_psxCounters->psxRcntWmode(a0, 0);
            PCSX::g_emulator.m_psxCounters->psxRcntWtarget(a0, 0);
            PCSX::g_emulator.m_psxCounters->psxRcntWcount(a0, 0);
        }
        pc0 = ra;
    }

/* gets ev for use with s_Event */
#define GetEv()              \
    ev = (a0 >> 24) & 0xf;   \
    if (ev == 0xf) ev = 0x5; \
    ev *= 32;                \
    ev += a0 & 0x1f;

/* gets spec for use with s_Event */
#define GetSpec()                    \
    spec = 0;                        \
    switch (a1) {                    \
        case 0x0301:                 \
            spec = 16;               \
            break;                   \
        case 0x0302:                 \
            spec = 17;               \
            break;                   \
        default:                     \
            for (i = 0; i < 16; i++) \
                if (a1 & (1 << i)) { \
                    spec = i;        \
                    break;           \
                }                    \
            break;                   \
    }

    void psxBios_DeliverEvent() {  // 07
        int ev, spec;
        int i;

        GetEv();
        GetSpec();

        PSXBIOS_LOG("psxBios_%s %x,%x\n", B0names[0x07], ev, spec);

        DeliverEvent(ev, spec);

        pc0 = ra;
    }

    void psxBios_OpenEvent() {  // 08
        int ev, spec;
        int i;

        GetEv();
        GetSpec();

        PSXBIOS_LOG("psxBios_%s %x,%x (class:%x, spec:%x, mode:%x, func:%x)\n", B0names[0x08], ev, spec, a0, a1, a2,
                    a3);

        s_Event[ev][spec].status = EvStWAIT;
        s_Event[ev][spec].mode = a2;
        s_Event[ev][spec].fhandler = a3;

        v0 = ev | (spec << 8);
        pc0 = ra;
    }

    void psxBios_CloseEvent() {  // 09
        int ev, spec;

        ev = a0 & 0xff;
        spec = (a0 >> 8) & 0xff;

        PSXBIOS_LOG("psxBios_%s %x,%x\n", B0names[0x09], ev, spec);

        s_Event[ev][spec].status = EvStUNUSED;

        v0 = 1;
        pc0 = ra;
    }

    void psxBios_WaitEvent() {  // 0a
        int ev, spec;

        ev = a0 & 0xff;
        spec = (a0 >> 8) & 0xff;

        PSXBIOS_LOG("psxBios_%s %x,%x\n", B0names[0x0a], ev, spec);

        s_Event[ev][spec].status = EvStACTIVE;

        v0 = 1;
        pc0 = ra;
    }

    void psxBios_TestEvent() {  // 0b
        int ev, spec;

        ev = a0 & 0xff;
        spec = (a0 >> 8) & 0xff;

        if (s_Event[ev][spec].status == EvStALREADY) {
            s_Event[ev][spec].status = EvStACTIVE;
            v0 = 1;
        } else
            v0 = 0;

        PSXBIOS_LOG("psxBios_%s %x,%x: %x\n", B0names[0x0b], ev, spec, v0);

        pc0 = ra;
    }

    void psxBios_EnableEvent() {  // 0c
        int ev, spec;

        ev = a0 & 0xff;
        spec = (a0 >> 8) & 0xff;

        PSXBIOS_LOG("psxBios_%s %x,%x\n", B0names[0x0c], ev, spec);

        s_Event[ev][spec].status = EvStACTIVE;

        v0 = 1;
        pc0 = ra;
    }

    void psxBios_DisableEvent() {  // 0d
        int ev, spec;

        ev = a0 & 0xff;
        spec = (a0 >> 8) & 0xff;

        PSXBIOS_LOG("psxBios_%s %x,%x\n", B0names[0x0d], ev, spec);

        s_Event[ev][spec].status = EvStWAIT;

        v0 = 1;
        pc0 = ra;
    }

    /*
     *  long OpenTh(long (*func)(), unsigned long sp, unsigned long gp);
     */

    void psxBios_OpenTh() {  // 0e
        int th;

        for (th = 1; th < 8; th++)
            if (s_Thread[th].status == 0) break;

        PSXBIOS_LOG("psxBios_%s: %x\n", B0names[0x0e], th);

        s_Thread[th].status = 1;
        s_Thread[th].func = a0;
        s_Thread[th].reg[29] = a1;
        s_Thread[th].reg[28] = a2;

        v0 = th;
        pc0 = ra;
    }

    /*
     *  int CloseTh(long thread);
     */

    void psxBios_CloseTh() {  // 0f
        int th = a0 & 0xff;

        PSXBIOS_LOG("psxBios_%s: %x\n", B0names[0x0f], th);

        if (s_Thread[th].status == 0) {
            v0 = 0;
        } else {
            s_Thread[th].status = 0;
            v0 = 1;
        }

        pc0 = ra;
    }

    /*
     *  int ChangeTh(long thread);
     */

    void psxBios_ChangeTh() {  // 10
        int th = a0 & 0xff;

        PSXBIOS_LOG("psxBios_%s: %x\n", B0names[0x10], th);

        if (s_Thread[th].status == 0 || s_CurThread == th) {
            v0 = 0;

            pc0 = ra;
        } else {
            v0 = 1;

            if (s_Thread[s_CurThread].status == 2) {
                s_Thread[s_CurThread].status = 1;
                s_Thread[s_CurThread].func = ra;
                memcpy(s_Thread[s_CurThread].reg, PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r, 32 * 4);
            }

            memcpy(PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r, s_Thread[th].reg, 32 * 4);
            pc0 = s_Thread[th].func;
            s_Thread[th].status = 2;
            s_CurThread = th;
        }
    }

    void psxBios_InitPAD() {  // 0x12
        PSXBIOS_LOG("psxBios_%s\n", B0names[0x12]);

        s_pad_buf1 = (char *)Ra0;
        s_pad_buf1len = a1;
        s_pad_buf2 = (char *)Ra2;
        s_pad_buf2len = a3;

        v0 = 1;
        pc0 = ra;
    }

    void psxBios_StartPAD() {  // 13
        PSXBIOS_LOG("psxBios_%s\n", B0names[0x13]);

        PCSX::g_emulator.m_hw->psxHwWrite16(0x1f801074,
                                            (unsigned short)(PCSX::g_emulator.m_hw->psxHwRead16(0x1f801074) | 0x1));
        PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.n.Status |= 0x401;
        pc0 = ra;
    }

    void psxBios_StopPAD() {  // 14
        PSXBIOS_LOG("psxBios_%s\n", B0names[0x14]);

        s_pad_buf1 = NULL;
        s_pad_buf2 = NULL;
        pc0 = ra;
    }

    void psxBios_PAD_init() {  // 15
        PSXBIOS_LOG("psxBios_%s\n", B0names[0x15]);

        PCSX::g_emulator.m_hw->psxHwWrite16(0x1f801074,
                                            (uint16_t)(PCSX::g_emulator.m_hw->psxHwRead16(0x1f801074) | 0x1));
        s_pad_buf = (int *)Ra1;
        *s_pad_buf = -1;
        PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.n.Status |= 0x401;
        pc0 = ra;
    }

    void psxBios_PAD_dr() {  // 16
        PSXBIOS_LOG("psxBios_%s\n", B0names[0x16]);

        v0 = -1;
        pc0 = ra;
    }

    void psxBios_ReturnFromException() {  // 17
        LoadRegs();

        pc0 = PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.n.EPC;
        if (PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.n.Cause & 0x80000000) pc0 += 4;

        PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.n.Status =
            (PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.n.Status & 0xfffffff0) |
            ((PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.n.Status & 0x3c) >> 2);
    }

    void psxBios_ResetEntryInt() {  // 18
        PSXBIOS_LOG("psxBios_%s\n", B0names[0x18]);

        s_jmp_int = NULL;
        pc0 = ra;
    }

    void psxBios_HookEntryInt() {  // 19
        PSXBIOS_LOG("psxBios_%s\n", B0names[0x19]);

        s_jmp_int = (uint32_t *)Ra0;
        pc0 = ra;
    }

    void psxBios_UnDeliverEvent() {  // 0x20
        int ev, spec;
        int i;

        GetEv();
        GetSpec();

        PSXBIOS_LOG("psxBios_%s %x,%x\n", B0names[0x20], ev, spec);

        if (s_Event[ev][spec].status == EvStALREADY && s_Event[ev][spec].mode == EvMdNOINTR)
            s_Event[ev][spec].status = EvStACTIVE;

        pc0 = ra;
    }

    void buopen(int mcd, char *ptr, const PCSX::u8string cfg) {
        int i;
        uint8_t *fptr = reinterpret_cast<uint8_t *>(ptr);

        strcpy(s_FDesc[1 + mcd].name, Ra0 + 5);
        s_FDesc[1 + mcd].offset = 0;
        s_FDesc[1 + mcd].mode = a1;

        for (i = 1; i < 16; i++) {
            fptr += 128;
            if ((*fptr & 0xF0) != 0x50) continue;
            if (strcmp(s_FDesc[1 + mcd].name, reinterpret_cast<char *>(fptr) + 0xa)) continue;
            s_FDesc[1 + mcd].mcfile = i;
            PCSX::g_system->biosPrintf("open %s\n", fptr + 0xa);
            v0 = 1 + mcd;
            break;
        }
        if (a1 & 0x200 && v0 == -1) { /* FCREAT */
            fptr = reinterpret_cast<uint8_t *>(ptr);
            for (i = 1; i < 16; i++) {
                int j, checksum, nblk = a1 >> 16;
                uint8_t *pptr, *fptr2;

                fptr += 128;
                if ((*fptr & 0xF0) != 0xa0) continue;

                s_FDesc[1 + mcd].mcfile = i;
                fptr[0] = 0x51;
                fptr[4] = 0x00;
                fptr[5] = 0x20 * nblk;
                fptr[6] = 0x00;
                fptr[7] = 0x00;
                strcpy(reinterpret_cast<char *>(fptr) + 0xa, s_FDesc[1 + mcd].name);
                pptr = fptr2 = fptr;
                for (j = 2; j <= nblk; j++) {
                    int k;
                    for (i++; i < 16; i++) {
                        fptr2 += 128;

                        memset(fptr2, 0, 128);
                        fptr2[0] = j < nblk ? 0x52 : 0x53;
                        pptr[8] = i - 1;
                        pptr[9] = 0;
                        for (k = 0, checksum = 0; k < 127; k++) checksum ^= pptr[k];
                        pptr[127] = checksum;
                        pptr = fptr2;
                        break;
                    }
                    /* shouldn't this return ENOSPC if i == 16? */
                }
                pptr[8] = pptr[9] = 0xff;
                for (j = 0, checksum = 0; j < 127; j++) checksum ^= pptr[j];
                pptr[127] = checksum;
                PCSX::g_system->biosPrintf("openC %s %d\n", ptr, nblk);
                v0 = 1 + mcd;
                /* just go ahead and resave them all */
                PCSX::g_emulator.m_sio->SaveMcd(cfg, reinterpret_cast<char *>(ptr), 128, 128 * 15);
                break;
            }
            /* shouldn't this return ENOSPC if i == 16? */
        }
    }

    /*
     *  int open(char *name , int mode);
     */

    void psxBios_open() {  // 0x32
        PSXBIOS_LOG("psxBios_%s: %s,%x\n", B0names[0x32], Ra0, a1);

        v0 = -1;

        if (!strncmp(Ra0, "bu00", 4)) {
            buopen(1, PCSX::g_emulator.m_sio->g_mcd1Data,
                   PCSX::g_emulator.settings.get<PCSX::Emulator::SettingMcd1>().string());
        }

        if (!strncmp(Ra0, "bu10", 4)) {
            buopen(2, PCSX::g_emulator.m_sio->g_mcd2Data,
                   PCSX::g_emulator.settings.get<PCSX::Emulator::SettingMcd2>().string());
        }

        pc0 = ra;
    }

    /*
     *  int lseek(int fd , int offset , int whence);
     */

    void psxBios_lseek() {  // 0x33
        PSXBIOS_LOG("psxBios_%s: %x, %x, %x\n", B0names[0x33], a0, a1, a2);

        switch (a2) {
            case 0:  // SEEK_SET
                s_FDesc[a0].offset = a1;
                v0 = a1;
                //          DeliverEvent(0x11, 0x2); // 0xf0000011, 0x0004
                //          DeliverEvent(0x81, 0x2); // 0xf4000001, 0x0004
                break;

            case 1:  // SEEK_CUR
                s_FDesc[a0].offset += a1;
                v0 = s_FDesc[a0].offset;
                break;
        }

        pc0 = ra;
    }

    template <int mcd>
    char *getmcdData() {
        if (mcd == 1) {
            return PCSX::g_emulator.m_sio->g_mcd1Data;
        } else if (mcd == 2) {
            return PCSX::g_emulator.m_sio->g_mcd2Data;
        }
        return NULL;
    }

    template <int mcd>
    const PCSX::u8string getmcdName() {
        if (mcd == 1) {
            return PCSX::g_emulator.settings.get<PCSX::Emulator::SettingMcd1>().string();
        } else if (mcd == 2) {
            return PCSX::g_emulator.settings.get<PCSX::Emulator::SettingMcd2>().string();
        }
        return MAKEU8(u8"");
    }

    template <int mcd>
    void buread() {
        PCSX::g_system->biosPrintf("read %d: %x,%x (%s)\n", s_FDesc[1 + mcd].mcfile, s_FDesc[1 + mcd].offset, a2,
                                   getmcdData<mcd>() + 128 * s_FDesc[1 + mcd].mcfile + 0xa);
        char *ptr = getmcdData<mcd>() + 8192 * s_FDesc[1 + mcd].mcfile + s_FDesc[1 + mcd].offset;
        memcpy(Ra1, ptr, a2);
        if (s_FDesc[1 + mcd].mode & 0x8000)
            v0 = 0;
        else
            v0 = a2;
        s_FDesc[1 + mcd].offset += v0;
        DeliverEvent(0x11, 0x2); /* 0xf0000011, 0x0004 */
        DeliverEvent(0x81, 0x2); /* 0xf4000001, 0x0004 */
    }

    /*
     *  int read(int fd , void *buf , int nbytes);
     */

    void psxBios_read() {  // 0x34
        PSXBIOS_LOG("psxBios_%s: %x, %x, %x\n", B0names[0x34], a0, a1, a2);

        v0 = -1;

        switch (a0) {
            case 2:
                buread<1>();
                break;
            case 3:
                buread<2>();
                break;
        }

        pc0 = ra;
    }

    template <int mcd>
    void buwrite() {
        uint32_t offset = +8192 * s_FDesc[1 + mcd].mcfile + s_FDesc[1 + mcd].offset;
        PCSX::g_system->biosPrintf("write %d: %x,%x\n", s_FDesc[1 + mcd].mcfile, s_FDesc[1 + mcd].offset, a2);
        char *ptr = getmcdData<mcd>() + offset;
        memcpy(ptr, Ra1, a2);
        s_FDesc[1 + mcd].offset += a2;
        PCSX::g_emulator.m_sio->SaveMcd(getmcdName<mcd>(), getmcdData<mcd>(), offset, a2);
        if (s_FDesc[1 + mcd].mode & 0x8000)
            v0 = 0;
        else
            v0 = a2;
        DeliverEvent(0x11, 0x2); /* 0xf0000011, 0x0004 */
        DeliverEvent(0x81, 0x2); /* 0xf4000001, 0x0004 */
    }

    /*
     *  int write(int fd , void *buf , int nbytes);
     */

    void psxBios_write() {  // 0x35/0x03
        if (a0 == 1) {      // stdout
            char *ptr = Ra1;

            while (a2 > 0) {
                PCSX::g_system->biosPrintf("%c", *ptr++);
                a2--;
            }
            pc0 = ra;
            return;
        }
        PSXBIOS_LOG("psxBios_%s: %x,%x,%x\n", B0names[0x35], a0, a1, a2);

        v0 = -1;

        switch (a0) {
            case 2:
                buwrite<1>();
                break;
            case 3:
                buwrite<2>();
                break;
        }

        pc0 = ra;
    }

    /*
     *  int close(int fd);
     */

    void psxBios_close() {  // 0x36
        PSXBIOS_LOG("psxBios_%s: %x\n", B0names[0x36], a0);

        v0 = a0;
        pc0 = ra;
    }
    static const size_t PSXSTRBUFMAX = 255;
    char psxstrbuf[PSXSTRBUFMAX + 1];
    unsigned short psxstrbuf_count = 0;

    void psxBios_putchar() {  // 3d
        char logchar = (a0 == 0xa ? '>' : (char)a0);
        if (psxstrbuf_count < PSXSTRBUFMAX) psxstrbuf[psxstrbuf_count++] = logchar;

        PCSX::g_system->biosPrintf("%c", (char)a0);
        if ((a0 == 0xa && psxstrbuf_count >= 2) || psxstrbuf_count >= PSXSTRBUFMAX) {
            psxstrbuf[psxstrbuf_count++] = '\0';
            PSXBIOS_LOG("psxBios_%s: string_[%d]_cr: %s\n", B0names[0x3d], psxstrbuf_count, psxstrbuf);
            psxstrbuf_count = 0;
        }

        pc0 = ra;
    }

    void psxBios_puts() {  // 3e/3f
        PCSX::g_system->biosPrintf("%s", Ra0);
        pc0 = ra;
    }

    char ffile[64], *pfile;
    int nfile;

    template <int mcd>
    void bufile(struct DIRENTRY *dir) {
        while (nfile < 16) {
            int match = 1;

            char *ptr = getmcdData<mcd>() + 128 * (nfile + 1);
            nfile++;
            if ((*ptr & 0xF0) != 0x50) continue;
            /* Bug link files show up as free block. */
            if (!ptr[0xa]) continue;
            ptr += 0xa;
            if (pfile[0] == 0) {
                strncpy(dir->name, ptr, sizeof(dir->name));
                dir->name[sizeof(dir->name) - 1] = '\0';
            } else
                for (int i = 0; i < 20; i++) {
                    if (pfile[i] == ptr[i]) {
                        dir->name[i] = ptr[i];
                        continue;
                    }
                    if (pfile[i] == '?') {
                        dir->name[i] = ptr[i];
                        continue;
                    }
                    if (pfile[i] == '*') {
                        strcpy(dir->name + i, ptr + i);
                        break;
                    }
                    match = 0;
                    break;
                }
            PCSX::g_system->printf("%d : %s = %s + %s (match=%d)\n", nfile, dir->name, pfile, ptr, match);
            if (match == 0) {
                continue;
            }
            dir->size = 8192;
            v0 = a1;
            break;
        }
    }

    /*
     *  struct DIRENTRY* firstfile(char *name,struct DIRENTRY *dir);
     */

    void psxBios_firstfile() {  // 42
        struct DIRENTRY *dir = (struct DIRENTRY *)Ra1;

        PSXBIOS_LOG("psxBios_%s: %s\n", B0names[0x42], Ra0);

        v0 = 0;

        strcpy(ffile, Ra0);
        pfile = ffile + 5;
        nfile = 0;

        if (!strncmp(Ra0, "bu00", 4)) {
            DeliverEvent(0x11, 0x2);
            bufile<1>(dir);
        } else if (!strncmp(Ra0, "bu10", 4)) {
            DeliverEvent(0x11, 0x2);
            bufile<2>(dir);
        }

        pc0 = ra;
    }

    /*
     *  struct DIRENTRY* nextfile(struct DIRENTRY *dir);
     */

    void psxBios_nextfile() {  // 43
        struct DIRENTRY *dir = (struct DIRENTRY *)Ra0;

        PSXBIOS_LOG("psxBios_%s: %s\n", B0names[0x43], dir->name);

        v0 = 0;

        if (!strncmp(ffile, "bu00", 4)) {
            bufile<1>(dir);
        }

        if (!strncmp(ffile, "bu10", 4)) {
            bufile<2>(dir);
        }

        pc0 = ra;
    }

    template <int mcd>
    void burename() {
        for (int i = 1; i < 16; i++) {
            int namelen, j, chksum = 0;
            char *ptr = getmcdData<mcd>() + 128 * i;
            if ((*ptr & 0xF0) != 0x50) continue;
            if (strcmp(Ra0 + 5, ptr + 0xa)) continue;
            namelen = strlen(Ra1 + 5);
            memcpy(ptr + 0xa, Ra1 + 5, namelen);
            memset(ptr + 0xa + namelen, 0, 0x75 - namelen);
            for (j = 0; j < 127; j++) chksum ^= ptr[j];
            ptr[127] = chksum;
            PCSX::g_emulator.m_sio->SaveMcd(getmcdName<mcd>(), getmcdData<mcd>(), 128 * i + 0xa, 0x76);
            v0 = 1;
            break;
        }
    }

    /*
     *  int rename(char *old, char *new);
     */

    void psxBios_rename() {  // 44
        PSXBIOS_LOG("psxBios_%s: %s,%s\n", B0names[0x44], Ra0, Ra1);

        v0 = 0;

        if (!strncmp(Ra0, "bu00", 4) && !strncmp(Ra1, "bu00", 4)) {
            burename<1>();
        }

        if (!strncmp(Ra0, "bu10", 4) && !strncmp(Ra1, "bu10", 4)) {
            burename<2>();
        }

        pc0 = ra;
    }

    template <int mcd>
    void budelete() {
        for (int i = 1; i < 16; i++) {
            char *ptr = getmcdData<mcd>() + 128 * i;
            if ((*ptr & 0xF0) != 0x50) continue;
            if (strcmp(Ra0 + 5, ptr + 0xa)) continue;
            *ptr = (*ptr & 0xf) | 0xA0;
            PCSX::g_emulator.m_sio->SaveMcd(getmcdName<mcd>(), getmcdData<mcd>(), 128 * i, 1);
            PCSX::g_system->biosPrintf("delete %s\n", ptr + 0xa);
            v0 = 1;
            break;
        }
    }

    /*
     *  int delete(char *name);
     */

    void psxBios_delete() {  // 45
        PSXBIOS_LOG("psxBios_%s: %s\n", B0names[0x45], Ra0);

        v0 = 0;

        if (!strncmp(Ra0, "bu00", 4)) {
            budelete<1>();
        }

        if (!strncmp(Ra0, "bu10", 4)) {
            budelete<2>();
        }

        pc0 = ra;
    }

    void psxBios_InitCARD() {  // 4a
        PSXBIOS_LOG("psxBios_%s: %x\n", B0names[0x4a], a0);

        s_CardState = 0;

        pc0 = ra;
    }

    void psxBios_StartCARD() {  // 4b
        PSXBIOS_LOG("psxBios_%s\n", B0names[0x4b]);

        if (s_CardState == 0) s_CardState = 1;

        pc0 = ra;
    }

    void psxBios_StopCARD() {  // 4c
        PSXBIOS_LOG("psxBios_%s\n", B0names[0x4c]);

        if (s_CardState == 1) s_CardState = 0;

        pc0 = ra;
    }

    void psxBios__card_write() {  // 0x4e
        int const port = a0 >> 4;
        uint32_t const sect = a1 % (PCSX::SIO::MCD_SIZE / 8);  // roll on range 0...3FFF

        PSXBIOS_LOG("psxBios_%s, PORT=%i, SECT=%u(%u), DEST=%p\n", B0names[0x4e], port, sect, a1, a2);

        s_card_active_chan = a0;

        if (port == 0) {
            memcpy(PCSX::g_emulator.m_sio->g_mcd1Data + (sect * PCSX::SIO::MCD_SECT_SIZE), Ra2,
                   PCSX::SIO::MCD_SECT_SIZE);
            PCSX::g_emulator.m_sio->SaveMcd(
                PCSX::g_emulator.settings.get<PCSX::Emulator::SettingMcd1>().string().c_str(),
                PCSX::g_emulator.m_sio->g_mcd1Data, sect * PCSX::SIO::MCD_SECT_SIZE, PCSX::SIO::MCD_SECT_SIZE);
        } else {
            memcpy(PCSX::g_emulator.m_sio->g_mcd2Data + (sect * PCSX::SIO::MCD_SECT_SIZE), Ra2,
                   PCSX::SIO::MCD_SECT_SIZE);
            PCSX::g_emulator.m_sio->SaveMcd(
                PCSX::g_emulator.settings.get<PCSX::Emulator::SettingMcd2>().string().c_str(),
                PCSX::g_emulator.m_sio->g_mcd2Data, sect * PCSX::SIO::MCD_SECT_SIZE, PCSX::SIO::MCD_SECT_SIZE);
        }

        DeliverEvent(0x11, 0x2);  // 0xf0000011, 0x0004
                                  //    DeliverEvent(0x81, 0x2); // 0xf4000001, 0x0004

        v0 = 1;
        pc0 = ra;
    }

    void psxBios__card_read() {  // 0x4f
        int const port = a0 >> 4;
        uint32_t const sect = a1 % (PCSX::SIO::MCD_SIZE / 8);  // roll on range 0...3FFF

        PSXBIOS_LOG("psxBios_%s, PORT=%i, SECT=%u(%u), DEST=%p\n", B0names[0x4f], port, sect, a1, a2);

        s_card_active_chan = a0;

        if (port == 0) {
            memcpy(Ra2, PCSX::g_emulator.m_sio->g_mcd1Data + (sect * PCSX::SIO::MCD_SECT_SIZE),
                   PCSX::SIO::MCD_SECT_SIZE);
        } else {
            memcpy(Ra2, PCSX::g_emulator.m_sio->g_mcd2Data + (sect * PCSX::SIO::MCD_SECT_SIZE),
                   PCSX::SIO::MCD_SECT_SIZE);
        }

        DeliverEvent(0x11, 0x2);  // 0xf0000011, 0x0004
                                  //    DeliverEvent(0x81, 0x2); // 0xf4000001, 0x0004

        v0 = 1;
        pc0 = ra;
    }

    void psxBios__new_card() {  // 0x50
        PSXBIOS_LOG("psxBios_%s\n", B0names[0x50]);

        pc0 = ra;
    }

    void psxBios_Krom2RawAdd() {  // 0x51
        int i = 0;

        const uint32_t table_8140[][2] = {
            {0x8140, 0x0000}, {0x8180, 0x0762}, {0x81ad, 0x0cc6}, {0x81b8, 0x0ca8}, {0x81c0, 0x0f00}, {0x81c8, 0x0d98},
            {0x81cf, 0x10c2}, {0x81da, 0x0e6a}, {0x81e9, 0x13ce}, {0x81f0, 0x102c}, {0x81f8, 0x1590}, {0x81fc, 0x111c},
            {0x81fd, 0x1626}, {0x824f, 0x113a}, {0x8259, 0x20ee}, {0x8260, 0x1266}, {0x827a, 0x24cc}, {0x8281, 0x1572},
            {0x829b, 0x28aa}, {0x829f, 0x187e}, {0x82f2, 0x32dc}, {0x8340, 0x2238}, {0x837f, 0x4362}, {0x8380, 0x299a},
            {0x8397, 0x4632}, {0x839f, 0x2c4c}, {0x83b7, 0x49f2}, {0x83bf, 0x2f1c}, {0x83d7, 0x4db2}, {0x8440, 0x31ec},
            {0x8461, 0x5dde}, {0x8470, 0x35ca}, {0x847f, 0x6162}, {0x8480, 0x378c}, {0x8492, 0x639c}, {0x849f, 0x39a8},
            {0xffff, 0}};

        const uint32_t table_889f[][2] = {
            {0x889f, 0x3d68},  {0x8900, 0x40ec},  {0x897f, 0x4fb0},  {0x8a00, 0x56f4},  {0x8a7f, 0x65b8},
            {0x8b00, 0x6cfc},  {0x8b7f, 0x7bc0},  {0x8c00, 0x8304},  {0x8c7f, 0x91c8},  {0x8d00, 0x990c},
            {0x8d7f, 0xa7d0},  {0x8e00, 0xaf14},  {0x8e7f, 0xbdd8},  {0x8f00, 0xc51c},  {0x8f7f, 0xd3e0},
            {0x9000, 0xdb24},  {0x907f, 0xe9e8},  {0x9100, 0xf12c},  {0x917f, 0xfff0},  {0x9200, 0x10734},
            {0x927f, 0x115f8}, {0x9300, 0x11d3c}, {0x937f, 0x12c00}, {0x9400, 0x13344}, {0x947f, 0x14208},
            {0x9500, 0x1494c}, {0x957f, 0x15810}, {0x9600, 0x15f54}, {0x967f, 0x16e18}, {0x9700, 0x1755c},
            {0x977f, 0x18420}, {0x9800, 0x18b64}, {0xffff, 0}};

        if (a0 >= 0x8140 && a0 <= 0x84be) {
            while (table_8140[i][0] <= a0) i++;
            a0 -= table_8140[i - 1][0];
            v0 = 0xbfc66000 + (a0 * 0x1e + table_8140[i - 1][1]);
        } else if (a0 >= 0x889f && a0 <= 0x9872) {
            while (table_889f[i][0] <= a0) i++;
            a0 -= table_889f[i - 1][0];
            v0 = 0xbfc66000 + (a0 * 0x1e + table_889f[i - 1][1]);
        } else {
            v0 = 0xffffffff;
        }

        pc0 = ra;
    }

    // stub?
    void psxBios__get_error() {  // 55
        PSXBIOS_LOG("psxBios_%s\n", B0names[0x55]);

        v0 = 0;
        pc0 = ra;
    }

    void psxBios_GetC0Table() {  // 56
        PSXBIOS_LOG("psxBios_%s\n", B0names[0x56]);

        v0 = 0x674;
        pc0 = ra;
    }

    void psxBios_GetB0Table() {  // 57
        PSXBIOS_LOG("psxBios_%s\n", B0names[0x57]);

        v0 = 0x874;
        pc0 = ra;
    }

    void psxBios__card_chan() {  // 0x58
        PSXBIOS_LOG("psxBios_%s\n", B0names[0x58]);

        v0 = s_card_active_chan;
        pc0 = ra;
    }

    void psxBios_ChangeClearPad() {  // 5b
        PSXBIOS_LOG("psxBios_%s: %x\n", B0names[0x5b], a0);

        pc0 = ra;
    }

    void psxBios__card_status() {  // 5c
        PSXBIOS_LOG("psxBios_%s: %x\n", B0names[0x5c], a0);

        v0 = 1;
        pc0 = ra;
    }

    /* System calls C0 */

    /*
     * int SysEnqIntRP(int index , long *queue);
     */

    void psxBios_SysEnqIntRP() {  // 02
        PSXBIOS_LOG("psxBios_%s: %x\n", C0names[0x02], a0);

        s_SysIntRP[a0] = a1;

        v0 = 0;
        pc0 = ra;
    }

    /*
     * int SysDeqIntRP(int index , long *queue);
     */

    void psxBios_SysDeqIntRP() {  // 03
        PSXBIOS_LOG("psxBios_%s: %x\n", C0names[0x03], a0);

        s_SysIntRP[a0] = 0;

        v0 = 0;
        pc0 = ra;
    }

    void psxBios_ChangeClearRCnt() {  // 0a
        uint32_t *ptr;

        PSXBIOS_LOG("psxBios_%s: %x, %x\n", C0names[0x0a], a0, a1);

        ptr = (uint32_t *)PSXM((a0 << 2) + 0x8600);
        v0 = *ptr;
        *ptr = a1;

        //  PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.n.Status|= 0x404;
        pc0 = ra;
    }

    void psxBios_dummy() {
        PSXBIOS_LOG("unk %x call: %x\n", pc0 & 0x1fffff, t1);
        pc0 = ra;
    }

    void (BiosImpl::*m_biosA0[256])();
    void (BiosImpl::*m_biosB0[256])();
    void (BiosImpl::*m_biosC0[256])();

    bool callA0(unsigned index) final {
        if (m_biosA0[index]) (*this.*m_biosA0[index])();
        return !!m_biosA0[index];
    }
    bool callB0(unsigned index) final {
        if (m_biosB0[index]) (*this.*m_biosB0[index])();
        return !!m_biosB0[index];
    }
    bool callC0(unsigned index) final {
        if (m_biosC0[index]) (*this.*m_biosC0[index])();
        return !!m_biosC0[index];
    }

#include "sjisfont.h"

    void psxBiosInit() final {
        uint32_t *ptr;
        int i;
        uLongf len;

        for (i = 0; i < 256; i++) {
            m_biosA0[i] = &BiosImpl::psxBios_dummy;
            m_biosB0[i] = &BiosImpl::psxBios_dummy;
            m_biosC0[i] = &BiosImpl::psxBios_dummy;
        }

        m_biosA0[0x00] = &BiosImpl::psxBios_open;
        m_biosA0[0x01] = &BiosImpl::psxBios_lseek;
        m_biosA0[0x02] = &BiosImpl::psxBios_read;
        m_biosA0[0x03] = &BiosImpl::psxBios_write;
        m_biosA0[0x04] = &BiosImpl::psxBios_close;
        // m_biosA0[0x05] = &BiosImpl::psxBios_ioctl;
        // m_biosA0[0x06] = &BiosImpl::psxBios_exit;
        // m_biosA0[0x07] = &BiosImpl::psxBios_sys_a0_07;
        // m_biosA0[0x08] = &BiosImpl::psxBios_getc;
        // m_biosA0[0x09] = &BiosImpl::psxBios_putc;
        // m_biosA0[0x0a] = &BiosImpl::psxBios_todigit;
        // m_biosA0[0x0b] = &BiosImpl::psxBios_atof;
        // m_biosA0[0x0c] = &BiosImpl::psxBios_strtoul;
        // m_biosA0[0x0d] = &BiosImpl::psxBios_strtol;
        m_biosA0[0x0e] = &BiosImpl::psxBios_abs;
        m_biosA0[0x0f] = &BiosImpl::psxBios_labs;
        m_biosA0[0x10] = &BiosImpl::psxBios_atoi;
        m_biosA0[0x11] = &BiosImpl::psxBios_atol;
        // m_biosA0[0x12] = &BiosImpl::psxBios_atob;
        m_biosA0[0x13] = &BiosImpl::psxBios_setjmp;
        m_biosA0[0x14] = &BiosImpl::psxBios_longjmp;
        m_biosA0[0x15] = &BiosImpl::psxBios_strcat;
        m_biosA0[0x16] = &BiosImpl::psxBios_strncat;
        m_biosA0[0x17] = &BiosImpl::psxBios_strcmp;
        m_biosA0[0x18] = &BiosImpl::psxBios_strncmp;
        m_biosA0[0x19] = &BiosImpl::psxBios_strcpy;
        m_biosA0[0x1a] = &BiosImpl::psxBios_strncpy;
        m_biosA0[0x1b] = &BiosImpl::psxBios_strlen;
        m_biosA0[0x1c] = &BiosImpl::psxBios_index;
        m_biosA0[0x1d] = &BiosImpl::psxBios_rindex;
        m_biosA0[0x1e] = &BiosImpl::psxBios_strchr;
        m_biosA0[0x1f] = &BiosImpl::psxBios_strrchr;
        m_biosA0[0x20] = &BiosImpl::psxBios_strpbrk;
        m_biosA0[0x21] = &BiosImpl::psxBios_strspn;
        m_biosA0[0x22] = &BiosImpl::psxBios_strcspn;
        m_biosA0[0x23] = &BiosImpl::psxBios_strtok;
        m_biosA0[0x24] = &BiosImpl::psxBios_strstr;
        m_biosA0[0x25] = &BiosImpl::psxBios_toupper;
        m_biosA0[0x26] = &BiosImpl::psxBios_tolower;
        m_biosA0[0x27] = &BiosImpl::psxBios_bcopy;
        m_biosA0[0x28] = &BiosImpl::psxBios_bzero;
        m_biosA0[0x29] = &BiosImpl::psxBios_bcmp;
        m_biosA0[0x2a] = &BiosImpl::psxBios_memcpy;
        m_biosA0[0x2b] = &BiosImpl::psxBios_memset;
        m_biosA0[0x2c] = &BiosImpl::psxBios_memmove;
        m_biosA0[0x2d] = &BiosImpl::psxBios_memcmp;
        m_biosA0[0x2e] = &BiosImpl::psxBios_memchr;
        m_biosA0[0x2f] = &BiosImpl::psxBios_rand;
        m_biosA0[0x30] = &BiosImpl::psxBios_srand;
        m_biosA0[0x31] = &BiosImpl::psxBios_qsort;
        // m_biosA0[0x32] = &BiosImpl::psxBios_strtod;
        m_biosA0[0x33] = &BiosImpl::psxBios_malloc;
        m_biosA0[0x34] = &BiosImpl::psxBios_free;
        // m_biosA0[0x35] = &BiosImpl::psxBios_lsearch;
        // m_biosA0[0x36] = &BiosImpl::psxBios_bsearch;
        m_biosA0[0x37] = &BiosImpl::psxBios_calloc;
        m_biosA0[0x38] = &BiosImpl::psxBios_realloc;
        m_biosA0[0x39] = &BiosImpl::psxBios_InitHeap;
        // m_biosA0[0x3a] = &BiosImpl::psxBios__exit;
        m_biosA0[0x3b] = &BiosImpl::psxBios_getchar;
        m_biosA0[0x3c] = &BiosImpl::psxBios_putchar;
        // m_biosA0[0x3d] = &BiosImpl::psxBios_gets;
        m_biosA0[0x3e] = &BiosImpl::psxBios_puts;
        m_biosA0[0x3f] = &BiosImpl::psxBios_printf;
        // m_biosA0[0x40] = &BiosImpl::psxBios_sys_a0_40;
        // m_biosA0[0x41] = &BiosImpl::psxBios_LoadTest;
        m_biosA0[0x42] = &BiosImpl::psxBios_Load;
        m_biosA0[0x43] = &BiosImpl::psxBios_Exec;
        m_biosA0[0x44] = &BiosImpl::psxBios_FlushCache;
        // m_biosA0[0x45] = &BiosImpl::psxBios_InstallInterruptHandler;
        m_biosA0[0x46] = &BiosImpl::psxBios_GPU_dw;
        m_biosA0[0x47] = &BiosImpl::psxBios_mem2vram;
        m_biosA0[0x48] = &BiosImpl::psxBios_SendGPU;
        m_biosA0[0x49] = &BiosImpl::psxBios_GPU_cw;
        m_biosA0[0x4a] = &BiosImpl::psxBios_GPU_cwb;
        m_biosA0[0x4b] = &BiosImpl::psxBios_GPU_SendPackets;
        m_biosA0[0x4c] = &BiosImpl::psxBios_sys_a0_4c;
        m_biosA0[0x4d] = &BiosImpl::psxBios_GPU_GetGPUStatus;
        // m_biosA0[0x4e] = &BiosImpl::psxBios_GPU_sync;
        // m_biosA0[0x4f] = &BiosImpl::psxBios_sys_a0_4f;
        // m_biosA0[0x50] = &BiosImpl::psxBios_sys_a0_50;
        m_biosA0[0x51] = &BiosImpl::psxBios_LoadExec;
        // m_biosA0[0x52] = &BiosImpl::psxBios_GetSysSp;
        // m_biosA0[0x53] = &BiosImpl::psxBios_sys_a0_53;
        // m_biosA0[0x54] = &BiosImpl::psxBios__96_init_a54;
        // m_biosA0[0x55] = &BiosImpl::psxBios__bu_init_a55;
        // m_biosA0[0x56] = &BiosImpl::psxBios__96_remove_a56;
        // m_biosA0[0x57] = &BiosImpl::psxBios_sys_a0_57;
        // m_biosA0[0x58] = &BiosImpl::psxBios_sys_a0_58;
        // m_biosA0[0x59] = &BiosImpl::psxBios_sys_a0_59;
        // m_biosA0[0x5a] = &BiosImpl::psxBios_sys_a0_5a;
        // m_biosA0[0x5b] = &BiosImpl::psxBios_dev_tty_init;
        // m_biosA0[0x5c] = &BiosImpl::psxBios_dev_tty_open;
        // m_biosA0[0x5d] = &BiosImpl::psxBios_sys_a0_5d;
        // m_biosA0[0x5e] = &BiosImpl::psxBios_dev_tty_ioctl;
        // m_biosA0[0x5f] = &BiosImpl::psxBios_dev_cd_open;
        // m_biosA0[0x60] = &BiosImpl::psxBios_dev_cd_read;
        // m_biosA0[0x61] = &BiosImpl::psxBios_dev_cd_close;
        // m_biosA0[0x62] = &BiosImpl::psxBios_dev_cd_firstfile;
        // m_biosA0[0x63] = &BiosImpl::psxBios_dev_cd_nextfile;
        // m_biosA0[0x64] = &BiosImpl::psxBios_dev_cd_chdir;
        // m_biosA0[0x65] = &BiosImpl::psxBios_dev_card_open;
        // m_biosA0[0x66] = &BiosImpl::psxBios_dev_card_read;
        // m_biosA0[0x67] = &BiosImpl::psxBios_dev_card_write;
        // m_biosA0[0x68] = &BiosImpl::psxBios_dev_card_close;
        // m_biosA0[0x69] = &BiosImpl::psxBios_dev_card_firstfile;
        // m_biosA0[0x6a] = &BiosImpl::psxBios_dev_card_nextfile;
        // m_biosA0[0x6b] = &BiosImpl::psxBios_dev_card_erase;
        // m_biosA0[0x6c] = &BiosImpl::psxBios_dev_card_undelete;
        // m_biosA0[0x6d] = &BiosImpl::psxBios_dev_card_format;
        // m_biosA0[0x6e] = &BiosImpl::psxBios_dev_card_rename;
        // m_biosA0[0x6f] = &BiosImpl::psxBios_dev_card_6f;
        m_biosA0[0x70] = &BiosImpl::psxBios__bu_init;
        m_biosA0[0x71] = &BiosImpl::psxBios__96_init;
        m_biosA0[0x72] = &BiosImpl::psxBios__96_remove;
        // m_biosA0[0x73] = &BiosImpl::psxBios_sys_a0_73;
        // m_biosA0[0x74] = &BiosImpl::psxBios_sys_a0_74;
        // m_biosA0[0x75] = &BiosImpl::psxBios_sys_a0_75;
        // m_biosA0[0x76] = &BiosImpl::psxBios_sys_a0_76;
        // m_biosA0[0x77] = &BiosImpl::psxBios_sys_a0_77;
        // m_biosA0[0x78] = &BiosImpl::psxBios__96_CdSeekL;
        // m_biosA0[0x79] = &BiosImpl::psxBios_sys_a0_79;
        // m_biosA0[0x7a] = &BiosImpl::psxBios_sys_a0_7a;
        // m_biosA0[0x7b] = &BiosImpl::psxBios_sys_a0_7b;
        // m_biosA0[0x7c] = &BiosImpl::psxBios__96_CdGetStatus;
        // m_biosA0[0x7d] = &BiosImpl::psxBios_sys_a0_7d;
        // m_biosA0[0x7e] = &BiosImpl::psxBios__96_CdRead;
        // m_biosA0[0x7f] = &BiosImpl::psxBios_sys_a0_7f;
        // m_biosA0[0x80] = &BiosImpl::psxBios_sys_a0_80;
        // m_biosA0[0x81] = &BiosImpl::psxBios_sys_a0_81;
        // m_biosA0[0x82] = &BiosImpl::psxBios_sys_a0_82;
        // m_biosA0[0x83] = &BiosImpl::psxBios_sys_a0_83;
        // m_biosA0[0x84] = &BiosImpl::psxBios_sys_a0_84;
        // m_biosA0[0x85] = &BiosImpl::psxBios__96_CdStop;
        // m_biosA0[0x86] = &BiosImpl::psxBios_sys_a0_86;
        // m_biosA0[0x87] = &BiosImpl::psxBios_sys_a0_87;
        // m_biosA0[0x88] = &BiosImpl::psxBios_sys_a0_88;
        // m_biosA0[0x89] = &BiosImpl::psxBios_sys_a0_89;
        // m_biosA0[0x8a] = &BiosImpl::psxBios_sys_a0_8a;
        // m_biosA0[0x8b] = &BiosImpl::psxBios_sys_a0_8b;
        // m_biosA0[0x8c] = &BiosImpl::psxBios_sys_a0_8c;
        // m_biosA0[0x8d] = &BiosImpl::psxBios_sys_a0_8d;
        // m_biosA0[0x8e] = &BiosImpl::psxBios_sys_a0_8e;
        // m_biosA0[0x8f] = &BiosImpl::psxBios_sys_a0_8f;
        // m_biosA0[0x90] = &BiosImpl::psxBios_sys_a0_90;
        // m_biosA0[0x91] = &BiosImpl::psxBios_sys_a0_91;
        // m_biosA0[0x92] = &BiosImpl::psxBios_sys_a0_92;
        // m_biosA0[0x93] = &BiosImpl::psxBios_sys_a0_93;
        // m_biosA0[0x94] = &BiosImpl::psxBios_sys_a0_94;
        // m_biosA0[0x95] = &BiosImpl::psxBios_sys_a0_95;
        // m_biosA0[0x96] = &BiosImpl::psxBios_AddCDROMDevice;
        // m_biosA0[0x97] = &BiosImpl::psxBios_AddMemCardDevide;
        // m_biosA0[0x98] = &BiosImpl::psxBios_DisableKernelIORedirection;
        // m_biosA0[0x99] = &BiosImpl::psxBios_EnableKernelIORedirection;
        // m_biosA0[0x9a] = &BiosImpl::psxBios_sys_a0_9a;
        // m_biosA0[0x9b] = &BiosImpl::psxBios_sys_a0_9b;
        // m_biosA0[0x9c] = &BiosImpl::psxBios_SetConf;
        // m_biosA0[0x9d] = &BiosImpl::psxBios_GetConf;
        // m_biosA0[0x9e] = &BiosImpl::psxBios_sys_a0_9e;
        m_biosA0[0x9f] = &BiosImpl::psxBios_SetMem;
        // m_biosA0[0xa0] = &BiosImpl::psxBios__boot;
        // m_biosA0[0xa1] = &BiosImpl::psxBios_SystemError;
        // m_biosA0[0xa2] = &BiosImpl::psxBios_EnqueueCdIntr;
        // m_biosA0[0xa3] = &BiosImpl::psxBios_DequeueCdIntr;
        // m_biosA0[0xa4] = &BiosImpl::psxBios_sys_a0_a4;
        // m_biosA0[0xa5] = &BiosImpl::psxBios_ReadSector;
        // m_biosA0[0xa6] = &BiosImpl::psxBios_get_cd_status;
        // m_biosA0[0xa7] = &BiosImpl::psxBios_bufs_cb_0;
        // m_biosA0[0xa8] = &BiosImpl::psxBios_bufs_cb_1;
        // m_biosA0[0xa9] = &BiosImpl::psxBios_bufs_cb_2;
        // m_biosA0[0xaa] = &BiosImpl::psxBios_bufs_cb_3;
        m_biosA0[0xab] = &BiosImpl::psxBios__card_info;
        m_biosA0[0xac] = &BiosImpl::psxBios__card_load;
        // m_biosA0[0axd] = &BiosImpl::psxBios__card_auto;
        // m_biosA0[0xae] = &BiosImpl::psxBios_bufs_cd_4;
        // m_biosA0[0xaf] = &BiosImpl::psxBios_sys_a0_af;
        // m_biosA0[0xb0] = &BiosImpl::psxBios_sys_a0_b0;
        // m_biosA0[0xb1] = &BiosImpl::psxBios_sys_a0_b1;
        // m_biosA0[0xb2] = &BiosImpl::psxBios_do_a_long_jmp
        // m_biosA0[0xb3] = &BiosImpl::psxBios_sys_a0_b3;
        // m_biosA0[0xb4] = &BiosImpl::psxBios_sub_function;
        //*******************B0 CALLS****************************
        // m_biosB0[0x00] = &BiosImpl::psxBios_SysMalloc;
        // m_biosB0[0x01] = &BiosImpl::psxBios_sys_b0_01;
        m_biosB0[0x02] = &BiosImpl::psxBios_SetRCnt;
        m_biosB0[0x03] = &BiosImpl::psxBios_GetRCnt;
        m_biosB0[0x04] = &BiosImpl::psxBios_StartRCnt;
        m_biosB0[0x05] = &BiosImpl::psxBios_StopRCnt;
        m_biosB0[0x06] = &BiosImpl::psxBios_ResetRCnt;
        m_biosB0[0x07] = &BiosImpl::psxBios_DeliverEvent;
        m_biosB0[0x08] = &BiosImpl::psxBios_OpenEvent;
        m_biosB0[0x09] = &BiosImpl::psxBios_CloseEvent;
        m_biosB0[0x0a] = &BiosImpl::psxBios_WaitEvent;
        m_biosB0[0x0b] = &BiosImpl::psxBios_TestEvent;
        m_biosB0[0x0c] = &BiosImpl::psxBios_EnableEvent;
        m_biosB0[0x0d] = &BiosImpl::psxBios_DisableEvent;
        m_biosB0[0x0e] = &BiosImpl::psxBios_OpenTh;
        m_biosB0[0x0f] = &BiosImpl::psxBios_CloseTh;
        m_biosB0[0x10] = &BiosImpl::psxBios_ChangeTh;
        // m_biosB0[0x11] = &BiosImpl::psxBios_&BiosImpl::psxBios_b0_11;
        m_biosB0[0x12] = &BiosImpl::psxBios_InitPAD;
        m_biosB0[0x13] = &BiosImpl::psxBios_StartPAD;
        m_biosB0[0x14] = &BiosImpl::psxBios_StopPAD;
        m_biosB0[0x15] = &BiosImpl::psxBios_PAD_init;
        m_biosB0[0x16] = &BiosImpl::psxBios_PAD_dr;
        m_biosB0[0x17] = &BiosImpl::psxBios_ReturnFromException;
        m_biosB0[0x18] = &BiosImpl::psxBios_ResetEntryInt;
        m_biosB0[0x19] = &BiosImpl::psxBios_HookEntryInt;
        // m_biosB0[0x1a] = &BiosImpl::psxBios_sys_b0_1a;
        // m_biosB0[0x1b] = &BiosImpl::psxBios_sys_b0_1b;
        // m_biosB0[0x1c] = &BiosImpl::psxBios_sys_b0_1c;
        // m_biosB0[0x1d] = &BiosImpl::psxBios_sys_b0_1d;
        // m_biosB0[0x1e] = &BiosImpl::psxBios_sys_b0_1e;
        // m_biosB0[0x1f] = &BiosImpl::psxBios_sys_b0_1f;
        m_biosB0[0x20] = &BiosImpl::psxBios_UnDeliverEvent;
        // m_biosB0[0x21] = &BiosImpl::psxBios_sys_b0_21;
        // m_biosB0[0x22] = &BiosImpl::psxBios_sys_b0_22;
        // m_biosB0[0x23] = &BiosImpl::psxBios_sys_b0_23;
        // m_biosB0[0x24] = &BiosImpl::psxBios_sys_b0_24;
        // m_biosB0[0x25] = &BiosImpl::psxBios_sys_b0_25;
        // m_biosB0[0x26] = &BiosImpl::psxBios_sys_b0_26;
        // m_biosB0[0x27] = &BiosImpl::psxBios_sys_b0_27;
        // m_biosB0[0x28] = &BiosImpl::psxBios_sys_b0_28;
        // m_biosB0[0x29] = &BiosImpl::psxBios_sys_b0_29;
        // m_biosB0[0x2a] = &BiosImpl::psxBios_sys_b0_2a;
        // m_biosB0[0x2b] = &BiosImpl::psxBios_sys_b0_2b;
        // m_biosB0[0x2c] = &BiosImpl::psxBios_sys_b0_2c;
        // m_biosB0[0x2d] = &BiosImpl::psxBios_sys_b0_2d;
        // m_biosB0[0x2e] = &BiosImpl::psxBios_sys_b0_2e;
        // m_biosB0[0x2f] = &BiosImpl::psxBios_sys_b0_2f;
        // m_biosB0[0x30] = &BiosImpl::psxBios_sys_b0_30;
        // m_biosB0[0x31] = &BiosImpl::psxBios_sys_b0_31;
        m_biosB0[0x32] = &BiosImpl::psxBios_open;
        m_biosB0[0x33] = &BiosImpl::psxBios_lseek;
        m_biosB0[0x34] = &BiosImpl::psxBios_read;
        m_biosB0[0x35] = &BiosImpl::psxBios_write;
        m_biosB0[0x36] = &BiosImpl::psxBios_close;
        // m_biosB0[0x37] = &BiosImpl::psxBios_ioctl;
        // m_biosB0[0x38] = &BiosImpl::psxBios_exit;
        // m_biosB0[0x39] = &BiosImpl::psxBios_sys_b0_39;
        // m_biosB0[0x3a] = &BiosImpl::psxBios_getc;
        // m_biosB0[0x3b] = &BiosImpl::psxBios_putc;
        m_biosB0[0x3c] = &BiosImpl::psxBios_getchar;
        m_biosB0[0x3d] = &BiosImpl::psxBios_putchar;
        // m_biosB0[0x3e] = &BiosImpl::psxBios_gets;
        m_biosB0[0x3f] = &BiosImpl::psxBios_puts;
        // m_biosB0[0x40] = &BiosImpl::psxBios_cd;
        m_biosB0[0x41] = &BiosImpl::psxBios_format;
        m_biosB0[0x42] = &BiosImpl::psxBios_firstfile;
        m_biosB0[0x43] = &BiosImpl::psxBios_nextfile;
        m_biosB0[0x44] = &BiosImpl::psxBios_rename;
        m_biosB0[0x45] = &BiosImpl::psxBios_delete;
        // m_biosB0[0x46] = &BiosImpl::psxBios_undelete;
        // m_biosB0[0x47] = &BiosImpl::psxBios_AddDevice;
        // m_biosB0[0x48] = &BiosImpl::psxBios_RemoteDevice;
        // m_biosB0[0x49] = &BiosImpl::psxBios_PrintInstalledDevices;
        m_biosB0[0x4a] = &BiosImpl::psxBios_InitCARD;
        m_biosB0[0x4b] = &BiosImpl::psxBios_StartCARD;
        m_biosB0[0x4c] = &BiosImpl::psxBios_StopCARD;
        // m_biosB0[0x4d] = &BiosImpl::psxBios_sys_b0_4d;
        m_biosB0[0x4e] = &BiosImpl::psxBios__card_write;
        m_biosB0[0x4f] = &BiosImpl::psxBios__card_read;
        m_biosB0[0x50] = &BiosImpl::psxBios__new_card;
        m_biosB0[0x51] = &BiosImpl::psxBios_Krom2RawAdd;
        // m_biosB0[0x52] = &BiosImpl::psxBios_sys_b0_52;
        // m_biosB0[0x53] = &BiosImpl::psxBios_sys_b0_53;
        // m_biosB0[0x54] = &BiosImpl::psxBios__get_errno;
        m_biosB0[0x55] = &BiosImpl::psxBios__get_error;
        m_biosB0[0x56] = &BiosImpl::psxBios_GetC0Table;
        m_biosB0[0x57] = &BiosImpl::psxBios_GetB0Table;
        m_biosB0[0x58] = &BiosImpl::psxBios__card_chan;
        // m_biosB0[0x59] = &BiosImpl::psxBios_sys_b0_59;
        // m_biosB0[0x5a] = &BiosImpl::psxBios_sys_b0_5a;
        m_biosB0[0x5b] = &BiosImpl::psxBios_ChangeClearPad;
        m_biosB0[0x5c] = &BiosImpl::psxBios__card_status;
        // m_biosB0[0x5d] = &BiosImpl::psxBios__card_wait;
        //*******************C0 CALLS****************************
        // m_biosC0[0x00] = &BiosImpl::psxBios_InitRCnt;
        // m_biosC0[0x01] = &BiosImpl::psxBios_InitException;
        m_biosC0[0x02] = &BiosImpl::psxBios_SysEnqIntRP;
        m_biosC0[0x03] = &BiosImpl::psxBios_SysDeqIntRP;
        // m_biosC0[0x04] = &BiosImpl::psxBios_get_free_EvCB_slot;
        // m_biosC0[0x05] = &BiosImpl::psxBios_get_free_TCB_slot;
        // m_biosC0[0x06] = &BiosImpl::psxBios_ExceptionHandler;
        // m_biosC0[0x07] = &BiosImpl::psxBios_InstallExeptionHandler;
        // m_biosC0[0x08] = &BiosImpl::psxBios_SysInitMemory;
        // m_biosC0[0x09] = &BiosImpl::psxBios_SysInitKMem;
        m_biosC0[0x0a] = &BiosImpl::psxBios_ChangeClearRCnt;
        // m_biosC0[0x0b] = &BiosImpl::psxBios_SystemError;
        // m_biosC0[0x0c] = &BiosImpl::psxBios_InitDefInt;
        // m_biosC0[0x0d] = &BiosImpl::psxBios_sys_c0_0d;
        // m_biosC0[0x0e] = &BiosImpl::psxBios_sys_c0_0e;
        // m_biosC0[0x0f] = &BiosImpl::psxBios_sys_c0_0f;
        // m_biosC0[0x10] = &BiosImpl::psxBios_sys_c0_10;
        // m_biosC0[0x11] = &BiosImpl::psxBios_sys_c0_11;
        // m_biosC0[0x12] = &BiosImpl::psxBios_InstallDevices;
        // m_biosC0[0x13] = &BiosImpl::psxBios_FlushStfInOutPut;
        // m_biosC0[0x14] = &BiosImpl::psxBios_sys_c0_14;
        // m_biosC0[0x15] = &BiosImpl::psxBios__cdevinput;
        // m_biosC0[0x16] = &BiosImpl::psxBios__cdevscan;
        // m_biosC0[0x17] = &BiosImpl::psxBios__circgetc;
        // m_biosC0[0x18] = &BiosImpl::psxBios__circputc;
        // m_biosC0[0x19] = &BiosImpl::psxBios_ioabort;
        // m_biosC0[0x1a] = &BiosImpl::psxBios_sys_c0_1a
        // m_biosC0[0x1b] = &BiosImpl::psxBios_KernelRedirect;
        // m_biosC0[0x1c] = &BiosImpl::psxBios_PatchAOTable;
        //************** THE END ***************************************
        /**/
        ptr = (uint32_t *)&PCSX::g_emulator.m_psxMem->g_psxM[0x0874];  // b0 table
        ptr[0] = SWAP_LEu32(0x4c54 - 0x884);

        ptr = (uint32_t *)&PCSX::g_emulator.m_psxMem->g_psxM[0x0674];  // c0 table
        ptr[6] = SWAP_LEu32(0xc80);

        memset(s_SysIntRP, 0, sizeof(s_SysIntRP));
        memset(s_Thread, 0, sizeof(s_Thread));
        s_Thread[0].status = 2;  // main thread

        s_jmp_int = NULL;
        s_pad_buf = NULL;
        s_pad_buf1 = NULL;
        s_pad_buf2 = NULL;
        s_pad_buf1len = s_pad_buf2len = 0;
        s_heap_addr = NULL;
        s_heap_end = NULL;
        s_CardState = -1;
        s_CurThread = 0;
        memset(s_FDesc, 0, sizeof(s_FDesc));
        s_card_active_chan = 0;

        psxMu32ref(0x0150) = SWAP_LEu32(0x160);
        psxMu32ref(0x0154) = SWAP_LEu32(0x320);
        psxMu32ref(0x0160) = SWAP_LEu32(0x248);
        strcpy((char *)&PCSX::g_emulator.m_psxMem->g_psxM[0x248], "bu");
        /*  psxMu32ref(0x0ca8) = SWAP_LEu32(0x1f410004);
                psxMu32ref(0x0cf0) = SWAP_LEu32(0x3c020000);
                psxMu32ref(0x0cf4) = SWAP_LEu32(0x2442641c);
                psxMu32ref(0x09e0) = SWAP_LEu32(0x43d0);
                psxMu32ref(0x4d98) = SWAP_LEu32(0x946f000a);
        */
        // opcode HLE
        // Each are prepended with a nop to ensure any potential delayed load will be completed.
        // They will each change PC directly, either by returning to ra, or by returning to EPC.
        // ??
        psxMu32ref(0x0000) = 0;
        psxMu32ref(0x0004) = SWAP_LEu32((0x3b << 26) | 0);
        // exception handler
        psxMu32ref(0x0080) = SWAP_LEu32(0x3c1a0000);  // lui   $k0, 0x0000
        psxMu32ref(0x0084) = SWAP_LEu32(0x275a0090);  // addiu $k0, 0x0090
        psxMu32ref(0x0088) = SWAP_LEu32(0x03400008);  // jr    $k0
        psxMu32ref(0x008c) = SWAP_LEu32(0x275a0008);  // addiu $k0, 0x0008
        psxMu32ref(0x0090) = SWAP_LEu32(0x03400008);  // jr    $k0
        psxMu32ref(0x0094) = SWAP_LEu32((0x3b << 26) | 6);
        // a0 calls handler
        psxMu32ref(0x00a0) = 0;
        psxMu32ref(0x00a4) = SWAP_LEu32((0x3b << 26) | 1);
        // b0 calls handler
        psxMu32ref(0x00b0) = 0;
        psxMu32ref(0x00b4) = SWAP_LEu32((0x3b << 26) | 2);
        // c0 calls handler
        psxMu32ref(0x00c0) = 0;
        psxMu32ref(0x00c4) = SWAP_LEu32((0x3b << 26) | 3);
        // ??
        psxMu32ref(0x4c54) = 0;
        psxMu32ref(0x4c58) = SWAP_LEu32((0x3b << 26) | 0);
        // Exec return (a0 call 43)
        psxMu32ref(0x8000) = 0;
        psxMu32ref(0x8004) = SWAP_LEu32((0x3b << 26) | 5);
        // ??
        psxMu32ref(0x07a0) = 0;
        psxMu32ref(0x07a4) = SWAP_LEu32((0x3b << 26) | 0);
        // ??
        psxMu32ref(0x0884) = 0;
        psxMu32ref(0x0888) = SWAP_LEu32((0x3b << 26) | 0);
        // ??
        psxMu32ref(0x0894) = 0;
        psxMu32ref(0x0898) = SWAP_LEu32((0x3b << 26) | 0);

        // initial stack pointer for BIOS interrupt
        psxMu32ref(0x6c80) = SWAP_LEu32(0x000085c8);

        // initial RNG seed
        psxMu32ref(0x9010) = SWAP_LEu32(0xac20cc00);

        // memory size 2 MB
        psxHu32ref(0x1060) = SWAP_LEu32(0x00000b88);

        m_hleSoftCall = false;

        uint32_t base = 0x1000;
        uint32_t size = sizeof(EvCB) * 32;
        s_Event = reinterpret_cast<EvCB *>(&PCSX::g_emulator.m_psxMem->g_psxR[base]);
        s_HwEV = s_Event;
        s_EvEV = s_Event + 32;
        s_RcEV = s_Event + 32 * 2;
        s_UeEV = s_Event + 32 * 3;
        s_SwEV = s_Event + 32 * 4;
        s_ThEV = s_Event + 32 * 5;
        // All the above is done in the emulated RAM, in the emulator's state, or in the hardware registers.
        // Anything below here is done by touching the ROM section. Therefore, if the real BIOS has been loaded,
        // let's not poke into it. A better method might be to do this inconditionally, THEN load the BIOS, if
        // specified.
        // In all cases, this ensures that savestates are going to be consistent.
        if (m_realBiosLoaded) return;
        memset(s_Event, 0, size * 6);

        // bootstrap
        psxRu32ref(0x0000) = 0;
        psxRu32ref(0x0004) = SWAP_LEu32((0x3b << 26) | 4);
        // exception handler
        psxRu32ref(0x0180) = 0;
        psxRu32ref(0x0184) = SWAP_LEu32((0x3b << 26) | 6);
        // fonts
        len = 0x80000 - 0x66000;
        uncompress((Bytef *)(PCSX::g_emulator.m_psxMem->g_psxR + 0x66000), &len, font_8140, sizeof(font_8140));
        len = 0x80000 - 0x69d68;
        uncompress((Bytef *)(PCSX::g_emulator.m_psxMem->g_psxR + 0x69d68), &len, font_889f, sizeof(font_889f));
    }

    void psxBiosShutdown() final {}

#define psxBios_PADpoll(pad)                                            \
    {                                                                   \
        PCSX::g_emulator.m_pad##pad->startPoll();                       \
        s_pad_buf##pad[0] = 0;                                          \
        s_pad_buf##pad[1] = PCSX::g_emulator.m_pad##pad->poll(0x42);    \
        if (!(s_pad_buf##pad[1] & 0x0f)) {                              \
            bufcount = 32;                                              \
        } else {                                                        \
            bufcount = (s_pad_buf##pad[1] & 0x0f) * 2;                  \
        }                                                               \
        PCSX::g_emulator.m_pad##pad->poll(0);                           \
        i = 2;                                                          \
        while (bufcount--) {                                            \
            s_pad_buf##pad[i++] = PCSX::g_emulator.m_pad##pad->poll(0); \
        }                                                               \
    }

    void biosInterrupt() {
        int i, bufcount;

        //  if (psxHu32(0x1070) & 0x1) { // Vsync
        if (s_pad_buf != NULL) {
            uint32_t *buf = (uint32_t *)s_pad_buf;

            PCSX::g_emulator.m_pad1->startPoll();
            if (PCSX::g_emulator.m_pad1->poll(0x42) == 0x23) {
                PCSX::g_emulator.m_pad1->poll(0);
                *buf = PCSX::g_emulator.m_pad1->poll(0) << 8;
                *buf |= PCSX::g_emulator.m_pad1->poll(0);
                PCSX::g_emulator.m_pad1->poll(0);
                *buf &= ~((PCSX::g_emulator.m_pad1->poll(0) > 0x20) ? 1 << 6 : 0);
                *buf &= ~((PCSX::g_emulator.m_pad1->poll(0) > 0x20) ? 1 << 7 : 0);
            } else {
                PCSX::g_emulator.m_pad1->poll(0);
                *buf = PCSX::g_emulator.m_pad1->poll(0) << 8;
                *buf |= PCSX::g_emulator.m_pad1->poll(0);
            }

            PCSX::g_emulator.m_pad2->startPoll();
            if (PCSX::g_emulator.m_pad2->poll(0x42) == 0x23) {
                PCSX::g_emulator.m_pad2->poll(0);
                *buf |= PCSX::g_emulator.m_pad2->poll(0) << 24;
                *buf |= PCSX::g_emulator.m_pad2->poll(0) << 16;
                PCSX::g_emulator.m_pad2->poll(0);
                *buf &= ~((PCSX::g_emulator.m_pad2->poll(0) > 0x20) ? 1 << 22 : 0);
                *buf &= ~((PCSX::g_emulator.m_pad2->poll(0) > 0x20) ? 1 << 23 : 0);
            } else {
                PCSX::g_emulator.m_pad2->poll(0);
                *buf |= PCSX::g_emulator.m_pad2->poll(0) << 24;
                *buf |= PCSX::g_emulator.m_pad2->poll(0) << 16;
            }
        }
        if (s_pad_buf1) {
            psxBios_PADpoll(1);
        }

        if (s_pad_buf2) {
            psxBios_PADpoll(2);
        }

        if (psxHu32(0x1070) & 0x1) {  // Vsync
            if (s_RcEV[3][1].status == EvStACTIVE) {
                softCall(s_RcEV[3][1].fhandler);
                //          hwWrite32(0x1f801070, ~(1));
            }
        }

        if (psxHu32(0x1070) & 0x70) {  // Rcnt 0,1,2
            int i;

            for (i = 0; i < 3; i++) {
                if (psxHu32(0x1070) & (1 << (i + 4))) {
                    if (s_RcEV[i][1].status == EvStACTIVE) {
                        softCall(s_RcEV[i][1].fhandler);
                    }
                    PCSX::g_emulator.m_hw->psxHwWrite32(0x1f801070, ~(1 << (i + 4)));
                }
            }
        }
    }

    void psxBiosException() final {
        int i;

        switch (PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.n.Cause & 0x3c) {
            case 0x00:  // Interrupt
                PSXCPU_LOG("interrupt\n");
                SaveRegs();

                sp = psxMu32(0x6c80);  // create new stack for interrupt handlers

                biosInterrupt();

                for (i = 0; i < 8; i++) {
                    if (s_SysIntRP[i]) {
                        uint32_t *queue = (uint32_t *)PSXM(s_SysIntRP[i]);

                        s0 = queue[2];
                        softCall(queue[1]);
                    }
                }

                if (s_jmp_int != NULL) {
                    int i;

                    PCSX::g_emulator.m_hw->psxHwWrite32(0x1f801070, 0xffffffff);

                    ra = s_jmp_int[0];
                    sp = s_jmp_int[1];
                    fp = s_jmp_int[2];
                    for (i = 0; i < 8; i++)  // s0-s7
                        PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[16 + i] = s_jmp_int[3 + i];
                    gp = s_jmp_int[11];

                    v0 = 1;
                    pc0 = ra;
                    return;
                }
                PCSX::g_emulator.m_hw->psxHwWrite16(0x1f801070, 0);
                break;

            case 0x20:  // Syscall
                PSXCPU_LOG("syscall exp %x\n", a0);
                switch (a0) {
                    case 1:  // EnterCritical - disable irq's
                        PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.n.Status &= ~0x404;
                        v0 = 1;  // HDHOSHY experimental patch: Spongebob, Coldblood, fearEffect, Medievil2, Martian
                                 // Gothic
                        break;

                    case 2:  // ExitCritical - enable irq's
                        PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.n.Status |= 0x404;
                        break;
                }
                pc0 = PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.n.EPC + 4;

                PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.n.Status =
                    (PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.n.Status & 0xfffffff0) |
                    ((PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.n.Status & 0x3c) >> 2);
                return;

            default:
                PSXCPU_LOG("unknown bios exception!\n");
                break;
        }

        pc0 = PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.n.EPC;
        if (PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.n.Cause & 0x80000000) pc0 += 4;

        PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.n.Status =
            (PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.n.Status & 0xfffffff0) |
            ((PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.n.Status & 0x3c) >> 2);
    }

    template <typename T>
    static uint32_t fromMemory(T *ptr) {
        if (ptr) {
            return reinterpret_cast<uint8_t *>(ptr) - PCSX::g_emulator.m_psxMem->g_psxM;
        } else {
            return 0;
        }
    }

    template <typename T>
    static T *toMemory(uint32_t val) {
        if (val) {
            return reinterpret_cast<T *>(PCSX::g_emulator.m_psxMem->g_psxM + val);
        } else {
            return nullptr;
        }
    }

    void save(PCSX::SaveStates::BiosHLE &state) {
        state.get<PCSX::SaveStates::BiosJmpInt>().value = fromMemory(s_jmp_int);
        state.get<PCSX::SaveStates::BiosPadBuf>().value = fromMemory(s_pad_buf);
        state.get<PCSX::SaveStates::BiosPadBuf1>().value = fromMemory(s_pad_buf1);
        state.get<PCSX::SaveStates::BiosPadBuf2>().value = fromMemory(s_pad_buf2);
        state.get<PCSX::SaveStates::BiosHeapAddr>().value = fromMemory(s_heap_addr);
        state.get<PCSX::SaveStates::BiosPadBuf1Len>().value = s_pad_buf1len;
        state.get<PCSX::SaveStates::BiosPadBuf2Len>().value = s_pad_buf2len;
        for (unsigned i = 0; i < 35; i++) {
            state.get<PCSX::SaveStates::BiosRegs>().value[i].value = s_regs[i];
        }
        for (unsigned i = 0; i < 8; i++) {
            state.get<PCSX::SaveStates::BiosSysIntRP>().value[i].value = s_SysIntRP[i];
        }
        state.get<PCSX::SaveStates::BiosCardState>().value = s_CardState;
        for (unsigned i = 0; i < 8; i++) {
            auto &thread = state.get<PCSX::SaveStates::BiosThreads>().value[i];
            thread.get<PCSX::SaveStates::BiosTCBStatus>().value = s_Thread[i].status;
            thread.get<PCSX::SaveStates::BiosTCBMode>().value = s_Thread[i].mode;
            for (unsigned j = 0; j < 32; j++) {
                thread.get<PCSX::SaveStates::BiosTCBReg>().value[j].value = s_Thread[i].reg[j];
            }
            thread.get<PCSX::SaveStates::BiosTCBFunc>().value = s_Thread[i].func;
        }
        state.get<PCSX::SaveStates::BiosCurThread>().value = s_CurThread;
        for (unsigned int i = 0; i < 32; i++) {
            auto &fd = state.get<PCSX::SaveStates::BiosFDescs>().value[i];
            fd.get<PCSX::SaveStates::BiosFDName>().value = s_FDesc[i].name;
            fd.get<PCSX::SaveStates::BiosFDMode>().value = s_FDesc[i].mode;
            fd.get<PCSX::SaveStates::BiosFDOffset>().value = s_FDesc[i].offset;
            fd.get<PCSX::SaveStates::BiosFDSize>().value = s_FDesc[i].size;
            fd.get<PCSX::SaveStates::BiosFDMCFile>().value = s_FDesc[i].mcfile;
        }
        state.get<PCSX::SaveStates::BiosCardActiveChan>().value = s_card_active_chan;
    }

    void load(const PCSX::SaveStates::BiosHLE &state) {
        s_jmp_int = toMemory<uint32_t>(state.get<PCSX::SaveStates::BiosJmpInt>().value);
        s_pad_buf = toMemory<int>(state.get<PCSX::SaveStates::BiosPadBuf>().value);
        s_pad_buf1 = toMemory<char>(state.get<PCSX::SaveStates::BiosPadBuf1>().value);
        s_pad_buf2 = toMemory<char>(state.get<PCSX::SaveStates::BiosPadBuf2>().value);
        s_heap_addr = toMemory<uint32_t>(state.get<PCSX::SaveStates::BiosHeapAddr>().value);
        s_pad_buf1len = state.get<PCSX::SaveStates::BiosPadBuf1Len>().value;
        s_pad_buf2len = state.get<PCSX::SaveStates::BiosPadBuf2Len>().value;
        for (unsigned i = 0; i < 35; i++) {
            s_regs[i] = state.get<PCSX::SaveStates::BiosRegs>().value[i].value;
        }
        for (unsigned i = 0; i < 8; i++) {
            s_SysIntRP[i] = state.get<PCSX::SaveStates::BiosSysIntRP>().value[i].value;
        }
        s_CardState = state.get<PCSX::SaveStates::BiosCardState>().value;
        for (unsigned i = 0; i < 8; i++) {
            const auto &thread = state.get<PCSX::SaveStates::BiosThreads>().value[i];
            s_Thread[i].status = thread.get<PCSX::SaveStates::BiosTCBStatus>().value;
            s_Thread[i].mode = thread.get<PCSX::SaveStates::BiosTCBMode>().value;
            for (unsigned j = 0; j < 32; j++) {
                s_Thread[i].reg[j] = thread.get<PCSX::SaveStates::BiosTCBReg>().value[j].value;
            }
            s_Thread[i].func = thread.get<PCSX::SaveStates::BiosTCBFunc>().value;
        }
        s_CurThread = state.get<PCSX::SaveStates::BiosCurThread>().value;
        for (unsigned int i = 0; i < 32; i++) {
            const auto &fd = state.get<PCSX::SaveStates::BiosFDescs>().value[i];
            std::strncpy(s_FDesc[i].name, fd.get<PCSX::SaveStates::BiosFDName>().value.c_str(), 32);
            s_FDesc[i].mode = fd.get<PCSX::SaveStates::BiosFDMode>().value;
            s_FDesc[i].offset = fd.get<PCSX::SaveStates::BiosFDOffset>().value;
            s_FDesc[i].size = fd.get<PCSX::SaveStates::BiosFDSize>().value;
            s_FDesc[i].mcfile = fd.get<PCSX::SaveStates::BiosFDMCFile>().value;
        }
        s_card_active_chan = state.get<PCSX::SaveStates::BiosCardActiveChan>().value;
    }
};

PCSX::Bios *PCSX::Bios::factory() { return new BiosImpl(); }
