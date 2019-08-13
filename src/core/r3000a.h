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

#pragma once

#include <memory>

#include "core/psxbios.h"
#include "core/psxcounters.h"
#include "core/psxemulator.h"
#include "core/psxhle.h"
#include "core/psxmem.h"

namespace PCSX {

typedef union {
#if defined(__BIGENDIAN__)
    struct {
        uint8_t h3, h2, h, l;
    } b;
    struct {
        int8_t h3, h2, h, l;
    } sb;
    struct {
        uint16_t h, l;
    } w;
    struct {
        int16_t h, l;
    } sw;
#else
    struct {
        uint8_t l, h, h2, h3;
    } b;
    struct {
        uint16_t l, h;
    } w;
    struct {
        int8_t l, h, h2, h3;
    } sb;
    struct {
        int16_t l, h;
    } sw;
#endif
    uint32_t d;
    int32_t sd;
} PAIR;

typedef union {
    struct {
        uint32_t r0, at, v0, v1, a0, a1, a2, a3;
        uint32_t t0, t1, t2, t3, t4, t5, t6, t7;
        uint32_t s0, s1, s2, s3, s4, s5, s6, s7;
        uint32_t t8, t9, k0, k1, gp, sp, s8, ra;
        uint32_t lo, hi;
    } n;
    uint32_t r[34]; /* Lo, Hi in r[32] and r[33] */
    PAIR p[34];
} psxGPRRegs;

typedef union {
    struct {
        uint32_t Index, Random, EntryLo0, BPC, Context, BDA, PIDMask, DCIC;
        uint32_t BadVAddr, BDAM, EntryHi, BPCM, Status, Cause, EPC, PRid;
        uint32_t Config, LLAddr, WatchLO, WatchHI, XContext, Reserved1, Reserved2, Reserved3;
        uint32_t Reserved4, Reserved5, ECC, CacheErr, TagLo, TagHi, ErrorEPC, Reserved6;
    } n;
    uint32_t r[32];
} psxCP0Regs;

typedef struct {
    int16_t x, y;
} SVector2D;

typedef struct {
    int16_t z, unused;
} SVector2Dz;

typedef struct {
    int16_t x, y, z, unused;
} SVector3D;

typedef struct {
    int16_t x, y, z, unused;
} LVector3D;

typedef struct {
    uint8_t r, g, b, c;
} CBGR;

typedef struct {
    int16_t m11, m12, m13, m21, m22, m23, m31, m32, m33, unused;
} SMatrix3D;

typedef union {
    struct {
        SVector3D v0, v1, v2;
        CBGR rgb;
        int32_t otz;
        int32_t ir0, ir1, ir2, ir3;
        SVector2D sxy0, sxy1, sxy2, sxyp;
        SVector2Dz sz0, sz1, sz2, sz3;
        CBGR rgb0, rgb1, rgb2;
        int32_t reserved;
        int32_t mac0, mac1, mac2, mac3;
        uint32_t irgb, orgb;
        int32_t lzcs, lzcr;
    } n;
    uint32_t r[32];
    PAIR p[32];
} psxCP2Data;

typedef union {
    struct {
        SMatrix3D rMatrix;
        int32_t trX, trY, trZ;
        SMatrix3D lMatrix;
        int32_t rbk, gbk, bbk;
        SMatrix3D cMatrix;
        int32_t rfc, gfc, bfc;
        int32_t ofx, ofy;
        int32_t h;
        int32_t dqa, dqb;
        int32_t zsf3, zsf4;
        int32_t flag;
    } n;
    uint32_t r[32];
    PAIR p[32];
} psxCP2Ctrl;

enum {
    PSXINT_SIO = 0,
    PSXINT_CDR,
    PSXINT_CDREAD,
    PSXINT_GPUDMA,
    PSXINT_MDECOUTDMA,
    PSXINT_SPUDMA,
    PSXINT_GPUBUSY,
    PSXINT_MDECINDMA,
    PSXINT_GPUOTCDMA,
    PSXINT_CDRDMA,
    PSXINT_SPUASYNC,
    PSXINT_CDRDBUF,
    PSXINT_CDRLID,
    PSXINT_CDRPLAY
};

typedef struct {
    psxGPRRegs GPR;  /* General Purpose Registers */
    psxCP0Regs CP0;  /* Coprocessor0 Registers */
    psxCP2Data CP2D; /* Cop2 data registers */
    psxCP2Ctrl CP2C; /* Cop2 control registers */
    uint32_t pc;     /* Program counter */
    uint32_t code;   /* The instruction */
    uint32_t cycle;
    uint32_t interrupt;
    struct {
        uint32_t sCycle, cycle;
    } intCycle[32];
    uint8_t ICache_Addr[0x1000];
    uint8_t ICache_Code[0x1000];
    bool ICache_valid;
} psxRegisters;

// U64 and S64 are used to wrap long integer constants.
#define U64(val) val##ULL
#define S64(val) val##LL

#if defined(__BIGENDIAN__)

#define _i32(x) reinterpret_cast<int32_t *>(&x)[0]
#define _u32(x) reinterpret_cast<uint32_t *>(&x)[0]

#define _i16(x) reinterpret_cast<int16_t *>(&x)[1]
#define _u16(x) reinterpret_cast<uint16_t *>(&x)[1]

#define _i8(x) reinterpret_cast<int8_t *>(&x)[3]
#define _u8(x) reinterpret_cast<uint8_t *>(&x)[3]

#else

#define _i32(x) reinterpret_cast<int32_t *>(&x)[0]
#define _u32(x) reinterpret_cast<uint32_t *>(&x)[0]

#define _i16(x) reinterpret_cast<int16_t *>(&x)[0]
#define _u16(x) reinterpret_cast<uint16_t *>(&x)[0]

#define _i8(x) reinterpret_cast<int8_t *>(&x)[0]
#define _u8(x) reinterpret_cast<uint8_t *>(&x)[0]

#endif

/**** R3000A Instruction Macros ****/
#define _PC_ PCSX::g_emulator.m_psxCpu->m_psxRegs.pc  // The next PC to be executed

#define _fOp_(code) ((code >> 26))           // The opcode part of the instruction register
#define _fFunct_(code) ((code)&0x3F)         // The funct part of the instruction register
#define _fRd_(code) ((code >> 11) & 0x1F)    // The rd part of the instruction register
#define _fRt_(code) ((code >> 16) & 0x1F)    // The rt part of the instruction register
#define _fRs_(code) ((code >> 21) & 0x1F)    // The rs part of the instruction register
#define _fSa_(code) ((code >> 6) & 0x1F)     // The sa part of the instruction register
#define _fIm_(code) ((uint16_t)code)         // The immediate part of the instruction register
#define _fTarget_(code) (code & 0x03ffffff)  // The target part of the instruction register

#define _fImm_(code) ((int16_t)code)   // sign-extended immediate
#define _fImmU_(code) (code & 0xffff)  // zero-extended immediate
#define _fImmLU_(code) (code << 16)    // LUI

#define _Op_ _fOp_(PCSX::g_emulator.m_psxCpu->m_psxRegs.code)
#define _Funct_ _fFunct_(PCSX::g_emulator.m_psxCpu->m_psxRegs.code)
#define _Rd_ _fRd_(PCSX::g_emulator.m_psxCpu->m_psxRegs.code)
#define _Rt_ _fRt_(PCSX::g_emulator.m_psxCpu->m_psxRegs.code)
#define _Rs_ _fRs_(PCSX::g_emulator.m_psxCpu->m_psxRegs.code)
#define _Sa_ _fSa_(PCSX::g_emulator.m_psxCpu->m_psxRegs.code)
#define _Im_ _fIm_(PCSX::g_emulator.m_psxCpu->m_psxRegs.code)
#define _Target_ _fTarget_(PCSX::g_emulator.m_psxCpu->m_psxRegs.code)

#define _Imm_ _fImm_(PCSX::g_emulator.m_psxCpu->m_psxRegs.code)
#define _ImmU_ _fImmU_(PCSX::g_emulator.m_psxCpu->m_psxRegs.code)
#define _ImmLU_ _fImmLU_(PCSX::g_emulator.m_psxCpu->m_psxRegs.code)

#define _rRs_ PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rs_]  // Rs register
#define _rRt_ PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rt_]  // Rt register
#define _rRd_ PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Rd_]  // Rd register
#define _rSa_ PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[_Sa_]  // Sa register
#define _rFs_ PCSX::g_emulator.m_psxCpu->m_psxRegs.CP0.r[_Rd_]  // Fs register

#define _c2dRs_ PCSX::g_emulator.m_psxCpu->m_psxRegs.CP2D.r[_Rs_]  // Rs cop2 data register
#define _c2dRt_ PCSX::g_emulator.m_psxCpu->m_psxRegs.CP2D.r[_Rt_]  // Rt cop2 data register
#define _c2dRd_ PCSX::g_emulator.m_psxCpu->m_psxRegs.CP2D.r[_Rd_]  // Rd cop2 data register
#define _c2dSa_ PCSX::g_emulator.m_psxCpu->m_psxRegs.CP2D.r[_Sa_]  // Sa cop2 data register

#define _rHi_ PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.hi  // The HI register
#define _rLo_ PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.n.lo  // The LO register

#define _JumpTarget_ ((_Target_ * 4) + (_PC_ & 0xf0000000))  // Calculates the target during a jump instruction
#define _BranchTarget_ ((int16_t)_Im_ * 4 + _PC_)            // Calculates the target during a branch instruction

#define _SetLink(x) \
    PCSX::g_emulator.m_psxCpu->m_psxRegs.GPR.r[x] = _PC_ + 4  // Sets the return address in the link register

class R3000Acpu {
  public:
    R3000Acpu() {
        for (int s = 0; s < 3; s++) {
            for (int c = 0; c < 256; c++) {
                m_breakpoints[s][c] = false;
            }
        }
    }
    virtual ~R3000Acpu() {}
    virtual bool Init() { return false; }
    virtual void Execute() = 0;         /* executes up to a debug break */
    virtual void ExecuteHLEBlock() = 0; /* executes up to a jump, to run an HLE softcall;
                                           debug breaks won't happen until after the softcall */
    virtual void Clear(uint32_t Addr, uint32_t Size) = 0;
    virtual void Shutdown() = 0;
    virtual void SetPGXPMode(uint32_t pgxpMode) = 0;
    virtual bool Implemented() { return false; }

    const std::string &getName() { return m_name; }

  public:
    static int psxInit();
    void psxReset();
    void psxShutdown();
    void psxException(uint32_t code, bool bd);
    void psxBranchTest();

    void psxSetPGXPMode(uint32_t pgxpMode);

    psxRegisters m_psxRegs;
    bool m_booted = false;

    virtual void Reset() { m_psxRegs.ICache_valid = false; }
    bool m_nextIsDelaySlot = false;
    bool m_inDelaySlot = false;
    struct {
        uint32_t index = 0;
        uint32_t value = 0;
        uint32_t mask = 0;
        uint32_t pcValue = 0;
        bool active = false;
        bool pcActive = false;
    } m_delayedLoadInfo[2];
    unsigned m_currentDelayedLoad = 0;
    uint32_t &delayedLoadRef(unsigned reg, uint32_t mask = 0) {
        if (reg >= 32) abort();
        auto &delayedLoad = m_delayedLoadInfo[m_currentDelayedLoad];
        delayedLoad.active = true;
        delayedLoad.index = reg;
        delayedLoad.mask = mask;
        return delayedLoad.value;
    }
    void delayedLoad(unsigned reg, uint32_t value, uint32_t mask = 0) {
        auto &ref = delayedLoadRef(reg, mask);
        ref = value;
    }
    uint32_t &delayedPCLoad() {
        auto &delayedLoad = m_delayedLoadInfo[m_currentDelayedLoad];
        delayedLoad.pcActive = true;
        return delayedLoad.pcValue;
    }
    void delayedPCLoad(uint32_t value) {
        auto &ref = delayedPCLoad();
        ref = value;
    }

  protected:
    R3000Acpu(const std::string &name) : m_name(name) {}
    static inline const uint32_t g_LWL_MASK[4] = {0xffffff, 0xffff, 0xff, 0};
    static inline const uint32_t g_LWL_SHIFT[4] = {24, 16, 8, 0};
    static inline const uint32_t g_LWR_MASK[4] = {0, 0xff000000, 0xffff0000, 0xffffff00};
    static inline const uint32_t g_LWR_SHIFT[4] = {0, 8, 16, 24};
    static inline const uint32_t g_SWL_MASK[4] = {0xffffff00, 0xffff0000, 0xff000000, 0};
    static inline const uint32_t g_SWL_SHIFT[4] = {24, 16, 8, 0};
    static inline const uint32_t g_SWR_MASK[4] = {0, 0xff, 0xffff, 0xffffff};
    static inline const uint32_t g_SWR_SHIFT[4] = {0, 8, 16, 24};
    inline bool hasToRun() {
        if (!g_system->running()) return false;
        if (!m_booted) {
            uint32_t &pc = m_psxRegs.pc;
            if (pc == 0x80030000) {
                m_booted = true;
                if (g_emulator.settings.get<PCSX::Emulator::SettingFastBoot>()) pc = m_psxRegs.GPR.n.ra;
            }
        }
        return true;
    }
    inline void InterceptBIOS() {
        const uint32_t pc = m_psxRegs.pc & 0x1fffff;
        const uint32_t base = (m_psxRegs.pc >> 20) & 0xffc;
        if ((base != 0x000) && (base != 0x800) && (base != 0xa00)) return;
        const auto r = m_psxRegs.GPR.n;
        bool ignore = m_biosCounters;
        const uint32_t rabase = (r.ra >> 20) & 0xffc;
        const uint32_t ra = r.ra & 0x1fffff;
        if ((rabase != 0x000) && (rabase != 0x800) && (rabase != 0xa00)) ignore = true;
        if (ra < 0x10000) ignore = true;
        if (m_debugKernel) ignore = false;

        // Intercept printf, puts and putchar, even if running the binary bios.
        // The binary bios doesn't have the TTY output set up by default,
        // so this hack enables us to properly display printfs. Also,
        // sometimes, games will fully redirect printf's output, so it
        // will stop calling putchar.
        const uint32_t call = r.t1 & 0xff;
        if (pc == 0xa0) {
            if (!ignore) {
                if (m_breakpoints[0][call]) g_system->pause();
                if (m_savedCounters[0][call] == 0) {
                    if (m_breakpointOnNew) g_system->pause();
                    if (m_logNewSyscalls) {
                        const char *name = Bios::getA0name(call);
                        g_system->printf("Bios call a0: %s (%x) %x,%x,%x,%x\n", name, call, r.a0, r.a1, r.a2, r.a3);
                    }
                    m_counters[0][call]++;
                }
            }
            switch (call) {
                case 0x03:  // write
                    // stdout
                    if (r.a0 != 1) break;
                case 0x3e:  // puts
                case 0x3f:  // printf
                    PCSX::g_emulator.m_psxBios->callA0(call);
                    PCSX::g_emulator.m_psxCpu->psxBranchTest();
                    break;
            }
        }

        if (pc == 0xb0) {
            if (!ignore) {
                if (m_breakpoints[1][call]) g_system->pause();
                if (m_savedCounters[1][call] == 0) {
                    if (m_breakpointOnNew) g_system->pause();
                    if (m_logNewSyscalls) {
                        const char *name = Bios::getB0name(call);
                        g_system->printf("Bios call b0: %s (%x) %x,%x,%x,%x\n", name, call, r.a0, r.a1, r.a2, r.a3);
                    }
                }
                m_counters[1][call]++;
            }
            switch (call) {
                case 0x07:  // DeliverEvent
                case 0x08:  // OpenEvent
                case 0x09:  // CloseEvent
                case 0x0a:  // WaitEvent
                case 0x0b:  // TestEvent
                case 0x0c:  // EnableEvent
                case 0x0d:  // DisableEvent
                    if (m_logEvents) {
                        int ev = GetEv();
                        int spec = GetSpec();
                        g_system->printf("%s(0x%02x, 0x%02x)\n", Bios::getB0name(call), ev, spec);
                    }
                    break;
                case 0x35:  // write
                    // stdout
                    if (r.a0 != 1) break;
                case 0x3d:  // putchar
                case 0x3f:  // puts
                    PCSX::g_emulator.m_psxBios->callB0(call);
                    PCSX::g_emulator.m_psxCpu->psxBranchTest();
                    break;
            }
        }

        if (pc == 0xc0) {
            if (!ignore) {
                if (m_breakpoints[2][call]) g_system->pause();
                if (m_savedCounters[2][call] == 0) {
                    if (m_breakpointOnNew) g_system->pause();
                    if (m_logNewSyscalls) {
                        const char *name = Bios::getC0name(call);
                        g_system->printf("Bios call c0: %s (%x) %x,%x,%x,%x\n", name, call, r.a0, r.a1, r.a2, r.a3);
                    }
                }
                m_counters[2][call]++;
            }
        }
    }

  private:
    /* gets ev for use with s_Event */
    int GetEv() {
        const auto r = m_psxRegs.GPR.n;
        int ev = (r.a0 >> 24) & 0xf;
        if (ev == 0xf) ev = 0x5;
        ev *= 32;
        ev += r.a0 & 0x1f;
        return ev;
    }

    int GetSpec() {
        int spec = 0;
        const auto r = m_psxRegs.GPR.n;
        switch (r.a1) {
            case 0x0301:
                spec = 16;
                break;
            case 0x0302:
                spec = 17;
                break;
            default:
                for (int i = 0; i < 16; i++)
                    if (r.a1 & (1 << i)) {
                        spec = i;
                        break;
                    }
                break;
        }
        return spec;
    }
    uint64_t m_counters[3][256];
    uint64_t m_savedCounters[3][256];

  public:
    inline void memorizeCounters() {
        for (int i = 0; i < 3; i++) {
            memcpy(m_savedCounters[i], m_counters[i], 256 * sizeof(m_savedCounters[0][0]));
        }
    }
    inline void clearCounters() {
        for (int i = 0; i < 3; i++) {
            memset(m_counters[i], 0, 256 * sizeof(m_counters[0][0]));
        }
    }
    bool m_breakpoints[3][256];
    bool m_biosCounters = false;
    bool m_logNewSyscalls = false;
    bool m_breakpointOnNew = false;
    bool m_debugKernel = false;
    bool m_logEvents = false;
    const uint64_t *getCounters(int syscall) { return m_counters[syscall]; }
    /*
Formula One 2001
- Use old CPU cache code when the RAM location is
  updated with new code (affects in-game racing)

TODO:
- I-cache / D-cache swapping
- Isolate D-cache from RAM
*/

    inline uint32_t *Read_ICache(uint32_t pc, bool isolate) {
        uint32_t pc_bank, pc_offset, pc_cache;
        uint8_t *IAddr, *ICode;

        pc_bank = pc >> 24;
        pc_offset = pc & 0xffffff;
        pc_cache = pc & 0xfff;

        IAddr = m_psxRegs.ICache_Addr;
        ICode = m_psxRegs.ICache_Code;

        // clear I-cache
        if (!m_psxRegs.ICache_valid) {
            memset(m_psxRegs.ICache_Addr, 0xff, sizeof(m_psxRegs.ICache_Addr));
            memset(m_psxRegs.ICache_Code, 0xff, sizeof(m_psxRegs.ICache_Code));

            m_psxRegs.ICache_valid = true;
        }

        // uncached
        if (pc_bank >= 0xa0) return (uint32_t *)PSXM(pc);

        // cached - RAM
        if (pc_bank == 0x80 || pc_bank == 0x00) {
            if (SWAP_LE32(*(uint32_t *)(IAddr + pc_cache)) == pc_offset) {
                // Cache hit - return last opcode used
                return (uint32_t *)(ICode + pc_cache);
            } else {
                // Cache miss - addresses don't match
                // - default: 0xffffffff (not init)

                if (!isolate) {
                    // cache line is 4 bytes wide
                    pc_offset &= ~0xf;
                    pc_cache &= ~0xf;

                    // address line
                    *(uint32_t *)(IAddr + pc_cache + 0x0) = SWAP_LE32(pc_offset + 0x0);
                    *(uint32_t *)(IAddr + pc_cache + 0x4) = SWAP_LE32(pc_offset + 0x4);
                    *(uint32_t *)(IAddr + pc_cache + 0x8) = SWAP_LE32(pc_offset + 0x8);
                    *(uint32_t *)(IAddr + pc_cache + 0xc) = SWAP_LE32(pc_offset + 0xc);

                    // opcode line
                    pc_offset = pc & ~0xf;
                    *(uint32_t *)(ICode + pc_cache + 0x0) = psxMu32ref(pc_offset + 0x0);
                    *(uint32_t *)(ICode + pc_cache + 0x4) = psxMu32ref(pc_offset + 0x4);
                    *(uint32_t *)(ICode + pc_cache + 0x8) = psxMu32ref(pc_offset + 0x8);
                    *(uint32_t *)(ICode + pc_cache + 0xc) = psxMu32ref(pc_offset + 0xc);
                }

                // normal code
                return (uint32_t *)PSXM(pc);
            }
        }

        /*
        TODO: Probably should add cached BIOS
        */

        // default
        return (uint32_t *)PSXM(pc);
    }

  private:
    const std::string m_name;
};

class Cpus {
  public:
    static std::unique_ptr<R3000Acpu> Interpreted();
    static std::unique_ptr<R3000Acpu> DynaRec();

  private:
    static std::unique_ptr<R3000Acpu> getX86DynaRec();
    static std::unique_ptr<R3000Acpu> getInterpreted();
};

}  // namespace PCSX
