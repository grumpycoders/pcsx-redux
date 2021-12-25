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

#include <atomic>
#include <cstdint>
#include <memory>
#include <type_traits>

#include "core/kernel.h"
#include "core/psxcounters.h"
#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "support/file.h"
#include "support/hashtable.h"


#if defined(__i386__) || defined(_M_IX86)
#define DYNAREC_X86_32
#elif defined(__x86_64) || defined(_M_AMD64)
#define DYNAREC_X86_64
#elif defined(__aarch64__) || defined(_M_ARM64) || defined(__ARM_ARCH_ISA_A64)
#define DYNAREC_NONE  // Placeholder for AA64
#elif defined(__arm__) || defined(_M_ARM)
#define DYNAREC_NONE  // Placeholder for AA32
#elif defined(__powerpc__) || defined(_M_PPC)
#define DYNAREC_NONE  // Placeholder for PPC
#else
#define DYNAREC_NONE
#endif

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

struct psxRegisters {
    psxGPRRegs GPR;   // General Purpose Registers
    psxCP0Regs CP0;   // COP0 Registers
    psxCP2Data CP2D;  // COP2 data registers
    psxCP2Ctrl CP2C;  // COP2 control registers
    uint32_t pc;      // Program counter
    uint32_t code;    // The current instruction
    uint32_t cycle;
    uint32_t previousCycles;
    uint32_t interrupt;
    std::atomic<bool> spuInterrupt;
    uint32_t intTargets[32];
    uint32_t lowestTarget;
    uint8_t ICache_Addr[0x1000];
    uint8_t ICache_Code[0x1000];
};

// U64 and S64 are used to wrap long integer constants.
#define U64(val) val##ULL
#define S64(val) val##LL

#if defined(__BIGENDIAN__)

#define _i32(x) reinterpret_cast<int32_t *>(&x)[0]
#define _u32(x) reinterpret_cast<uint32_t *>(&x)[0]

#else

#define _i32(x) reinterpret_cast<int32_t *>(&x)[0]
#define _u32(x) reinterpret_cast<uint32_t *>(&x)[0]

#endif

// R3000A Instruction Macros
#define _PC_ PCSX::g_emulator->m_psxCpu->m_psxRegs.pc  // The next PC to be executed

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

#define _Op_ _fOp_(PCSX::g_emulator->m_psxCpu->m_psxRegs.code)
#define _Funct_ _fFunct_(PCSX::g_emulator->m_psxCpu->m_psxRegs.code)
#define _Rd_ _fRd_(PCSX::g_emulator->m_psxCpu->m_psxRegs.code)
#define _Rt_ _fRt_(PCSX::g_emulator->m_psxCpu->m_psxRegs.code)
#define _Rs_ _fRs_(PCSX::g_emulator->m_psxCpu->m_psxRegs.code)
#define _Sa_ _fSa_(PCSX::g_emulator->m_psxCpu->m_psxRegs.code)
#define _Im_ _fIm_(PCSX::g_emulator->m_psxCpu->m_psxRegs.code)
#define _Target_ _fTarget_(PCSX::g_emulator->m_psxCpu->m_psxRegs.code)

#define _Imm_ _fImm_(PCSX::g_emulator->m_psxCpu->m_psxRegs.code)
#define _ImmU_ _fImmU_(PCSX::g_emulator->m_psxCpu->m_psxRegs.code)
#define _ImmLU_ _fImmLU_(PCSX::g_emulator->m_psxCpu->m_psxRegs.code)

#define _rRs_ PCSX::g_emulator->m_psxCpu->m_psxRegs.GPR.r[_Rs_]  // Rs register
#define _rRt_ PCSX::g_emulator->m_psxCpu->m_psxRegs.GPR.r[_Rt_]  // Rt register
#define _rRd_ PCSX::g_emulator->m_psxCpu->m_psxRegs.GPR.r[_Rd_]  // Rd register

#define _c2dRs_ PCSX::g_emulator->m_psxCpu->m_psxRegs.CP2D.r[_Rs_]  // Rs cop2 data register
#define _c2dRt_ PCSX::g_emulator->m_psxCpu->m_psxRegs.CP2D.r[_Rt_]  // Rt cop2 data register
#define _c2dRd_ PCSX::g_emulator->m_psxCpu->m_psxRegs.CP2D.r[_Rd_]  // Rd cop2 data register

#define _rHi_ PCSX::g_emulator->m_psxCpu->m_psxRegs.GPR.n.hi  // The HI register
#define _rLo_ PCSX::g_emulator->m_psxCpu->m_psxRegs.GPR.n.lo  // The LO register

#define _JumpTarget_ ((_Target_ * 4) + (_PC_ & 0xf0000000))  // Calculates the target during a jump instruction
#define _BranchTarget_ ((int16_t)_Im_ * 4 + _PC_)            // Calculates the target during a branch instruction

class R3000Acpu {
  public:
    virtual ~R3000Acpu() { m_pcdrvFiles.destroyAll(); }
    virtual bool Init() { return false; }
    virtual void Execute() = 0; /* executes up to a debug break */
    virtual void Clear(uint32_t Addr, uint32_t Size) = 0;
    virtual void Shutdown() = 0;
    virtual void SetPGXPMode(uint32_t pgxpMode) = 0;
    virtual bool Implemented() = 0;
    virtual const uint8_t *getBufferPtr() = 0;
    virtual const size_t getBufferSize() = 0;

    const std::string &getName() { return m_name; }

  public:
    static int psxInit();
    virtual bool isDynarec() = 0;
    void psxReset();
    void psxShutdown();

    enum class Exception : uint32_t {
        Interrupt = 0,
        LoadAddressError = 4,
        StoreAddressError = 5,
        InstructionBusError = 6,
        DataBusError = 7,
        Syscall = 8,
        Break = 9,
        ReservedInstruction = 10,
        CoprocessorUnusable = 11,
        ArithmeticOverflow = 12,
    };
    void psxException(Exception e, bool bd, bool cop0 = false) {
        psxException(static_cast<std::underlying_type<Exception>::type>(e) << 2, bd, cop0);
    }
    void psxException(uint32_t code, bool bd, bool cop0 = false);
    void psxBranchTest();

    void psxSetPGXPMode(uint32_t pgxpMode);

    void scheduleInterrupt(unsigned interrupt, uint32_t eCycle) {
        PSXIRQ_LOG("Scheduling interrupt %08x at %08x\n", interrupt, eCycle);
        const uint32_t cycle = m_psxRegs.cycle;
        uint32_t target = cycle + eCycle * m_interruptScales[interrupt];
        m_psxRegs.interrupt |= (1 << interrupt);
        m_psxRegs.intTargets[interrupt] = target;
        int32_t lowest = m_psxRegs.lowestTarget - cycle;
        int32_t maybeNewLowest = target - cycle;
        if (maybeNewLowest < lowest) m_psxRegs.lowestTarget = target;
    }

    psxRegisters m_psxRegs;
    float m_interruptScales[14] = {1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f};
    bool m_shellStarted = false;

    virtual void Reset() {
        invalidateCache();
        m_psxRegs.interrupt = 0;
    }
    bool m_inISR = false;
    bool m_nextIsDelaySlot = false;
    bool m_inDelaySlot = false;
    struct {
        uint32_t index = 0;
        uint32_t value = 0;
        uint32_t mask = 0;
        uint32_t pcValue = 0;
        bool active = false;
        bool pcActive = false;
        bool fromLink = false;
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
    void delayedPCLoad(uint32_t value, bool fromLink) {
        auto &delayedLoad = m_delayedLoadInfo[m_currentDelayedLoad];
        delayedLoad.pcActive = true;
        delayedLoad.pcValue = value;
        delayedLoad.fromLink = fromLink;
    }

  protected:
    R3000Acpu(const std::string &name) : m_name(name) {}
    static inline const uint32_t MASKS[7] = {0, 0xffffff, 0xffff, 0xff, 0xff000000, 0xffff0000, 0xffffff00};
    static inline const uint32_t LWL_MASK[4] = {0xffffff, 0xffff, 0xff, 0};
    static inline const uint32_t LWL_MASK_INDEX[4] = {1, 2, 3, 0};
    static inline const uint32_t LWL_SHIFT[4] = {24, 16, 8, 0};
    static inline const uint32_t LWR_MASK[4] = {0, 0xff000000, 0xffff0000, 0xffffff00};
    static inline const uint32_t LWR_MASK_INDEX[4] = {0, 4, 5, 6};
    static inline const uint32_t LWR_SHIFT[4] = {0, 8, 16, 24};
    static inline const uint32_t SWL_MASK[4] = {0xffffff00, 0xffff0000, 0xff000000, 0};
    static inline const uint32_t SWL_SHIFT[4] = {24, 16, 8, 0};
    static inline const uint32_t SWR_MASK[4] = {0, 0xff, 0xffff, 0xffffff};
    static inline const uint32_t SWR_SHIFT[4] = {0, 8, 16, 24};
    inline bool hasToRun() {
        if (!m_shellStarted) {
            uint32_t &pc = m_psxRegs.pc;
            if (pc == 0x80030000) {
                m_shellStarted = true;
                g_system->m_eventBus->signal(Events::ExecutionFlow::ShellReached{});
            }
        }
        return g_system->running();
    }
    void logA0KernelCall(uint32_t call);
    void logB0KernelCall(uint32_t call);
    void logC0KernelCall(uint32_t call);

    template <bool checkPC = true>
    inline void InterceptBIOS(uint32_t currentPC) {
        const uint32_t pc = currentPC & 0x1fffff;

        if constexpr (checkPC) {
            const uint32_t base = (currentPC >> 20) & 0xffc;
            if ((base != 0x000) && (base != 0x800) && (base != 0xa00)) return;
        }

        const auto r = m_psxRegs.GPR.n;

        // Intercepts write, puts, putc, and putchar.
        // The BIOS doesn't have the TTY output set up by default,
        // so this hack enables us to properly display printfs. However,
        // sometimes, games will fully redirect printf's output, so it
        // will stop calling putchar. We'd need to also intercept
        // printf, but interpreting it is awful. The hope is it'd
        // eventually call one of these 4 functions.
        const uint32_t call = r.t1 & 0xff;
        if (pc == 0xa0) {
            switch (call) {
                case 0x03: {  // write
                    if (r.a0 != 1) break;
                    uint8_t *str = PSXM(r.a1);
                    uint32_t size = r.a2;
                    m_psxRegs.GPR.n.v0 = size;
                    while (size--) {
                        g_system->biosPutc(*str++);
                    }
                    break;
                }
                case 0x09: {  // putc
                    g_system->biosPutc(r.a0);
                    break;
                }
                case 0x3c: {  // putchar
                    g_system->biosPutc(r.a0);
                    break;
                }
                case 0x3e: {  // puts
                    uint8_t *str = PSXM(r.a0);
                    uint8_t c;
                    while ((c = *str++) != 0) {
                        g_system->biosPutc(c);
                    }
                    break;
                }
            }
        } else if (pc == 0xb0) {
            switch (call) {
                case 0x35: {  // write
                    if (r.a0 != 1) break;
                    uint8_t *str = PSXM(r.a1);
                    uint32_t size = r.a2;
                    m_psxRegs.GPR.n.v0 = size;
                    while (size--) {
                        g_system->biosPutc(*str++);
                    }
                    break;
                }
                case 0x3b: {  // putc
                    g_system->biosPutc(r.a0);
                    break;
                }
                case 0x3d: {  // putchar
                    g_system->biosPutc(r.a0);
                    break;
                }
                case 0x3f: {  // puts
                    uint8_t *str = PSXM(r.a0);
                    uint8_t c;
                    while ((c = *str++) != 0) {
                        g_system->biosPutc(c);
                    }
                    break;
                }
            }
        }

        if (g_emulator->settings.get<Emulator::SettingDebugSettings>().get<Emulator::DebugSettings::KernelLog>()) {
            switch (pc) {
                case 0xa0:
                    logA0KernelCall(call);
                    break;
                case 0xb0:
                    logB0KernelCall(call);
                    break;
                case 0xc0:
                    logC0KernelCall(call);
                    break;
            }
        }
    }

  public:
    /*
Formula One 2001
- Use old CPU cache code when the RAM location is
  updated with new code (affects in-game racing)
*/

    inline void invalidateCache() {
        memset(m_psxRegs.ICache_Addr, 0xff, sizeof(m_psxRegs.ICache_Addr));
        memset(m_psxRegs.ICache_Code, 0xff, sizeof(m_psxRegs.ICache_Code));
    }

    inline uint32_t *Read_ICache(uint32_t pc) {
        uint32_t pc_bank, pc_offset, pc_cache;
        uint8_t *IAddr, *ICode;

        pc_bank = pc >> 24;
        pc_offset = pc & 0xffffff;
        pc_cache = pc & 0xfff;

        IAddr = m_psxRegs.ICache_Addr;
        ICode = m_psxRegs.ICache_Code;

        // cached - RAM
        if (pc_bank == 0x80 || pc_bank == 0x00) {
            if (SWAP_LE32(*(uint32_t *)(IAddr + pc_cache)) == pc_offset) {
                // Cache hit - return last opcode used
                return (uint32_t *)(ICode + pc_cache);
            } else {
                // Cache miss - addresses don't match
                // - default: 0xffffffff (not init)

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
                *(uint32_t *)(ICode + pc_cache + 0x0) = *(uint32_t *)PSXM(pc_offset + 0x0);
                *(uint32_t *)(ICode + pc_cache + 0x4) = *(uint32_t *)PSXM(pc_offset + 0x4);
                *(uint32_t *)(ICode + pc_cache + 0x8) = *(uint32_t *)PSXM(pc_offset + 0x8);
                *(uint32_t *)(ICode + pc_cache + 0xc) = *(uint32_t *)PSXM(pc_offset + 0xc);
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

    struct PCdrvFile;
    typedef Intrusive::HashTable<uint32_t, PCdrvFile> PCdrvFiles;
    struct PCdrvFile : public File, public PCdrvFiles::Node {
        PCdrvFile(const std::filesystem::path &filename) : File(filename, File::READWRITE) {}
        PCdrvFile(const std::filesystem::path &filename, File::Create) : File(filename, File::CREATE) {}
        virtual ~PCdrvFile() = default;
        std::string m_relativeFilename;
    };
    PCdrvFiles m_pcdrvFiles;
    uint16_t m_pcdrvIndex = 0;

  public:
    void closeAllPCdevFiles() { m_pcdrvFiles.destroyAll(); }
    void listAllPCdevFiles(std::function<void(uint16_t, std::filesystem::path, bool)> walker) {
        for (auto iter = m_pcdrvFiles.begin(); iter != m_pcdrvFiles.end(); iter++) {
            walker(iter->getKey(), iter->m_relativeFilename, iter->writable());
        }
    }
    void restorePCdrvFile(const std::filesystem::path &path, uint16_t fd);
    void restorePCdrvFile(const std::filesystem::path &path, uint16_t fd, File::Create);
};

class Cpus {
  public:
    static std::unique_ptr<R3000Acpu> Interpreted();
    static std::unique_ptr<R3000Acpu> DynaRec();

  private:
    static std::unique_ptr<R3000Acpu> getDynaRec();
    static std::unique_ptr<R3000Acpu> getInterpreted();
};

}  // namespace PCSX
