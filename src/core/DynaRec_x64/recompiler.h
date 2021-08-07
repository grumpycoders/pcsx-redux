#pragma once
#include "core/r3000a.h"

#if defined(DYNAREC_X86_64)
#include <array>
#include <fstream>
#include <optional>
#include "fmt/format.h"
#include "tracy/Tracy.hpp"
#include "emitter.h"
#include "regAllocation.h"

#define HOST_REG_CACHE_OFFSET(x) ((uintptr_t) &m_psxRegs.hostRegisterCache[(x)] - (uintptr_t) &m_psxRegs)
#define GPR_OFFSET(x) ((uintptr_t) &m_psxRegs.GPR.r[(x)] - (uintptr_t) &m_psxRegs)
#define COP0_OFFSET(x) ((uintptr_t) &m_psxRegs.CP0.r[(x)] - (uintptr_t) &m_psxRegs)
#define PC_OFFSET ((uintptr_t) &m_psxRegs.pc - (uintptr_t) &m_psxRegs)
#define CYCLE_OFFSET ((uintptr_t)&m_psxRegs.cycle - (uintptr_t)&m_psxRegs)

static uint8_t psxMemRead8Wrapper(uint32_t mem) { return PCSX::g_emulator->m_psxMem->psxMemRead8(mem); }
static uint16_t psxMemRead16Wrapper(uint32_t mem) { return PCSX::g_emulator->m_psxMem->psxMemRead16(mem); }
static uint32_t psxMemRead32Wrapper(uint32_t mem) { return PCSX::g_emulator->m_psxMem->psxMemRead32(mem); }
static void psxMemWrite8Wrapper(uint32_t mem, uint8_t value) { PCSX::g_emulator->m_psxMem->psxMemWrite8(mem, value); }
static void psxMemWrite16Wrapper(uint32_t mem, uint16_t value) { PCSX::g_emulator->m_psxMem->psxMemWrite16(mem, value); }
static void psxMemWrite32Wrapper(uint32_t mem, uint32_t value) {
    PCSX::g_emulator->m_psxMem->psxMemWrite32(mem, value);
}

using DynarecCallback = void(*)(); // A function pointer to JIT-emitted code
using namespace Xbyak;
using namespace Xbyak::util;

class DynaRecCPU final : public PCSX::R3000Acpu {
    typedef void (DynaRecCPU::*func_t)();  // A function pointer to a dynarec member function, used for m_recBSC
  private:
    DynarecCallback** m_recompilerLUT;
    DynarecCallback* m_ramBlocks;  // Pointers to compiled RAM blocks (If nullptr then this block needs to be compiled)
    DynarecCallback* m_biosBlocks; // Pointers to compiled BIOS blocks
    Emitter gen;
    uint32_t m_pc; // Recompiler PC

    bool m_needsStackFrame; // Do we need to setup a stack frame? Usually needed when the block has C fallbacks
    bool m_stopCompiling; // Should we stop compiling code?
    bool m_pcWrittenBack; // Has the PC been written back already by a jump?
    uint32_t m_ramSize;   // RAM is 2MB on retail units, 8MB on some DTL units (Can be toggled in GUI)
    const int MAX_BLOCK_SIZE = 30;

    enum class RegState { Unknown, Constant };

    struct Register {
        uint32_t val = 0; // The register's cached value used for constant propagation
        RegState state = RegState::Unknown; // Is this register's value a constant, or some unknown

        bool allocated = false; // Has this register been allocated to a host reg?
        bool writeback = false; // Does this register need to be written back to memory at the end of the block?
        Reg32 allocatedReg; // If a host reg has been allocated to this register, which reg is it?

        inline bool isConst() { return state == RegState::Constant; }
        inline bool isAllocated() { return allocated; }
        inline void markConst(uint32_t value) {
            val = value;
            state = RegState::Constant;
            unallocate();
        }

        // Note: It's important that markUnknown does not modify the val field as that would mess up codegen
        inline void markUnknown() {
            state = RegState::Unknown;
        }

        inline void setWriteback(bool wb) {
            writeback = wb;
        }

        void unallocate() { 
            allocated = false;
            writeback = false;
        }
    };

    struct HostRegister {
        std::optional<int> mappedReg = std::nullopt; // The register this is allocated to, if any
        bool restore = false; // Did this register need to get restored after this block?
    };
    
    Register m_regs[32];
    std::array <HostRegister, ALLOCATEABLE_REG_COUNT> m_hostRegs;
    
    void allocateReg(int reg);
    void allocateReg(int reg1, int reg2);
    void allocateReg(int reg1, int reg2, int reg3);
    void reserveReg(int index);
    void flushRegs();
    void spillRegisterCache();
    unsigned int m_allocatedRegisters = 0; // how many registers have been allocated in this block?

    void prepareForCall();

public:
    DynaRecCPU() : R3000Acpu("x86-64 DynaRec") {}

    virtual bool Implemented() final { return true; }
    virtual bool Init() final { 
        // Initialize recompiler memory
        // Check for 8MB RAM expansion
        const bool ramExpansion = PCSX::g_emulator->settings.get<PCSX::Emulator::Setting8MB>();
        m_ramSize = ramExpansion ? 0x800000 : 0x200000;
        const auto biosSize = 0x80000;
        const auto ramPages = m_ramSize >> 16; // The amount of 64KB RAM pages. 0x80 with the ram expansion, 0x20 otherwise

        m_recompilerLUT = new DynarecCallback*[0x10000](); // Split the 32-bit address space into 64KB pages, so 0x10000 pages in total
        
        // Instructions need to be on 4-byte boundaries. So the amount of valid block entrypoints 
        // in a region of memory is REGION_SIZE / 4
        m_ramBlocks = new DynarecCallback[m_ramSize / 4](); 
        m_biosBlocks = new DynarecCallback[biosSize / 4]();

        // For every 64KB page of memory, we can have 64*1024/4 unique blocks = 0x4000
        // Hence the multiplications below
        for (auto page = 0; page < ramPages; page++) { // Map RAM to the recompiler LUT
            const auto pointer = &m_ramBlocks[page * 0x4000]; // Get a pointer to the page of RAM blocks
            m_recompilerLUT[page + 0x0000] = pointer; // Map KUSEG, KSEG0 and KSEG1 RAM respectively
            m_recompilerLUT[page + 0x8000] = pointer;
            m_recompilerLUT[page + 0xA000] = pointer;
        }

        for (auto page = 0; page < 8; page++) { // Map BIOS to recompiler LUT
            const auto pointer = &m_biosBlocks[page * 0x4000];
            m_recompilerLUT[page + 0x1FC0] = pointer; // Map KUSEG, KSEG0 and KSEG1 BIOS respectively
            m_recompilerLUT[page + 0x9FC0] = pointer;
            m_recompilerLUT[page + 0xBFC0] = pointer;
        }

        if (m_ramBlocks == nullptr || m_biosBlocks == nullptr || gen.getCode() == nullptr || m_recompilerLUT == nullptr) {
            PCSX::g_system->message("[Dynarec] Error allocating memory");
            return false;
        }
        m_regs[0].markConst(0); // $zero is always zero!

        gen.reset();
        return true;
    }
    
    virtual void Reset() final { 
        R3000Acpu::Reset(); // Reset CPU registers
        Shutdown();         // Deinit and re-init dynarec
        Init();
    }
    
    virtual void Shutdown() final { 
        if (gen.getCode() == nullptr) return; // This should never be true
        delete[] m_recompilerLUT;
        delete[] m_ramBlocks;
        delete[] m_biosBlocks;
    }
   
    virtual void Execute() final {
        ZoneScoped; // Tell the Tracy profiler to do its thing
        while (hasToRun()) execute();
    }

    virtual void Clear(uint32_t Addr, uint32_t Size) final { fmt::print ("Can't clear. Oops\n"); abort(); }
    virtual void SetPGXPMode(uint32_t pgxpMode) final {}
    virtual bool isDynarec() final { return true; }

    void dumpBuffer() {
        std::ofstream file("DynarecOutput.bin", std::ios::binary); // Make a file for our dump
        file.write((const char*) gen.getCode(), gen.getSize()); // Write the code buffer to the dump
    }

  private:
    static void psxExceptionWrapper(DynaRecCPU* that, int32_t e, int32_t bd) {
        that->psxException(e, bd);
    }

    // Check if we're executing from valid memory
    inline bool isPcValid(uint32_t addr) { return m_recompilerLUT[addr >> 16] != nullptr; }
    void execute();
    void recompile(DynarecCallback* callback);
    void error();
    void flushCache();
    void loadContext();
    DynarecCallback* getBlockPointer(uint32_t pc);

    void maybeCancelDelayedLoad(uint32_t index) {
        const unsigned other = m_currentDelayedLoad ^ 1;
        if (m_delayedLoadInfo[other].index == index) {
            m_delayedLoadInfo[other].active = false;
        }
    }

    // Instruction definitions
    void recUnknown();
    void recSpecial();

    void recADDU();
    void recADDIU();
    void recANDI();
    void recBEQ();
    void recBNE();
    void recBGTZ();
    void recCOP0();
    void recJ();
    void recLB();
    void recLBU();
    void recLW();
    void recLUI();
    void recMTC0();
    void recOR();
    void recORI();
    void recSLL();
    void recSLTU();
    void recSRL();
    void recSW();
    void testSoftwareInterrupt();

    // Prepare for a call to a C++ function and then actually emit it
    template <typename T>
    void call(T& func) {
        prepareForCall();
        gen.callFunc(func);
    }

    const func_t m_recBSC[64] = {
        &DynaRecCPU::recSpecial, &DynaRecCPU::recUnknown, &DynaRecCPU::recJ, &DynaRecCPU::recUnknown,  // 00
        &DynaRecCPU::recBEQ, &DynaRecCPU::recBNE, &DynaRecCPU::recUnknown, &DynaRecCPU::recBGTZ,  // 04
        &DynaRecCPU::recADDIU, &DynaRecCPU::recADDIU,   &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 08
        &DynaRecCPU::recANDI, &DynaRecCPU::recORI,     &DynaRecCPU::recUnknown, &DynaRecCPU::recLUI,      // 0c
        &DynaRecCPU::recCOP0, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 10
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 14
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 18
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 1c
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recLW,  // 20
        &DynaRecCPU::recLBU, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 24
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recSW,       // 28
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 2c
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 30
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 34
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 38
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 3c
    };

    const func_t m_recSPC[64] = {
        &DynaRecCPU::recSLL, &DynaRecCPU::recUnknown, &DynaRecCPU::recSRL, &DynaRecCPU::recUnknown,  // 00
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 04
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 08
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 0c
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 10
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 14
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 18
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 1c
        &DynaRecCPU::recUnknown, &DynaRecCPU::recADDU, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 20
        &DynaRecCPU::recUnknown, &DynaRecCPU::recOR, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 24
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recSLTU,  // 28
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 2c
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 30
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 34
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 38
        &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown, &DynaRecCPU::recUnknown,  // 3c
    };
};
#endif // DYNAREC_X86_64
