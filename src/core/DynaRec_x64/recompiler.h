#pragma once
#include "core/r3000a.h"

#if defined(DYNAREC_X86_64)
#include "fmt/format.h"
#include "xbyak.h"

using DynarecCallback = uint32_t(*)(); // A function pointer to JIT-emitted code
using namespace Xbyak;
using namespace Xbyak::util;

class DynaRecCPU : public PCSX::R3000Acpu {
  public:
    DynaRecCPU() : R3000Acpu("x86-64 DynaRec") {}

    virtual bool Implemented() final { return true; }
    virtual bool Init() final { return false; }
    virtual void Reset() final { fmt::print ("Can't reset. Oops\n"); abort(); }
    virtual void Execute() final { fmt::print ("Can't execute. Oops\n"); abort(); }
    virtual void Clear(uint32_t Addr, uint32_t Size) final { fmt::print ("Can't clear. Oops\n"); abort(); }
    virtual void Shutdown() final { fmt::print ("Can't shutdown. Oops\n"); abort(); }
    virtual void SetPGXPMode(uint32_t pgxpMode) final {}
    virtual bool isDynarec() final { return true; }
};
#endif // DYNAREC_X86_64