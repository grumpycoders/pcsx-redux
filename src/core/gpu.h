#pragma once

#include "core/psxemulator.h"

namespace PCSX {

class GPU {
  public:
    static int gpuReadStatus();
    void dma(uint32_t madr, uint32_t bcr, uint32_t chcr);
    static void gpuInterrupt();

  private:
    // Taken from PEOPS SOFTGPU
    uint32_t s_lUsedAddr[3];

    bool CheckForEndlessLoop(uint32_t laddr);
    uint32_t gpuDmaChainSize(uint32_t addr);
};

}  // namespace PCSX
