#pragma once

#include "core/psxemulator.h"

namespace PCSX {

class GUI;

class GPUinterface {
  public:
    int gpuReadStatus();
    void dma(uint32_t madr, uint32_t bcr, uint32_t chcr);
    static void gpuInterrupt();

    bool m_showCfg;
    virtual bool configure() = 0;
    virtual ~GPUinterface() {}

  private:
    // Taken from PEOPS GPU
    uint32_t s_lUsedAddr[3];

    bool CheckForEndlessLoop(uint32_t laddr);
    uint32_t gpuDmaChainSize(uint32_t addr);

  public:
    typedef struct {
        uint32_t ulFreezeVersion;
        uint32_t ulStatus;
        uint32_t ulControl[256];
        unsigned char psxVRam[1024 * 512 * 2];
    } GPUFreeze_t;

    virtual int32_t init() = 0;
    virtual int32_t shutdown() = 0;
    virtual int32_t open(GUI *) = 0;
    virtual int32_t close() = 0;
    virtual uint32_t readData() = 0;
    virtual void readDataMem(uint32_t *pMem, int iSize) = 0;
    virtual uint32_t readStatus() = 0;
    virtual void writeData(uint32_t gdata) = 0;
    virtual void writeDataMem(uint32_t *pMem, int iSize) = 0;
    virtual void writeStatus(uint32_t gdata) = 0;
    virtual int32_t dmaChain(uint32_t *baseAddrL, uint32_t addr) = 0;
    virtual void updateLace() = 0;
    virtual void keypressed(int key) {}
    virtual void displayText(char *pText) { PCSX::g_system->printf("%s\n", pText); }
    virtual void makeSnapshot(void) {}
    virtual void toggleDebug(void) {}
    virtual int32_t freeze(uint32_t ulGetFreezeData, GPUFreeze_t *pF) = 0;
    virtual int32_t getScreenPic(unsigned char *pMem) { return -1; }
    virtual int32_t showScreenPic(unsigned char *pMem) { return -1; }
    virtual void clearDynarec(void (*callback)(void)) {}
    virtual void hSync(int val) {}
    virtual void vBlank(int val) {}
    virtual void visualVibration(uint32_t iSmall, uint32_t iBig) {}
    virtual void cursor(int player, int x, int y) {}
    virtual void addVertex(short sx, short sy, int64_t fx, int64_t fy, int64_t fz) {}
    virtual void setSpeed(float newSpeed) {}
    virtual void pgxpMemory(unsigned int addr, unsigned char *pVRAM) {}
    virtual void pgxpCacheVertex(short sx, short sy, const unsigned char *_pVertex) {}
    virtual int32_t test(void) { return 0; }
    virtual void about(void) {}
};

}  // namespace PCSX
