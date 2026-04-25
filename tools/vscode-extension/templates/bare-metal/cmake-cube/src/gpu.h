
#pragma once

#include <stdint.h>
#include "ps1/gpucmd.h"

// In order for Z averaging to work properly, ORDERING_TABLE_SIZE should be set
// to either a relatively high value (1024 or more) or a multiple of 12; see
// setupGTE() for more details. Higher values will take up more memory but are
// required to render more complex scenes with wide depth ranges correctly.
#define GPU_CHAIN_BUFFER_SIZE   1024
#define GPU_ORDERING_TABLE_SIZE  240

typedef struct {
    uint32_t data[GPU_CHAIN_BUFFER_SIZE];
    uint32_t orderingTable[GPU_ORDERING_TABLE_SIZE];
    uint32_t *nextPacket;
} GPUDMAChain;

typedef struct {
    uint8_t  u, v;
    uint16_t width, height;
    uint16_t page, clut;
} TextureInfo;

#ifdef __cplusplus
extern "C" {
#endif

void setupGPU(GP1VideoMode mode, int width, int height);
void waitForGP0Ready(void);
void waitForGPUDMADone(void);
void waitForVSync(void);

void sendGPULinkedList(const void *data);
void sendVRAMData(
    const void *data,
    int        x,
    int        y,
    int        width,
    int        height
);
void clearOrderingTable(uint32_t *table, int numEntries);
uint32_t *allocateGP0Packet(GPUDMAChain *chain, int zIndex, int numCommands);

void uploadTexture(
    TextureInfo *info,
    const void  *data,
    int         x,
    int         y,
    int         width,
    int         height
);
void uploadIndexedTexture(
    TextureInfo   *info,
    const void    *image,
    const void    *palette,
    int           imageX,
    int           imageY,
    int           paletteX,
    int           paletteY,
    int           width,
    int           height,
    GP0ColorDepth colorDepth
);

#ifdef __cplusplus
}
#endif
