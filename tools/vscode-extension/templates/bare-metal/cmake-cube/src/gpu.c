
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include "gpu.h"
#include "ps1/gpucmd.h"
#include "ps1/registers.h"

void setupGPU(GP1VideoMode mode, int width, int height) {
    int x = 0x760;
    int y = (mode == GP1_MODE_PAL) ? 0xa3 : 0x88;

    GP1HorizontalRes horizontalRes = GP1_HRES_320;
    GP1VerticalRes   verticalRes   = GP1_VRES_256;

    int offsetX = (width  * gp1_clockMultiplierH(horizontalRes)) / 2;
    int offsetY = (height / gp1_clockDividerV(verticalRes))      / 2;

    GPU_GP1 = gp1_resetGPU();
    GPU_GP1 = gp1_fbRangeH(x - offsetX, x + offsetX);
    GPU_GP1 = gp1_fbRangeV(y - offsetY, y + offsetY);
    GPU_GP1 = gp1_fbMode(
        horizontalRes, verticalRes, mode, false, GP1_COLOR_16BPP
    );
}

void waitForGP0Ready(void) {
    while (!(GPU_GP1 & GP1_STAT_CMD_READY))
        __asm__ volatile("");
}

void waitForDMADone(void) {
    while (DMA_CHCR(DMA_GPU) & DMA_CHCR_ENABLE)
        __asm__ volatile("");
}

void waitForVSync(void) {
    while (!(IRQ_STAT & (1 << IRQ_VSYNC)))
        __asm__ volatile("");

    IRQ_STAT = ~(1 << IRQ_VSYNC);
}

void sendLinkedList(const void *data) {
    waitForDMADone();
    assert(!((uint32_t) data % 4));

    DMA_MADR(DMA_GPU) = (uint32_t) data;
    DMA_CHCR(DMA_GPU) = DMA_CHCR_WRITE | DMA_CHCR_MODE_LIST | DMA_CHCR_ENABLE;
}

void sendVRAMData(const void *data, int x, int y, int width, int height) {
    waitForDMADone();
    assert(!((uint32_t) data % 4));

    size_t length = (width * height) / 2;
    size_t chunkSize, numChunks;

    if (length < DMA_MAX_CHUNK_SIZE) {
        chunkSize = length;
        numChunks = 1;
    } else {
        chunkSize = DMA_MAX_CHUNK_SIZE;
        numChunks = length / DMA_MAX_CHUNK_SIZE;

        assert(!(length % DMA_MAX_CHUNK_SIZE));
    }

    waitForGP0Ready();
    GPU_GP0 = gp0_vramWrite();
    GPU_GP0 = gp0_xy(x, y);
    GPU_GP0 = gp0_xy(width, height);

    DMA_MADR(DMA_GPU) = (uint32_t) data;
    DMA_BCR (DMA_GPU) = chunkSize | (numChunks << 16);
    DMA_CHCR(DMA_GPU) = DMA_CHCR_WRITE | DMA_CHCR_MODE_SLICE | DMA_CHCR_ENABLE;
}

void clearOrderingTable(uint32_t *table, int numEntries) {
    DMA_MADR(DMA_OTC) = (uint32_t) &table[numEntries - 1];
    DMA_BCR (DMA_OTC) = numEntries;
    DMA_CHCR(DMA_OTC) = 0
        | DMA_CHCR_READ | DMA_CHCR_REVERSE | DMA_CHCR_MODE_BURST
        | DMA_CHCR_ENABLE | DMA_CHCR_TRIGGER;

    while (DMA_CHCR(DMA_OTC) & DMA_CHCR_ENABLE)
        __asm__ volatile("");
}

uint32_t *allocatePacket(DMAChain *chain, int zIndex, int numCommands) {
    uint32_t *ptr      = chain->nextPacket;
    chain->nextPacket += numCommands + 1;

    assert((zIndex >= 0) && (zIndex < ORDERING_TABLE_SIZE));

    *ptr = gp0_tag(numCommands, (void *) chain->orderingTable[zIndex]);
    chain->orderingTable[zIndex] = gp0_tag(0, ptr);

    assert(chain->nextPacket < &(chain->data)[CHAIN_BUFFER_SIZE]);

    return &ptr[1];
}

void uploadTexture(
    TextureInfo *info, const void *data, int x, int y, int width, int height
) {
    assert((width <= 256) && (height <= 256));

    sendVRAMData(data, x, y, width, height);
    waitForDMADone();

    info->page   = gp0_page(
        x / 64, y / 256, GP0_BLEND_SEMITRANS, GP0_COLOR_16BPP
    );
    info->clut   = 0;
    info->u      = (uint8_t)  (x % 64);
    info->v      = (uint8_t)  (y % 256);
    info->width  = (uint16_t) width;
    info->height = (uint16_t) height;
}

void uploadIndexedTexture(
    TextureInfo *info, const void *image, const void *palette, int x, int y,
    int paletteX, int paletteY, int width, int height, GP0ColorDepth colorDepth
) {
    assert((width <= 256) && (height <= 256));

    int numColors    = (colorDepth == GP0_COLOR_8BPP) ? 256 : 16;
    int widthDivider = (colorDepth == GP0_COLOR_8BPP) ?   2 :  4;

    assert(!(paletteX % 16) && ((paletteX + numColors) <= 1024));

    sendVRAMData(image, x, y, width / widthDivider, height);
    waitForDMADone();
    sendVRAMData(palette, paletteX, paletteY, numColors, 1);
    waitForDMADone();

    info->page   = gp0_page(
        x / 64, y / 256, GP0_BLEND_SEMITRANS, colorDepth
    );
    info->clut   = gp0_clut(paletteX / 16, paletteY);
    info->u      = (uint8_t)  ((x % 64) * widthDivider);
    info->v      = (uint8_t)  (y % 256);
    info->width  = (uint16_t) width;
    info->height = (uint16_t) height;
}
