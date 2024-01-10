
#pragma once

#include <stdint.h>
#include "ps1/gpucmd.h"

#define DMA_MAX_CHUNK_SIZE  16
#define CHAIN_BUFFER_SIZE   1024
#define ORDERING_TABLE_SIZE 32

typedef struct {
	uint32_t data[CHAIN_BUFFER_SIZE];
	uint32_t orderingTable[ORDERING_TABLE_SIZE];
	uint32_t *nextPacket;
} DMAChain;

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
void waitForDMADone(void);
void waitForVSync(void);

void sendLinkedList(const void *data);
void sendVRAMData(const void *data, int x, int y, int width, int height);
void clearOrderingTable(uint32_t *table, int numEntries);
uint32_t *allocatePacket(DMAChain *chain, int zIndex, int numCommands);

void uploadTexture(
	TextureInfo *info, const void *data, int x, int y, int width, int height
);
void uploadIndexedTexture(
	TextureInfo *info, const void *image, const void *palette, int x, int y,
	int paletteX, int paletteY, int width, int height, GP0ColorDepth colorDepth
);

#ifdef __cplusplus
}
#endif
