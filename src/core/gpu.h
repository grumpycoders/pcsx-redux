#ifndef __GPU_H__
#define __GPU_H__

#include "core/psxcommon.h"

int gpuReadStatus();

void psxDma2(uint32_t madr, uint32_t bcr, uint32_t chcr);
void gpuInterrupt();

#endif
