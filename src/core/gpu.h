#ifndef __GPU_H__
#define __GPU_H__

#include "psxcommon.h"

#ifdef __cplusplus
extern "C" {
#endif

int gpuReadStatus();

void psxDma2(u32 madr, u32 bcr, u32 chcr);
void gpuInterrupt();

#ifdef __cplusplus
}
#endif

#endif
