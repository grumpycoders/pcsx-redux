/*
 * PS1 DMA
 */

#ifndef _PS1DMA_H
#define _PS1DMA_H

#ifdef __cplusplus
extern "C" {
#endif

// DMA channels
enum
{
    DMA_CH_MDEC_IN      = (0),
    DMA_CH_MDEC_OUT     = (1),
    DMA_CH_GPU          = (2), // list + image data
    DMA_CH_CDROM        = (3),
    DMA_CH_SPU          = (4),
    DMA_CH_EXP1         = (5),
    DMA_CH_GPU_OTC      = (6), // (reverse clear the Ordering Table)
};

#ifdef __cplusplus
}
#endif

#endif /* _PS1DMA_H */
