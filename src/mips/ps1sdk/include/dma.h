/*
 * PS1 DMA
 */

#ifndef _PS1DMA_H
#define _PS1DMA_H

#ifdef __cplusplus
extern "C" {
#endif

// DMA channels
// FIXME: properly define channels 5 and 6
#define PS1_DMA_CH_MDEC_IN      (0)
#define PS1_DMA_CH_MDEC_OUT     (1)
#define PS1_DMA_CH_GPU          (2)
#define PS1_DMA_CH_CDROM        (3)
#define PS1_DMA_CH_SPU          (4)
#define PS1_DMA_CH_5            (5)
#define PS1_DMA_CH_6            (6)

#ifdef __cplusplus
}
#endif

#endif /* _PS1DMA_H */
