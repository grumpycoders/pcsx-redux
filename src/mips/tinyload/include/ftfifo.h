#ifndef _FTFIFO_H
#define _FTFIFO_H

#ifdef __cplusplus
extern "C" {
#endif

#define FTFIFO_DATA ((volatile uint8_t *)0x1F000000)
#define FTFIFO_STAT ((volatile uint8_t *)0x1F000001)
#define FTFIFO_STAT_RXRDY (1 << 0)
#define FTFIFO_STAT_TXRDY (1 << 1)

uint8_t FT_peek8(uint32_t timeout, int *presult);
uint16_t FT_peek16(uint32_t timeout, int *presult);
uint32_t FT_peek32(uint32_t timeout, int *presult);

int FT_poke8(uint8_t d, uint32_t timeout);
int FT_poke16(uint16_t d, uint32_t timeout);
int FT_poke32(uint32_t d, uint32_t timeout);

#ifdef __cplusplus
}
#endif

#endif /* _FTFIFO_H */
