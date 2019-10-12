#ifndef _FTFIFO_H
#define _FTFIFO_H

#ifdef __cplusplus
extern "C" {
#endif

#define FTFIFO_DATA ((volatile uint8_t *)0x1F000000)
#define FTFIFO_STAT ((volatile uint8_t *)0x1F000001)
#define FTFIFO_STAT_RXRDY (1 << 0)
#define FTFIFO_STAT_TXRDY (1 << 1)

#define FTFIFO_RX_Ready() ((*FTFIFO_STAT & (FTFIFO_STAT_RXRDY)) == (FTFIFO_STAT_RXRDY))
#define FTFIFO_TX_Ready() ((*FTFIFO_STAT & (FTFIFO_STAT_TXRDY)) == (FTFIFO_STAT_TXRDY))
#define FTFIFO_Ready() ((*FTFIFO_STAT & (FTFIFO_STAT_RXRDY | FTFIFO_STAT_TXRDY)) == (FTFIFO_STAT_RXRDY | FTFIFO_STAT_TXRDY))

static inline uint8_t FT_get(void)
{
    while(!FTFIFO_RX_Ready());
    return *FTFIFO_DATA;
}

static inline void FT_put(uint8_t d)
{
    while(!FTFIFO_TX_Ready());
    *FTFIFO_DATA = d;    
}

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
