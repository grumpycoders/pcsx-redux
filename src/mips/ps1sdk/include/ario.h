/*
 * File:   ario.h
 * Author: aric
 *
 * Created on February 10, 2009, 1:13 AM
 */

#ifndef _ARIO_H
#define _ARIO_H

#ifdef __cplusplus
extern "C" {
#endif

#define AR12_STATUS ((volatile uint8_t *) 0x1F020010)
#define AR12_SWITCH ((volatile uint8_t *) 0x1F020018)
#define AR12_RXD    ((volatile uint8_t *) 0x1F060000)
#define AR12_TXD    ((volatile uint8_t *) 0x1F060008)

// Set when there is data to be read from the comms link.
#define AR12_STAT_RX_RDY (1 << 0)

/* prototypes */

uint8_t AR12_exchange8(uint8_t d);
uint16_t AR12_exchange16(uint16_t d);
uint32_t AR12_exchange32(uint32_t d);

// the following are basically helpers that call AR12_exchangeX(0)
uint8_t AR12_read8(void);
uint16_t AR12_read16(void);
uint32_t AR12_read32(void);

#ifdef __cplusplus
}
#endif

#endif /* _ARIO_H */
