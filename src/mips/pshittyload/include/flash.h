/*
# _____     ___   __      ___ ____
#  ____|   |        |    |        | |____|
# |     ___|     ___| ___|    ____| |    \
#-----------------------------------------------------------------------
#
# "flash.h" - header of the flash memory library for PS1.
#
*/

#ifndef _FLASH_H
#define _FLASH_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* macros */
// test if bit 6 of any byte in the array toggles on consecutive reads
// which indicates that a Program or Erase operation is in progress.
#define isBitToggling(__base) (((((volatile uint8_t *) __base)[0]  ^ ((volatile uint8_t *) __base)[0]) & (1 << 6)) != 0)

/* prototypes */
void Flash_Reset(void *base);
void Flash_Autoselect(void *base);
void Flash_SectorErase(void *base, uint32_t offset);
void Flash_ChipErase(void *base);;
void Flash_Program(void *base, uint32_t offs, void *src, uint32_t size);
void FlashUnlockCycle(void *base, uint8_t cmd);
void Flash_ProgramFast(void *base, uint32_t offs, void *src, uint32_t size);
uint32_t flash_detect(void *base, uint16_t *p_mid, uint16_t *p_did);

#ifdef __cplusplus
}
#endif

#endif /* _FLASH_H */
