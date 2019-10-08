/*
# _____     ___   __      ___ ____
#  ____|   |        |    |        | |____|
# |     ___|     ___| ___|    ____| |    \
#-----------------------------------------------------------------------
#
# Misc. Helpers
#
*/

#ifndef _HELPERS_H
#define _HELPERS_H

#include <stddef.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t C0_get_BPC(void);
uint32_t C0_get_BDA(void);
uint32_t C0_get_DCIC(void);
uint32_t C0_get_BADVADDR(void);
uint32_t C0_get_BDAM(void);
uint32_t C0_get_BPCM(void);
uint32_t C0_get_STATUS(void);
uint32_t C0_get_CAUSE(void);
uint32_t C0_get_EPC(void);
uint32_t C0_get_PRID(void);

void C0_set_BPC(uint32_t v);
void C0_set_BDA(uint32_t v);
void C0_set_DCIC(uint32_t v);
void C0_set_BADVADDR(uint32_t v);
void C0_set_BDAM(uint32_t v);
void C0_set_BPCM(uint32_t v);
void C0_set_STATUS(uint32_t v);
void C0_set_CAUSE(uint32_t v);
void C0_set_EPC(uint32_t v);
void C0_set_PRID(uint32_t v);

#ifdef __cplusplus
}
#endif

#endif /* _HELPERS_H */
