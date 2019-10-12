#ifndef _PSHITTY_H
#define _PSHITTY_H

#ifdef __cplusplus
extern "C" {
#endif

#include "common/compiler/stdint.h"
#include "exec.h"
#include "serialio.h"

extern void FlushCache(void);
extern int printf(const char * fmt, ...);
void shortWait(uint32_t n);
void longWait(uint32_t n);

#ifdef __cplusplus
}
#endif

#endif /* _PSHITTY_H */
