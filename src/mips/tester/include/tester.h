#ifndef _TESTER_H
#define _TESTER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "common/compiler/stdint.h"
#include "exec.h"
#include "serialio.h"

extern void FlushCache(void);
extern int printf(const char * fmt, ...);
// void shortWait(uint32_t n);
// void longWait(uint32_t n);

#ifdef __cplusplus
}
#endif

#endif /* _TESTER_H */
