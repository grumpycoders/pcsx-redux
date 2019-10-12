#ifndef _PSHITTY_H
#define _PSHITTY_H

#ifdef __cplusplus
extern "C" {
#endif

#include "common/compiler/stdint.h"
#include "exec.h"
#include "serialio.h"

extern void flushCache(void);
extern int printf(const char * fmt, ...);

#ifdef __cplusplus
}
#endif

#endif /* _PSHITTY_H */
