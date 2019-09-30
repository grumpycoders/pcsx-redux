/*
# _____     ___   __      ___ ____
#  ____|   |        |    |        | |____|
# |     ___|     ___| ___|    ____| |    \
#-----------------------------------------------------------------------
#
# PS1 standard definitions.
#
*/

#ifndef PS1_DEFS_H
#define PS1_DEFS_H

#include "types.h"

#ifndef NULL
#define NULL	((void *)0)
#endif

#define ALIGN(x, align)	(((x)+((align)-1))&~((align)-1))

#define PHYSADDR(a)	(((uint32_t)(a)) & 0x1fffffff)

#define KSEG1		0xa0000000
#define KSEG1ADDR(a)	((__typeof__(a))(((uint32_t)(a) & 0x1fffffff) | KSEG1))

#endif /* PS1_DEFS_H */
