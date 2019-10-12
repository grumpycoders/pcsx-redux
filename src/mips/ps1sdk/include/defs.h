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
#define NULL ((void*)0)
#endif

#define ALIGN(___x, ___align) (((___x) + ((___align)-1)) & ~((___align)-1))

#define PHYSADDR(a) (((uint32_t)(a)) & 0x1FFFFFFF)

#define KUSEG 0x00000000
// cached
#define KSEG0 0x80000000
// uncached
#define KSEG1 0xA0000000

#define KUSEGADDR(___a) (PHYSADDR(___a) | KUSEG)
#define KSEG0ADDR(___a) (PHYSADDR(___a) | KSEG0)
#define KSEG1ADDR(___a) (PHYSADDR(___a) | KSEG1)

#endif /* PS1_DEFS_H */
