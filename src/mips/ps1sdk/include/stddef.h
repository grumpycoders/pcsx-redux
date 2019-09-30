/*
# _____     ___   __      ___ ____
#  ____|   |        |    |        | |____|
# |     ___|     ___| ___|    ____| |    \
#-----------------------------------------------------------------------
#
# ANSI C "stddef.h" for PS1.
#
*/

#ifndef _STDDEF_H
#define	_STDDEF_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef NULL
#define NULL ((void *) 0)
#endif

#define offsetof(type, member)  __builtin_offsetof (type, member)

typedef int ptrdiff_t;
typedef unsigned long wchar_t;
typedef unsigned int size_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _STDDEF_H */

