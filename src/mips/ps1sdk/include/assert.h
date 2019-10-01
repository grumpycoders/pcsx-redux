/*
# _____     ___   __      ___ ____
#  ____|   |        |    |        | |____|
# |     ___|     ___| ___|    ____| |    \
#-----------------------------------------------------------------------
#
# ANSI C "assert.h" for PS1.
#
*/

#ifndef _ASSERT_H
#define _ASSERT_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef assert
#undef assert
#endif

#ifndef NDEBUG
void __assert(const char*, const char*, int);
#define assert(e) ((e) ? (void)0 : __assert(#e, __FILE__, __LINE__))
#else
#define assert(ignore) ((void)0)
#endif

#ifdef __cplusplus
}
#endif

#endif /* _ASSERT_H */
