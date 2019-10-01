/*
# _____     ___   __      ___ ____
#  ____|   |        |    |        | |____|
# |     ___|     ___| ___|    ____| |    \
#-----------------------------------------------------------------------
#
# ANSI C "stdarg.h" for PS1.
#
*/

#ifndef _STDARG_H
#define _STDARG_H

#ifdef __cplusplus
extern "C" {
#endif

#define __va_rounded_size(T) (((sizeof(T) + sizeof(int) - 1) / sizeof(int)) * sizeof(int))

#define va_arg(ap, T) \
    (ap = (va_list)((char*)(ap) + __va_rounded_size(T)), *((T*)(void*)((char*)(ap)-__va_rounded_size(T))))

#define va_start(ap, last_arg) (ap = ((char*)&(last_arg) + __va_rounded_size(last_arg)))

#define va_end(ap) ___ap = (char*)NULL

typedef void* va_list;

#ifdef __cplusplus
}
#endif

#endif /* _STDARG_H */
