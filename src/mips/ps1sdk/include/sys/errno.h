/*
# _____     ___   __      ___ ____
#  ____|   |        |    |        | |____|
# |     ___|     ___| ___|    ____| |    \
#-----------------------------------------------------------------------
#
# ANSI C "errno.h" for PS1.
#
*/

#ifndef _ERRNO_H
#define _ERRNO_H

#ifdef __cplusplus
extern "C" {
#endif

/* PS1 only */
#define ENOTBLK 15 /* Block device required */
#define EFORMAT 31 /* Bad file format */

/* ANSI C */
#define E2BIG 7 /* Argument list too long. */
#define EACCES 13 /* Permission denied. */
#define EAGAIN 11 /* Resource unavailable, try again. */
#define EALREADY 37 /* Connection already in progress. */
#define EBADF 9 /* Bad file descriptor. */
#define EBUSY 16 /* Device or resource busy. */
#define ECHILD 10 /* No child processes. */
#define EDOM 33 /* Mathematics argument out of domain of function. */
#define EEXIST 17 /* File exists. */
#define EFAULT 14 /* Bad address. */
#define EFBIG 27 /* File too large. */
#define EINPROGRESS 36 /* Operation in progress. */
#define EINTR 4 /* Interrupted function. */
#define EINVAL 22 /* Invalid argument. */
#define EIO 5 /* I/O error. */
#define EISDIR 21 /* Is a directory. */
#define EMFILE 24 /* File descriptor value too large. */
#define ENFILE 23 /* Too many files open in system. */
#define ENODEV 19 /* No such device. */
#define ENOENT 2 /* No such file or directory. */
#define ENOEXEC 8 /* Executable file format error. */
#define ENOMEM 12 /* Not enough space. */
#define ENOSPC 28 /* No space left on device. */
#define ENOTDIR 20 /* Not a directory. */
#define ENOTTY 25 /* Inappropriate I/O control operation. */
#define ENXIO 6 /* No such device or address. */
#define EPERM 1 /* Operation not permitted. */
#define EPIPE 32 /* Broken pipe. */
#define ERANGE 34 /* Result too large. */
#define EROFS 30 /* Read-only file system. */
#define ESPIPE 29 /* Invalid seek. */
#define ESRCH 3 /* No such process. */
#define ETXTBSY 26 /* Text file busy. */
#define EWOULDBLOCK 35 /* Operation would block. */
#define EXDEV 18 /* Cross-device link.  */

#ifdef __cplusplus
}
#endif

#endif /* _ERRNO_H */
