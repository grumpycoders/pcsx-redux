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
#define E2BIG 7        /* Argument list too long. */
#define EACCES 13      /* Permission denied. */
#define EAGAIN 11      /* Resource unavailable, try again. */
#define EALREADY 37    /* Connection already in progress. */
#define EBADF 9        /* Bad file descriptor. */
#define EBUSY 16       /* Device or resource busy. */
#define ECHILD 10      /* No child processes. */
#define EDOM 33        /* Mathematics argument out of domain of function. */
#define EEXIST 17      /* File exists. */
#define EFAULT 14      /* Bad address. */
#define EFBIG 27       /* File too large. */
#define EINPROGRESS 36 /* Operation in progress. */
#define EINTR 4        /* Interrupted function. */
#define EINVAL 22      /* Invalid argument. */
#define EIO 5          /* I/O error. */
#define EISDIR 21      /* Is a directory. */
#define EMFILE 24      /* File descriptor value too large. */
#define ENFILE 23      /* Too many files open in system. */
#define ENODEV 19      /* No such device. */
#define ENOENT 2       /* No such file or directory. */
#define ENOEXEC 8      /* Executable file format error. */
#define ENOMEM 12      /* Not enough space. */
#define ENOSPC 28      /* No space left on device. */
#define ENOTDIR 20     /* Not a directory. */
#define ENOTTY 25      /* Inappropriate I/O control operation. */
#define ENXIO 6        /* No such device or address. */
#define EPERM 1        /* Operation not permitted. */
#define EPIPE 32       /* Broken pipe. */
#define ERANGE 34      /* Result too large. */
#define EROFS 30       /* Read-only file system. */
#define ESPIPE 29      /* Invalid seek. */
#define ESRCH 3        /* No such process. */
#define ETXTBSY 26     /* Text file busy. */
#define EWOULDBLOCK 35 /* Operation would block. */
#define EXDEV 18       /* Cross-device link.  */

#if 0
#define	EPERM		1		/* Operation not permitted */
#define	ENOENT		2		/* No such file or directory */
#define	ESRCH		3		/* No such process */
#define	EINTR		4		/* Interrupted system call */
#define	EIO		5		/* Input/output error */
#define	ENXIO		6		/* Device not configured */
#define	E2BIG		7		/* Argument list too long */
#define	ENOEXEC		8		/* Exec format error */
#define	EBADF		9		/* Bad file descriptor */
#define	ECHILD		10		/* No child processes */
#define	EAGAIN		11		/* No more processes */
#define	ENOMEM		12		/* Cannot allocate memory */
#define	EACCES		13		/* Permission denied */
#define	EFAULT		14		/* Bad address */
#define	ENOTBLK		15		/* Block device required */
#define	EBUSY		16		/* Device busy */
#define	EEXIST		17		/* File exists */
#define	EXDEV		18		/* Cross-device link */
#define	ENODEV		19		/* Operation not supported by device */
#define	ENOTDIR		20		/* Not a directory */
#define	EISDIR		21		/* Is a directory */
#define	EINVAL		22		/* Invalid argument */
#define	ENFILE		23		/* Too many open files in system */
#define	EMFILE		24		/* Too many open files */
#define	ENOTTY		25		/* Inappropriate ioctl for device */
#define	ETXTBSY		26		/* Text file busy */
#define	EFBIG		27		/* File too large */
#define	ENOSPC		28		/* No space left on device */
#define	ESPIPE		29		/* Illegal seek */
#define	EROFS		30		/* Read-only file system */
#define	EMLINK		31		/* Too many links */
#define	EPIPE		32		/* Broken pipe */

/* math software */
#define	EDOM		33		/* Numerical argument out of domain */
#define	ERANGE		34		/* Result too large */

/* non-blocking and interrupt i/o */
#define	EWOULDBLOCK	35		/* Operation would block */
#define	EINPROGRESS	36		/* Operation now in progress */
#define	EALREADY	37		/* Operation already in progress */
#endif

extern int errno;			/* global error number */

#ifdef __cplusplus
}
#endif

#endif /* _ERRNO_H */
