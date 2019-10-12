/*
# _____     ___   __      ___ ____
#  ____|   |        |    |        | |____|
# |     ___|     ___| ___|    ____| |    \
#-----------------------------------------------------------------------
#
# Type definitions for PS1.
#
*/
#ifndef _TYPES_H_
#define	_TYPES_H_

#ifndef _UCHAR_T
#define _UCHAR_T
typedef	unsigned char	u_char;
#endif // !_UCHAR_T
#ifndef _USHORT_T
#define _USHORT_T
typedef	unsigned short	u_short;
#endif // !_USHORT_T
#ifndef _UINT_T
#define _UINT_T
typedef	unsigned int	u_int;
#endif // !_UINT_T
#ifndef _ULONG_T
#define _ULONG_T
typedef	unsigned long	u_long;
#endif // !_ULONG_T

#ifndef _DEV_T
#define _DEV_T
typedef short dev_t;			/* device number */
#endif // !_DEV_T

#ifndef _OFF_T
#define _OFF_T
typedef long off_t;			/* file offset (should be a quad) */
#endif // !_OFF_T

#ifndef _UID_T
#define _UID_T
typedef u_short uid_t;			/* user id */
#endif // !_UID_T

#ifndef _gid_T
#define _gid_T
typedef u_short gid_t;			/* group id */
#endif // !_GID_T

#ifndef _OFF_T
#define _OFF_T
typedef long off_t;			/* file offset (should be a quad) */
#endif // !_OFF_T

#ifndef _PID_T
#define _PID_T
typedef short pid_t;			/* process id */
#endif // !_PID_T

#ifndef _MODE_T
#define _MODE_T
typedef u_short mode_t;			/* permissions */
#endif // !_MODE_T

#ifndef	_SIZE_T
#define	_SIZE_T
typedef	unsigned int size_t;
#endif // !_SIZE_T

#ifdef	_TIME_T
#define	_TIME_T
typedef	long	time_t;
#endif // !_TIME_T

#ifndef NBBY
#define	NBBY	8		/* number of bits in a byte */
#endif // !NBBY

#define	major(x)	((int)(((u_int)(x) >> 8)&0xff))	/* major number */
#define	minor(x)	((int)((x)&0xff))		/* minor number */
#define	makedev(x,y)	((dev_t)(((x)<<8) | (y)))	/* create dev_t */

#ifdef __cplusplus
}
#endif

#endif /* _TYPES_H */
