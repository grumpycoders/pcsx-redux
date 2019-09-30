/*
# _____     ___   __      ___ ____
#  ____|   |        |    |        | |____|
# |     ___|     ___| ___|    ____| |    \
#-----------------------------------------------------------------------
#
# "fcntl.h" for PS1.
#
*/

#ifndef _FCNTL_H
#define	_FCNTL_H

#ifdef	__cplusplus
extern "C" {
#endif

/* Values for cmd used by fcntl(): */

#if 0
UNSUPPORTED
#define F_DUPFD         0x0000      /* Duplicate file descriptor. */
#define F_GETFD         0x0000      /* Get file descriptor flags. */
#define F_SETFD         0x0000      /* Set file descriptor flags. */
#define F_GETFL         0x0000      /* Get file status flags and file access modes. */
#define F_SETFL         0x0000      /* Set file status flags. */
#define F_GETLK         0x0000      /* Get record locking information. */
#define F_SETLK         0x0000      /* Set record locking information. */
#define F_SETLKW        0x0000      /* Set record locking information; wait if blocked. */
#endif

/* File creation flags for open(): */
#if 0
UNSUPPORTED
#define O_EXCL          0x0000      /* Exclusive use flag. */
#endif
#if 0
UNSUPPORTED
#define O_NOCTTY        0x0000      /* Do not assign controlling terminal. */
#endif
#define O_CREAT         0x0200      /* Create file if it does not exist. */
#define O_TRUNC         0x0400      /* Truncate flag. */ 

/* File status flags used for open() and fcntl(): */
#define O_APPEND        0x0100      /* Set append mode. */
#define O_NONBLOCK      0x0004      /* Non-blocking mode. */
#define O_SYNC          0x0000      /* Write according to synchronized I/O file integrity completion. */

/* PS1-specific file status flags used for open() and fcntl(): */
#define O_SCAN          0x1000      /* Scan type */
#define O_RCOM          0x2000      /* Remote command entry */
#define O_NBUF          0x4000      /* No ring buffer and console interrupt */
#define O_NOWAIT        0x8000      /* Asynchronous I/O mode */

/* File access modes used for open() and fcntl() */
#define O_RDONLY        0x0001      /* Open for reading only. */
#define O_WRONLY        0x0002      /* Open for writing only. */ 
#define O_RDWR          (O_RDONLY | O_WRONLY)  /* Open for reading and writing. */

/* Mask for use with file access modes */
#define O_ACCMODE       (O_RDONLY | O_WRONLY)

/* File descriptor flags used for fcntl(): */
#if 0
UNSUPPORTED
#define FD_CLOEXEC      0x0000      /* Close the file descriptor upon execution of an exec family function. */
#endif

/* Values for l_type used for record locking with fcntl() */
#if 0
UNSUPPORTED
#define F_UNLCK         0x0000      /* Unlock. */
#define F_RDLCK         0x0010      /* Shared or read lock. */
#define F_WRLCK         0x0020      /* Exclusive or write lock. */
#endif

#ifndef SEEK_SET
#define SEEK_SET        0
#endif

#ifndef SEEK_CUR
#define SEEK_CUR        1
#endif

#ifndef SEEK_END
#define SEEK_END        2
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _FCNTL_H */

