#ifndef _UTILS_H
#define _UTILS_H

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <sys/termios.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <fcntl.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

extern uint32_t __verbosity_flags;
extern uint32_t __verbosity_level;

#define VERBOSITY_FLAG_ERROR    (1 <<  0)
#define VERBOSITY_FLAG_WARN     (1 <<  1)
#define VERBOSITY_FLAG_INFO     (1 <<  2)
#define VERBOSITY_FLAG_DEBUG    (1 <<  3)

#define VERBOSITY_SILENT    0
#define VERBOSITY_ERROR     1
#define VERBOSITY_WARN      2
#define VERBOSITY_INFO      3
#define VERBOSITY_DEBUG     4
#define VERBOSITY_MAX       10

#define MAX_DATA_SIZE (MAXPATHLEN)

#define eprintf(...) if(((__verbosity_flags & VERBOSITY_FLAG_ERROR) != 0) && (__verbosity_level >= VERBOSITY_ERROR)) { fprintf (stderr, __VA_ARGS__); }
#define wprintf(...) if(((__verbosity_flags & VERBOSITY_FLAG_WARN) != 0) && (__verbosity_level >= VERBOSITY_WARN)) { fprintf (stderr, __VA_ARGS__); }
#define iprintf(...) if(((__verbosity_flags & VERBOSITY_FLAG_INFO) != 0) && (__verbosity_level >= VERBOSITY_INFO)) { fprintf (stdout, __VA_ARGS__); }
#define dprintf(__lvl, ...) if(((__verbosity_flags & VERBOSITY_FLAG_DEBUG) != 0) && (__verbosity_level >= (VERBOSITY_DEBUG + ((__lvl) - 1)))) { fprintf (stdout, __VA_ARGS__); }

#ifdef __cplusplus
}
#endif

#endif // _UTILS_H
