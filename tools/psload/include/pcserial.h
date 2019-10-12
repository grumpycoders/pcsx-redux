#ifndef _PCSERIAL_H
#define _PCSERIAL_H

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

typedef enum
{
    CHLEN_5,
    CHLEN_6,
    CHLEN_7,
    CHLEN_8
} CharLen;

typedef enum
{
    PARITY_NONE,
    PARITY_EVEN,
    PARITY_ODD
} Parity;

typedef enum
{
    STOPBITS_0,
    STOPBITS_1,
    STOPBITS_1_5,
    STOPBITS_2
} StopBits;

enum
{
    LINE_ENDS_LF, // use linefeed('\x0A'/'\n'), 
    LINE_ENDS_CRLF, // use carriage return('\x0D'/'\r'/CR) followed by a linefeed: "\r\n"
    LINE_ENDS_AUTO, // use line endings corresponding to the OS this app is running on.
                    // i.e. CRLF for Windows/DOS-based OS, LF for for others.
    LINE_ENDS_DEF // do not alter line endings
};

typedef struct SerialConfig_st
{
    int baud;
    CharLen chlen;
    Parity parity;
    StopBits sbits;
    int sw_handshake;
    int hw_handshake;
    int line_ends;
    
    // private
    char *_devPath;
    int _line_ends;
    int _fd; // fd for the device.
    FILE * _in_fp; // fp to use for local "stdin" output
    FILE * _out_fp; // fp to use for local "stdout" output
    FILE * _err_fp; // fp to use for local "stderr" output
    int _prev_ch;
    struct termios _old_tio;
} SerialConfig;

int serial_open(SerialConfig *cfg, const char *path);
int serial_config(SerialConfig *cfg);
int serial_close(SerialConfig *cfg);

int serial_getb(SerialConfig *cfg, uint8_t *c);
int serial_putb(SerialConfig *cfg, uint8_t c, uint32_t delay);

int cons_putchar(SerialConfig *cfg, uint8_t ch);

void print_serial_config(SerialConfig *cfg);

#ifdef __cplusplus
}
#endif

#endif // _PCSERIAL_H
