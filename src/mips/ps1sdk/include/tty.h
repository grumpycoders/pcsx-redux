/*
 * File:   tty.h
 * Author: asmblur
 *
 */

#ifndef _TTY_H
#define _TTY_H

#ifdef __cplusplus
extern "C" {
#endif

/* prototypes */

int init_tty(void);

// NOTE: you probably don't want to use the rest of these.  Instead, you should use the kernel putchar and such.
int DelTTY(void);
int tty_unhook_putchar(void);
int tty_hook_putchar(void);
int tty_putchar(char ch);
void tty_print32(uint32_t d);
void tty_print16(uint16_t d);
void tty_print8(uint8_t d);
void tty_puts(const char *s);

#ifdef __cplusplus
}
#endif

#endif /* _TTY_H */
