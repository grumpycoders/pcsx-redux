/*
# _____     ___   __      ___ ____
#  ____|   |        |    |        | |____|
# |     ___|     ___| ___|    ____| |    \
#-----------------------------------------------------------------------
#
# ANSI C "setjmp.h" for PS1.
#
*/

#ifndef _SETJMP_H
#define	_SETJMP_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct st_jmp_buf
{
    void *r_ra; // 0x00
    void *r_sp; // 0x04
    void *r_fp; // 0x08
    void *r_s0; // 0x0C
    void *r_s1; // 0x10
    void *r_s2; // 0x14
    void *r_s3; // 0x18
    void *r_s4; // 0x1C
    void *r_s5; // 0x20
    void *r_s6; // 0x24
    void *r_s7; // 0x28
    void *r_gp; // 0x2C
} jmp_buf;

int setjmp(jmp_buf env);
void longjmp(jmp_buf env, int val);

#ifdef	__cplusplus
}
#endif

#endif	/* _SETJMP_H */
