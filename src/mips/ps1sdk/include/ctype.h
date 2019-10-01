/*
# _____     ___   __      ___ ____
#  ____|   |        |    |        | |____|
# |     ___|     ___| ___|    ____| |    \
#-----------------------------------------------------------------------
#
# ANSI C "ctype.h" for PS1.
#
*/

#ifndef _PS1_CTYPE_H_
#define _PS1_CTYPE_H_

extern unsigned char __ctype_table[];

enum {
    // uppercase alphabetic
    CTYPE_UCASE = (1 << 0),
    // lowercase alphabetic
    CTYPE_LCASE = (1 << 1),
    // numeric ('0'-'9')
    CTYPE_NUMER = (1 << 2),
    // white space
    CTYPE_WSPAC = (1 << 3),
    // punctuation
    CTYPE_PUNCT = (1 << 4),
    // control
    CTYPE_CNTRL = (1 << 5),
    // hexadecimal('0'-'9', 'A'-'F', 'a'-'f')
    CTYPE_HEXAD = (1 << 6),
    // blank
    CTYPE_BLANK = (1 << 7)
};

#define __isctype(___ch, ___type) ((__ctype_table[(int)___ch] & (___type)) != 0)

#define isalnum(___ch) (isalpha(___ch) || isdigit(___ch))
#define isalpha(___ch) (isupper(___ch) || islower(___ch))
#define isascii(___ch) (((unsigned char)___ch) <= 127)
#define isblank(___ch) (__isctype(___ch, CTYPE_BLANK))
#define iscntrl(___ch) (__isctype(___ch, CTYPE_CNTRL))
#define isdigit(___ch) (__isctype(___ch, CTYPE_NUMER))
#define isgraph(___ch) (isprint(___ch) && !isspace(___ch))
#define islower(___ch) (__isctype(___ch, CTYPE_LCASE))
#define isprint(___ch) \
    (__isctype(___ch, (CTYPE_UCASE | CTYPE_LCASE | CTYPE_NUMER | CTYPE_WSPAC | CTYPE_PUNCT | CTYPE_BLANK)))
#define ispunct(___ch) (__isctype(___ch, CTYPE_PUNCT))
#define isspace(___ch) (__isctype(___ch, (CTYPE_WSPAC | CTYPE_BLANK)))
#define isupper(___ch) (__isctype(___ch, CTYPE_UCASE))
#define isxdigit(___ch) (__isctype(___ch, CTYPE_HEXAD))

#define _toupper(___ch) (islower(___ch) ? ((___ch)-0x20) : (___ch))
#define _tolower(___ch) (isupper(___ch) ? ((___ch) + 0x20) : (___ch))

#endif  // _PS1_CTYPE_H_
