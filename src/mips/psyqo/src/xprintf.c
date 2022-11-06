/*
** It turns out that the printf functions in the stock MIT pthread library
** is busted.  It isn't thread safe.  If two threads try to do a printf
** of a floating point value at the same time, a core-dump might result.
** So this code is substituted.
*/
/*
** NAME:    $Source: /open/anoncvs/cvs/src/lib/libpthread/stdio/Attic/xprintf.c,v $
** VERSION: $Revision: 1.1 $
** DATE:    $Date: 1998/07/21 13:22:19 $
**
** ONELINER:   A replacement for formatted printing programs.
**
** COPYRIGHT:
**   Copyright (c) 1990 by D. Richard Hipp.  This code is an original
**   work and has been prepared without reference to any prior
**   implementations of similar functions.  No part of this code is
**   subject to licensing restrictions of any telephone company or
**   university.
**
**   This copyright was released and the code placed in the public domain
**   by the author, D. Richard Hipp, on October 3, 1996.
**
** DESCRIPTION:
**   This program is an enhanced replacement for the "printf" programs
**   found in the standard library.  The following enhancements are
**   supported:
**
**      +  Additional functions.  The standard set of "printf" functions
**         includes printf, fprintf, sprintf, vprintf, vfprintf, and
**         vsprintf.  This module adds the following:
**
**           *  snprintf -- Works like sprintf, but has an extra argument
**                          which is the size of the buffer written to.
**
**           *  mprintf --  Similar to sprintf.  Writes output to memory
**                          obtained from mem_alloc.
**
**           *  xprintf --  Calls a function to dispose of output.
**
**           *  nprintf --  No output, but returns the number of characters
**                          that would have been output by printf.
**
**           *  A v- version (ex: vsnprintf) of every function is also
**              supplied.
**
**      +  A few extensions to the formatting notation are supported:
**
**           *  The "=" flag (similar to "-") causes the output to be
**              be centered in the appropriately sized field.
**
**           *  The %b field outputs an integer in binary notation.
**
**           *  The %c field now accepts a precision.  The character output
**              is repeated by the number of times the precision specifies.
**
**           *  The %' field works like %c, but takes as its character the
**              next character of the format string, instead of the next
**              argument.  For example,  printf("%.78'-")  prints 78 minus
**              signs, the same as  printf("%.78c",'-').
**
**      +  When compiled using GCC on a SPARC, this version of printf is
**         faster than the library printf for SUN OS 4.1.
**
**      +  All functions are fully reentrant.
**
*/
/*
** Undefine COMPATIBILITY to make some slight changes in the way things
** work.  I think the changes are an improvement, but they are not
** backwards compatible.
*/
/* #define COMPATIBILITY       / * Compatible with SUN OS 4.1 */
#include "psyqo/xprintf.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include "psyqo/alloc.h"

static __inline__ int isdigit(int c) { return c >= '0' && c <= '9'; }
static __inline__ size_t strlen(const char *s) {
    size_t r = 0;
    while (*s++) r++;
    return r;
}

/*
** The maximum number of digits of accuracy in a floating-point conversion.
*/
#define MAXDIG 20

/*
** Conversion types fall into various categories as defined by the
** following enumeration.
*/
enum e_type {             /* The type of the format field */
              RADIX,      /* Integer types.  %d, %x, %o, and so forth */
              FLOAT,      /* Floating point.  %f */
              EXP,        /* Exponentional notation. %e and %E */
              GENERIC,    /* Floating or exponential, depending on exponent. %g */
              SIZE,       /* Return number of characters processed so far. %n */
              STRING,     /* Strings. %s */
              PERCENT,    /* Percent symbol. %% */
              CHAR,       /* Characters. %c */
              ERROR,      /* Used to indicate no such conversion type */
                          /* The rest are extensions, not normally found in printf() */
              CHARLIT,    /* Literal characters.  %' */
              SEEIT,      /* Strings with visible control characters. %S */
              MEM_STRING, /* A string which should be deleted after use. %z */
              ORDINAL,    /* 1st, 2nd, 3rd and so forth */
};

/*
** Each builtin conversion character (ex: the 'd' in "%d") is described
** by an instance of the following structure
*/
typedef struct s_info { /* Information about each format field */
    int fmttype;        /* The format field code letter */
    int base;           /* The base for radix conversion */
    char *charset;      /* The character set for conversion */
    int flag_signed;    /* Is the quantity signed? */
    char *prefix;       /* Prefix on non-zero values in alt format */
    enum e_type type;   /* Conversion paradigm */
} info;

/*
** The following table is searched linearly, so it is good to put the
** most frequently used conversion types first.
*/
static const info fmtinfo[] = {
    {
        'd',
        10,
        "0123456789",
        1,
        0,
        RADIX,
    },
    {
        's',
        0,
        0,
        0,
        0,
        STRING,
    },
    {
        'S',
        0,
        0,
        0,
        0,
        SEEIT,
    },
    {
        'z',
        0,
        0,
        0,
        0,
        MEM_STRING,
    },
    {
        'c',
        0,
        0,
        0,
        0,
        CHAR,
    },
    {
        'o',
        8,
        "01234567",
        0,
        "0",
        RADIX,
    },
    {
        'u',
        10,
        "0123456789",
        0,
        0,
        RADIX,
    },
    {
        'x',
        16,
        "0123456789abcdef",
        0,
        "x0",
        RADIX,
    },
    {
        'X',
        16,
        "0123456789ABCDEF",
        0,
        "X0",
        RADIX,
    },
    {
        'r',
        10,
        "0123456789",
        0,
        0,
        ORDINAL,
    },
    {
        'f',
        0,
        0,
        1,
        0,
        FLOAT,
    },
    {
        'e',
        0,
        "e",
        1,
        0,
        EXP,
    },
    {
        'E',
        0,
        "E",
        1,
        0,
        EXP,
    },
    {
        'g',
        0,
        "e",
        1,
        0,
        GENERIC,
    },
    {
        'G',
        0,
        "E",
        1,
        0,
        GENERIC,
    },
    {
        'i',
        10,
        "0123456789",
        1,
        0,
        RADIX,
    },
    {
        'n',
        0,
        0,
        0,
        0,
        SIZE,
    },
    {
        'S',
        0,
        0,
        0,
        0,
        SEEIT,
    },
    {
        '%',
        0,
        0,
        0,
        0,
        PERCENT,
    },
    {
        'b',
        2,
        "01",
        0,
        "b0",
        RADIX,
    }, /* Binary notation */
    {
        'p',
        16,
        "0123456789abcdef",
        0,
        "x0",
        RADIX,
    }, /* Pointers */
    {
        '\'',
        0,
        0,
        0,
        0,
        CHARLIT,
    }, /* Literal char */
};
#define NINFO (sizeof(fmtinfo) / sizeof(info)) /* Size of the fmtinfo table */

/*
** Setting the size of the BUFFER involves trade-offs.  No %d or %f
** conversion can have more than BUFSIZE characters.  If the field
** width is larger than BUFSIZE, it is silently shortened.  On the
** other hand, this routine consumes more stack space with larger
** BUFSIZEs.  If you have some threads for which you want to minimize
** stack space, you should keep BUFSIZE small.
*/
#define BUFSIZE 100 /* Size of the output buffer */

/*
** The root program.  All variations call this core.
**
** INPUTS:
**   func   This is a pointer to a function taking three arguments
**            1. A pointer to the list of characters to be output
**               (Note, this list is NOT null terminated.)
**            2. An integer number of characters to be output.
**               (Note: This number might be zero.)
**            3. A pointer to anything.  Same as the "arg" parameter.
**
**   arg    This is the pointer to anything which will be passed as the
**          third argument to "func".  Use it for whatever you like.
**
**   fmt    This is the format string, as in the usual print.
**
**   ap     This is a pointer to a list of arguments.  Same as in
**          vfprint.
**
** OUTPUTS:
**          The return value is the total number of characters sent to
**          the function "func".  Returns -1 on a error.
**
** Note that the order in which automatic variables are declared below
** seems to make a big difference in determining how fast this beast
** will run.
*/
int vxprintf(func, arg, format, ap) void (*func)(const char *, int, void *);
void *arg;
const char *format;
va_list ap;
{
    register const char *fmt; /* The format string. */
    register int c;           /* Next character in the format string */
    register char *bufpt;     /* Pointer to the conversion buffer */
    register int precision;   /* Precision of the current field */
    register int length;      /* Length of the field */
    register int idx;         /* A general purpose loop counter */
    int count;                /* Total number of characters output */
    int width;                /* Width of the current field */
    int flag_leftjustify;     /* True if "-" flag is present */
    int flag_plussign;        /* True if "+" flag is present */
    int flag_blanksign;       /* True if " " flag is present */
    int flag_alternateform;   /* True if "#" flag is present */
    int flag_zeropad;         /* True if field width constant starts with zero */
    int flag_long;            /* True if "l" flag is present */
    int flag_center;          /* True if "=" flag is present */
    unsigned long longvalue;  /* Value for integer types */
    long double realvalue;    /* Value for real types */
    const info *infop;        /* Pointer to the appropriate info structure */
    char buf[BUFSIZE];        /* Conversion buffer */
    char prefix;              /* Prefix character.  "+" or "-" or " " or '\0'. */
    int errorflag = 0;        /* True if an error is encountered */
    enum e_type xtype;        /* Conversion paradigm */
    char *zMem = NULL;        /* String to be freed */
    static const char spaces[] = "                                                    ";
#define SPACESIZE (sizeof(spaces) - 1)

    fmt = format; /* Put in a register for speed */
    count = length = 0;
    bufpt = 0;
    for (; (c = (*fmt)) != 0; ++fmt) {
        if (c != '%') {
            register int amt;
            bufpt = (char *)fmt;
            amt = 1;
            while ((c = (*++fmt)) != '%' && c != 0) amt++;
            (*func)(bufpt, amt, arg);
            count += amt;
            if (c == 0) break;
        }
        if ((c = (*++fmt)) == 0) {
            errorflag = 1;
            (*func)("%", 1, arg);
            count++;
            break;
        }
        /* Find out what flags are present */
        flag_leftjustify = flag_plussign = flag_blanksign = flag_alternateform = flag_zeropad = flag_center = 0;
        do {
            switch (c) {
                case '-':
                    flag_leftjustify = 1;
                    c = 0;
                    break;
                case '+':
                    flag_plussign = 1;
                    c = 0;
                    break;
                case ' ':
                    flag_blanksign = 1;
                    c = 0;
                    break;
                case '#':
                    flag_alternateform = 1;
                    c = 0;
                    break;
                case '0':
                    flag_zeropad = 1;
                    c = 0;
                    break;
                case '=':
                    flag_center = 1;
                    c = 0;
                    break;
                default:
                    break;
            }
        } while (c == 0 && (c = (*++fmt)) != 0);
        if (flag_center) flag_leftjustify = 0;
        /* Get the field width */
        width = 0;
        if (c == '*') {
            width = va_arg(ap, int);
            if (width < 0) {
                flag_leftjustify = 1;
                width = -width;
            }
            c = *++fmt;
        } else {
            while (isdigit(c)) {
                width = width * 10 + c - '0';
                c = *++fmt;
            }
        }
        if (width > BUFSIZE - 10) {
            width = BUFSIZE - 10;
        }
        /* Get the precision */
        if (c == '.') {
            precision = 0;
            c = *++fmt;
            if (c == '*') {
                precision = va_arg(ap, int);
#ifndef COMPATIBILITY
                /* This is sensible, but SUN OS 4.1 doesn't do it. */
                if (precision < 0) precision = -precision;
#endif
                c = *++fmt;
            } else {
                while (isdigit(c)) {
                    precision = precision * 10 + c - '0';
                    c = *++fmt;
                }
            }
            /* Limit the precision to prevent overflowing buf[] during conversion */
            if (precision > BUFSIZE - 40) precision = BUFSIZE - 40;
        } else {
            precision = -1;
        }
        /* Get the conversion type modifier */
        if (c == 'l') {
            flag_long = 1;
            c = *++fmt;
        } else {
            flag_long = 0;
        }
        /* Fetch the info entry for the field */
        infop = 0;
        for (idx = 0; idx < NINFO; idx++) {
            if (c == fmtinfo[idx].fmttype) {
                infop = &fmtinfo[idx];
                break;
            }
        }
        /* No info entry found.  It must be an error. */
        if (infop == 0) {
            xtype = ERROR;
        } else {
            xtype = infop->type;
            if (c == 'p') {
                flag_alternateform = 1;
                width = sizeof(uintptr_t) * 2;
            }
        }

        /*
        ** At this point, variables are initialized as follows:
        **
        **   flag_alternateform          TRUE if a '#' is present.
        **   flag_plussign               TRUE if a '+' is present.
        **   flag_leftjustify            TRUE if a '-' is present or if the
        **                               field width was negative.
        **   flag_zeropad                TRUE if the width began with 0.
        **   flag_long                   TRUE if the letter 'l' (ell) prefixed
        **                               the conversion character.
        **   flag_blanksign              TRUE if a ' ' is present.
        **   width                       The specified field width.  This is
        **                               always non-negative.  Zero is the default.
        **   precision                   The specified precision.  The default
        **                               is -1.
        **   xtype                       The class of the conversion.
        **   infop                       Pointer to the appropriate info struct.
        */
        switch (xtype) {
            case ORDINAL:
            case RADIX:
                if (flag_long)
                    longvalue = va_arg(ap, long);
                else
                    longvalue = va_arg(ap, int);
#ifdef COMPATIBILITY
                /* For the format %#x, the value zero is printed "0" not "0x0".
                ** I think this is stupid. */
                if (longvalue == 0) flag_alternateform = 0;
#else
                /* More sensible: turn off the prefix for octal (to prevent "00"),
                ** but leave the prefix for hex. */
                if (longvalue == 0 && infop->base == 8) flag_alternateform = 0;
#endif
                if (infop->flag_signed) {
                    if (*(long *)&longvalue < 0) {
                        longvalue = -*(long *)&longvalue;
                        prefix = '-';
                    } else if (flag_plussign)
                        prefix = '+';
                    else if (flag_blanksign)
                        prefix = ' ';
                    else
                        prefix = 0;
                } else
                    prefix = 0;
                if (flag_zeropad && precision < width - (prefix != 0)) {
                    precision = width - (prefix != 0);
                }
                bufpt = &buf[BUFSIZE];
                if (xtype == ORDINAL) {
                    long a, b;
                    a = longvalue % 10;
                    b = longvalue % 100;
                    bufpt -= 2;
                    if (a == 0 || a > 3 || (b > 10 && b < 14)) {
                        bufpt[0] = 't';
                        bufpt[1] = 'h';
                    } else if (a == 1) {
                        bufpt[0] = 's';
                        bufpt[1] = 't';
                    } else if (a == 2) {
                        bufpt[0] = 'n';
                        bufpt[1] = 'd';
                    } else if (a == 3) {
                        bufpt[0] = 'r';
                        bufpt[1] = 'd';
                    }
                }
                {
                    register char *cset; /* Use registers for speed */
                    register int base;
                    cset = infop->charset;
                    base = infop->base;
                    do { /* Convert to ascii */
                        *(--bufpt) = cset[longvalue % base];
                        longvalue = longvalue / base;
                    } while (longvalue > 0);
                }
                length = (int)(&buf[BUFSIZE] - bufpt);
                for (idx = precision - length; idx > 0; idx--) {
                    *(--bufpt) = '0'; /* Zero pad */
                }
                if (prefix) *(--bufpt) = prefix;           /* Add sign */
                if (flag_alternateform && infop->prefix) { /* Add "0" or "0x" */
                    char *pre, x;
                    pre = infop->prefix;
                    if (*bufpt != pre[0]) {
                        for (pre = infop->prefix; (x = (*pre)) != 0; pre++) *(--bufpt) = x;
                    }
                }
                length = (int)(&buf[BUFSIZE] - bufpt);
                break;
            case FLOAT:
            case EXP:
            case GENERIC:
                realvalue = va_arg(ap, double);
                break;
            case SIZE:
                *(va_arg(ap, int *)) = count;
                length = width = 0;
                break;
            case PERCENT:
                buf[0] = '%';
                bufpt = buf;
                length = 1;
                break;
            case CHARLIT:
            case CHAR:
                c = buf[0] = (xtype == CHAR ? va_arg(ap, int) : *++fmt);
                if (precision >= 0) {
                    for (idx = 1; idx < precision; idx++) buf[idx] = c;
                    length = precision;
                } else {
                    length = 1;
                }
                bufpt = buf;
                break;
            case STRING:
            case MEM_STRING:
                zMem = bufpt = va_arg(ap, char *);
                if (bufpt == 0) bufpt = "(null)";
                length = strlen(bufpt);
                if (precision >= 0 && precision < length) length = precision;
                break;
            case SEEIT: {
                int i;
                int c;
                char *arg = va_arg(ap, char *);
                for (i = 0; i < BUFSIZE - 1 && (c = *arg++) != 0; i++) {
                    if (c < 0x20 || c >= 0x7f) {
                        buf[i++] = '^';
                        buf[i] = (c & 0x1f) + 0x40;
                    } else {
                        buf[i] = c;
                    }
                }
                bufpt = buf;
                length = i;
                if (precision >= 0 && precision < length) length = precision;
            } break;
            case ERROR:
                buf[0] = '%';
                buf[1] = c;
                errorflag = 0;
                idx = 1 + (c != 0);
                (*func)("%", idx, arg);
                count += idx;
                if (c == 0) fmt--;
                break;
        } /* End switch over the format type */
        /*
        ** The text of the conversion is pointed to by "bufpt" and is
        ** "length" characters long.  The field width is "width".  Do
        ** the output.
        */
        if (!flag_leftjustify) {
            register int nspace;
            nspace = width - length;
            if (nspace > 0) {
                if (flag_center) {
                    nspace = nspace / 2;
                    width -= nspace;
                    flag_leftjustify = 1;
                }
                count += nspace;
                while (nspace >= SPACESIZE) {
                    (*func)(spaces, SPACESIZE, arg);
                    nspace -= SPACESIZE;
                }
                if (nspace > 0) (*func)(spaces, nspace, arg);
            }
        }
        if (length > 0) {
            (*func)(bufpt, length, arg);
            count += length;
        }
        if (xtype == MEM_STRING && zMem) {
            psyqo_free(zMem);
        }
        if (flag_leftjustify) {
            register int nspace;
            nspace = width - length;
            if (nspace > 0) {
                count += nspace;
                while (nspace >= SPACESIZE) {
                    (*func)(spaces, SPACESIZE, arg);
                    nspace -= SPACESIZE;
                }
                if (nspace > 0) (*func)(spaces, nspace, arg);
            }
        }
    } /* End for loop over the format string */
    return errorflag ? -1 : count;
} /* End of function */

/*
** Now for string-print, also as found in any standard library.
** Add to this the snprint function which stops added characters
** to the string at a given length.
**
** Note that snprint returns the length of the string as it would
** be if there were no limit on the output.
*/
struct s_strargument { /* Describes the string being written to */
    char *next;        /* Next free slot in the string */
    char *last;        /* Last available slot in the string */
};

static void sout(txt, amt, arg) char *txt;
int amt;
void *arg;
{
    register char *head;
    register const char *t;
    register int a;
    register char *tail;
    a = amt;
    t = txt;
    head = ((struct s_strargument *)arg)->next;
    tail = ((struct s_strargument *)arg)->last;
    if (tail) {
        while (a-- > 0 && head < tail) *(head++) = *(t++);
    } else {
        while (a-- > 0) *(head++) = *(t++);
    }
    *head = 0;
    ((struct s_strargument *)arg)->next = head;
}

int vsprintf(char *buf, const char *fmt, va_list ap) {
    struct s_strargument arg;
    arg.next = buf;
    arg.last = 0;
    *buf = 0;
    return vxprintf(sout, &arg, fmt, ap);
}
int vsnprintf(char *buf, size_t n, const char *fmt, va_list ap) {
    struct s_strargument arg;
    arg.next = buf;
    arg.last = &buf[n - 1];
    *buf = 0;
    return vxprintf(sout, &arg, fmt, ap);
}

/*
** The following section of code handles the mprintf routine, that
** writes to memory obtained from malloc().
*/

/* This structure is used to store state information about the
** write in progress
*/
struct sgMprintf {
    char *zBase; /* A base allocation */
    char *zText; /* The string collected so far */
    int nChar;   /* Length of the string so far */
    int nAlloc;  /* Amount of space allocated in zText */
};

/* The xprintf callback function. */
static void mout(zNewText, nNewChar, arg) char *zNewText;
int nNewChar;
void *arg;
{
    struct sgMprintf *pM = (struct sgMprintf *)arg;
    if (pM->nChar + nNewChar + 1 > pM->nAlloc) {
        pM->nAlloc = pM->nChar + nNewChar * 2 + 1;
        if (pM->zText == pM->zBase) {
            pM->zText = psyqo_malloc(pM->nAlloc);
            if (pM->zText && pM->nChar) __builtin_memcpy(pM->zText, pM->zBase, pM->nChar);
        } else {
            pM->zText = psyqo_realloc(pM->zText, pM->nAlloc);
        }
    }
    if (pM->zText) {
        __builtin_memcpy(&pM->zText[pM->nChar], zNewText, nNewChar);
        pM->nChar += nNewChar;
        pM->zText[pM->nChar] = 0;
    }
}

/*
** mprintf() works like printf(), but allocations memory to hold the
** resulting string and returns a pointer to the allocated memory.
**
** We changed the name to TclMPrint() to conform with the Tcl private
** routine naming conventions.
*/

/* This is the varargs version of mprintf.
**
** The name is changed to TclVMPrintf() to conform with Tcl naming
** conventions.
*/
int vasprintf(char **out, const char *zFormat, va_list ap) {
    struct sgMprintf sMprintf;
    char zBuf[200];
    int r;
    sMprintf.nChar = 0;
    sMprintf.zText = zBuf;
    sMprintf.nAlloc = sizeof(zBuf);
    sMprintf.zBase = zBuf;
    r = vxprintf(mout, &sMprintf, zFormat, ap);
    if (sMprintf.zText == sMprintf.zBase) {
        sMprintf.zText = psyqo_malloc(strlen(zBuf) + 1);
        if (sMprintf.zText) __builtin_strcpy(sMprintf.zText, zBuf);
    } else {
        sMprintf.zText = psyqo_realloc(sMprintf.zText, sMprintf.nChar + 1);
    }
    *out = sMprintf.zText;
    return r;
}
