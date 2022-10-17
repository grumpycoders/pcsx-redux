/*

MIT License

Copyright (c) 2022 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

#pragma once

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Prints a formatted string to a callback.
 *
 * @details This function behaves mostly as you'd expect from a typical
 * printf, with some extra formatting options: The '=' flag (similar to
 * '-') causes the output to be centered in the appropriately sized field.
 * The %b field outputs an integer in binary notation. The %c field now
 * accepts a precision. The character output is repeated by the number
 * of times the precision specifies. The %' field works like %c, but
 * takes as its character the next character of the format string,
 * instead of the next. This is useful for when using the precision
 * modifier. For example, `printf("%.78'-")` prints 78 minus signs, the
 * same as `printf("%.78c", '-')` would. %S will display a string that
 * has its control characters escaped using the caret notation. For
 * example, character 26, also known as EOF, will be displayed as ^Z.
 * %z will display a string, and immediately dispose of it using
 * `psyqo_free()`. %r will display a number as an English ordinal.
 * For example, 1 will be displayed as "1st", 2 as "2nd", etc...
 * Finally, one difference with normal printf, is that %#x will
 * output "0x0" instead of "0" for the value 0. Note that floating
 * point formatting will not be available. The callback function will
 * be called with the string to print, and the length of the string. The
 * third argument will be the opaque pointer passed through.
 * The `xprintf` variant is available.
 *
 * @param func The callback function to use.
 * @param opaque The opaque pointer to pass to the callback.
 * @param fmt The format string.
 * @param ap The vararg list of arguments.
 * @return int The number of bytes written.
 */
int vxprintf(void (*func)(const char *, int, void *), void *opaque, const char *fmt, va_list ap);

/**
 * @brief Prints a formatted string to a string.
 *
 * @details This function is a helper around `vxprintf`, which will
 * print to a string, and otherwise behaves the same as normal
 * libc (v)sprintf.
 *
 * @param buf The buffer to print to.
 * @param fmt The format string.
 * @param ap The vararg list of arguments.
 * @return int The number of bytes written.
 */
int vsprintf(char *buf, const char *fmt, va_list ap);

/**
 * @brief Prints a formatted string to a length-limited string.
 *
 * @details This function is a helper around `vxprintf`, which will
 * print to a string, and otherwise behaves the same as normal
 * libc (v)snprintf.
 *
 * @param buf The buffer to print to.
 * @param n The maximum number of bytes to write, including the
 * terminating null byte.
 * @param fmt The format string.
 * @param ap The vararg list of arguments.
 * @return int The number of bytes written.
 */
int vsnprintf(char *buf, size_t n, const char *fmt, va_list ap);

/**
 * @brief Prints a formatted string to a newly allocated string.
 *
 * @details This function is a helper around `vxprintf`, which will
 * print to a string, and otherwise behaves the same as normal
 * glibc (v)asprintf. The string will be allocated using
 * `psyqo_malloc()`, and must be freed using `psyqo_free()`.
 *
 * @param out The pointer to the string to allocate.
 * @param fmt The format string.
 * @param ap The vararg list of arguments.
 * @return int The number of bytes written.
 */
int vasprintf(char **out, const char *fmt, va_list ap);

static inline int xprintf(void (*func)(const char *, int, void *), void *arg, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int ret = vxprintf(func, arg, fmt, ap);
    va_end(ap);
    return ret;
}

static inline int sprintf(char *buf, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int ret = vsprintf(buf, fmt, ap);
    va_end(ap);
    return ret;
}

static inline int snprintf(char *buf, size_t n, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int ret = vsnprintf(buf, n, fmt, ap);
    va_end(ap);
    return ret;
}

static inline int asprintf(char **out, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int ret = vasprintf(out, fmt, ap);
    va_end(ap);
    return ret;
}

#ifdef __cplusplus
}

#include <EASTL/fixed_string.h>
#include <EASTL/string.h>

/**
 * @brief Prints a formatted string to a C++ eastl::fixed_string.
 *
 * @details This function is a helper around `vxprintf`. The
 * `sprintf` variant is available.
 *
 * @param str The string to print to.
 * @param fmt The format string.
 * @param ap The vararg list of arguments.
 */
template <int nodeCount, bool bEnableOverflow = true>
static inline void vfsprintf(eastl::fixed_string<char, nodeCount, bEnableOverflow> &str, const char *fmt, va_list ap) {
    vxprintf(
        [](const char *str, int len, void *opaque) {
            eastl::fixed_string<char, nodeCount, bEnableOverflow> *out =
                (eastl::fixed_string<char, nodeCount, bEnableOverflow> *)opaque;
            out->append(str, len);
        },
        &str, fmt, ap);
}

template <int nodeCount, bool bEnableOverflow = true>
static inline void fsprintf(eastl::fixed_string<char, nodeCount, bEnableOverflow> &str, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfsprintf<nodeCount, bEnableOverflow>(str, fmt, ap);
    va_end(ap);
}

/**
 * @brief Prints a formatted string to a C++ eastl::string.
 *
 * @details This function is a helper around `vxprintf`. The
 * `sprintf` variant is available.
 *
 * @param fmt The format string.
 * @param ap The vararg list of arguments.
 * @return eastl::string The formatted string.
 */
static inline eastl::string vsprintf(const char *fmt, va_list ap) {
    eastl::string ret;
    vxprintf(
        [](const char *str, int len, void *opaque) {
            eastl::string *ret = (eastl::string *)opaque;
            ret->append(str, len);
        },
        &ret, fmt, ap);
    return ret;
}

static inline eastl::string sprintf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    eastl::string ret = vsprintf(fmt, ap);
    va_end(ap);
    return ret;
}

#endif
