/*

MIT License

Copyright (c) 2020 PCSX-Redux authors

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

#include "openbios/shell/shell.h"

#include <memory.h>
#include <stdint.h>
#include <string.h>

#include "openbios/kernel/flushcache.h"

extern const uint8_t _binary_shell_bin_start[];
extern const uint8_t _binary_shell_bin_end[];
extern const uint32_t _binary_psexe_bin_start[];
extern const uint32_t _binary_psexe_bin_end[];

int startShell(uint32_t arg) {
#ifdef OPENBIOS_USE_EMBEDDED_PSEXE
    if (strncmp("PS-X EXE", (const char *)_binary_psexe_bin_start, 8) == 0) {
        const uint32_t *header = _binary_psexe_bin_start;
        memcpy((uint8_t *)header[6], &_binary_psexe_bin_start[512], header[7]);
        flushCache();
        ((void (*)(int, char **))header[4])(0, NULL);
    }
#endif
#ifdef OPENBIOS_FASTBOOT
    return 0;
#else
    memcpy((uint32_t *)0x80030000, _binary_shell_bin_start, _binary_shell_bin_end - _binary_shell_bin_start);
    flushCache();
    return ((int (*)(int))0x80030000)(arg);
#endif
}
