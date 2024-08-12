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
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "openbios/kernel/flushcache.h"
#include "openbios/main/main.h"

extern const uint8_t _binary_shell_bin_start[];
extern const uint8_t _binary_shell_bin_end[];
extern const uint32_t _binary_psexe_bin_start[];
extern const uint32_t _binary_psexe_bin_end[];

static void copyExecutableData(uintptr_t dest, uintptr_t source, size_t length) {
    // On platforms with a watchdog (currently only the 573), larger binaries
    // must be copied in smaller chunks in order to make sure the watchdog is
    // cleared frequently enough. Konami's kernel offloads this task to a
    // separate binary in the BIOS ROM - with a "Lisenced by Sony" [sic]
    // signature similar to the one required for EXP1 hooks - which then
    // proceeds to chainload the actual shell into memory.
    while (length > 0) {
        size_t chunkLength = (length > 0x8000) ? 0x8000 : length;
        memcpy((void *)dest, (const void *)source, chunkLength);
        clearWatchdog();
        dest += chunkLength;
        source += chunkLength;
        length -= chunkLength;
    }
}

int startShell(uint32_t arg) {
    clearWatchdog();
#ifdef OPENBIOS_USE_EMBEDDED_PSEXE
    if (strncmp("PS-X EXE", (const char *)_binary_psexe_bin_start, 8) == 0) {
        const uint32_t *header = _binary_psexe_bin_start;
        copyExecutableData(header[6], (uintptr_t)&_binary_psexe_bin_start[512], header[7]);
        flushCache();
        ((void (*)(int, char **))header[4])(0, NULL);
    }
#endif
#ifdef OPENBIOS_BOOT_MODE_NO_SHELL
    // Embed a simple jr $ra / nop to simulate a shell being copied and run,
    // so cheat cart hooks and other tricks can still work properly.
    uint32_t *shell = (uint32_t *)0x80030000;
    shell[0] = 0x03e00008;
    shell[1] = 0;
#else
    copyExecutableData(0x80030000, (uintptr_t)_binary_shell_bin_start, _binary_shell_bin_end - _binary_shell_bin_start);
#endif
    flushCache();
    return ((int (*)(int))0x80030000)(arg);
}
