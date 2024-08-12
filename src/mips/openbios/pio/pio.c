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

#include "openbios/pio/pio.h"

#include <stdint.h>
#include <string.h>

struct pioInfo {
    void (*vector)();
    const char signature[124];
};

static const struct pioInfo *preHookInfo = (const struct pioInfo *)0x1f000080;
static const struct pioInfo *postHookInfo = (const struct pioInfo *)0x1f000000;

extern const char *_reset;
static int is_running_from_rom() { return _reset == (const char *)0xbfc00000; }

static const char *const licenseText = "Licensed by Sony Computer Entertainment Inc.";

void runExp1PreHook() {
#ifndef OPENBIOS_BOARD_SYS573
    if (is_running_from_rom() && (strcmp(preHookInfo->signature, licenseText) == 0)) preHookInfo->vector();
#endif
}

void runExp1PostHook() {
#ifndef OPENBIOS_BOARD_SYS573
    if (is_running_from_rom() && (strcmp(postHookInfo->signature, licenseText) == 0)) postHookInfo->vector();
#endif
}
