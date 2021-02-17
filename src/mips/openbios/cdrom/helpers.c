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

#include "openbios/cdrom/helpers.h"

#include "common/syscalls/syscalls.h"
#include "openbios/cdrom/events.h"

int cdromBlockReading(int count, int sector, char* buffer) {
    int retries;

    sector += 150;

    /* I can't in good conscience reproduce the bug seen in the retail bios
       code. The following bloc that computes the msf of the sector to read
       is inside the for loop in the retail bios code. Which means that the
       'sector' variable gets mangled every time there's a retry, and
       further retries will always fail or return the wrong sector. */

    int minutes = sector / 4500;
    sector %= 4500;
    uint8_t msf[3] = {(minutes % 10) + (minutes / 10) * 0x10, ((sector / 75) % 10) + ((sector / 75) / 10) * 0x10,
                      ((sector % 75) % 10) + ((sector % 75) / 10) * 0x10};

    for (retries = 0; retries < 10; retries++) {
        int cyclesToWait = 99999;
        while (!syscall_cdromSeekL(msf) && (--cyclesToWait > 0))
            ;

        if (cyclesToWait < 1) {
            syscall_exception(0x44, 0x0b);
            return -1;
        }

        while (!syscall_testEvent(g_cdEventDNE)) {
            if (syscall_testEvent(g_cdEventERR)) {
                syscall_exception(0x44, 0x0c);
                return -1;
            }
        }

        cyclesToWait = 99999;
        while (!syscall_cdromRead(count, buffer, 0x80) && (--cyclesToWait > 0))
            ;
        if (cyclesToWait < 1) {
            syscall_exception(0x44, 0x0c);
            return -1;
        }
        while (1) {
            // Here, the original code basically does the following:
            //   if (cyclesToWait < 1) return 1;
            // which is 1) useless, since cyclesToWait never mutates
            // and 2) senseless as we're supposed to return the
            // number of sectors read.
            // An optimzing compiler would cull it out anyway, so
            // it's no use letting it here.
            if (syscall_testEvent(g_cdEventDNE)) return count;
            if (syscall_testEvent(g_cdEventERR)) break;
            if (syscall_testEvent(g_cdEventEND)) {
                syscall_exception(0x44, 0x17);
                return -1;
            }
        }
        syscall_exception(0x44, 0x16);
    }

    syscall_exception(0x44, 0x0c);
    return -1;
}
