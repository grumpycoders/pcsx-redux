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

#include "common/syscalls/syscalls.h"
#include "openbios/cdrom/events.h"

uint32_t g_cdEventACK; /* 0x0010 */
uint32_t g_cdEventDNE; /* 0x0020 */
uint32_t g_cdEventRDY; /* 0x0040 */
uint32_t g_cdEventEND; /* 0x0080 */
uint32_t g_cdEventERR; /* 0x8000 */

// Yes, these undeliver some events that never got created in the first place.
void __attribute__((section(".ramtext"))) cdromUndeliverAllExceptAckAndRdy() {
    syscall_undeliverEvent(0xf0000003, 0x20);
    syscall_undeliverEvent(0xf0000003, 0x80);
    syscall_undeliverEvent(0xf0000003, 0x8000);
    syscall_undeliverEvent(0xf0000003, 0x100); // never created
    syscall_undeliverEvent(0xf0000003, 0x200); // never created
}

void __attribute__((section(".ramtext")))  cdromUndeliverAll() {
    syscall_undeliverEvent(0xf0000003, 0x40);
    syscall_undeliverEvent(0xf0000003, 0x10);
    syscall_undeliverEvent(0xf0000003, 0x20);
    syscall_undeliverEvent(0xf0000003, 0x80);
    syscall_undeliverEvent(0xf0000003, 0x8000);
    syscall_undeliverEvent(0xf0000003, 0x100); // never created
    syscall_undeliverEvent(0xf0000003, 0x200); // never created
}

