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

#include "openbios/kernel/misc.h"

#include "common/hardware/hwregs.h"
#include "openbios/fileio/fileio.h"
#include "openbios/kernel/globals.h"

void setMemSize(int memSize) {
    uint32_t current = RAM_SIZE;
    switch (memSize) {
        case 2:
            RAM_SIZE = current & ~0x300;
            break;
        case 8:
            RAM_SIZE = current | 0x300;
            break;
        default:
            psxprintf("Effective memory must be 2/8 MBytes\n");
            return;
    }

    __globals60.ramsize = memSize;
    psxprintf("Change effective memory : %d MBytes\n", memSize);
}
