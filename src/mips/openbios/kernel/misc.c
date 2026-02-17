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

#if defined(OPENBIOS_BOARD_SYS573)
static const char s_kernelName[] = "OpenBIOS (System 573)";
static const int s_kernelFlags = 2;
static const int s_isArcadeBoard = 1;
static const int s_unknownFlag = 0;

static __inline__ int getBoardRevision() { return 0; }
static __inline__ int getVRAMSize() { return 2048; }
static __inline__ int getSPURAMSize() { return 512; }
#elif defined(OPENBIOS_BOARD_ZN)
static const char s_kernelName[] = "OpenBIOS (ZN-1/ZN-2)";
static const int s_kernelFlags = 0x11001; // ZN-1: 0x11001, ZN-2: 0x13000
static const int s_isArcadeBoard = 1;
static const int s_unknownFlag = 1;

static __inline__ int getBoardRevision() { return ((ZN_BOARD_CONFIG >> 5) & 7) - 2; }
static __inline__ int getVRAMSize() { return ((ZN_BOARD_CONFIG >> 3) & 1) ? 2048 : 1024; }
static __inline__ int getSPURAMSize() { return ((ZN_BOARD_CONFIG >> 2) & 1) ? 2048 : 512; }
#else
static const char s_kernelName[] = "OpenBIOS";
static const int s_kernelFlags = 3;
static const int s_isArcadeBoard = 0;
static const int s_unknownFlag = 1;

static __inline__ int getBoardRevision() { return 0; }
static __inline__ int getVRAMSize() { return 1024; }
static __inline__ int getSPURAMSize() { return 512; }
#endif

static __inline__ uint32_t getCPURevision() {
    uint32_t ret;
    asm("mfc0 %0, $15\nnop\n" : "=r"(ret));
    return ret;
}

uint32_t getSystemInfo(int index) {
    switch (index) {
        case 0:
            return 0x20260101;
        case 1:
            return s_kernelFlags;
        case 2:
            return (uint32_t) s_kernelName;
        case 3:
            return getCPURevision();
        case 4:
            return getBoardRevision();
        case 5:
            return __globals60.ramsize << 10;
        case 6:
            return s_isArcadeBoard;
        case 7:
            return getVRAMSize();
        case 9:
            return getSPURAMSize();
        case 12:
        case 13:
            return s_unknownFlag;
        case 14:
            return s_isArcadeBoard ^ 1;
        default:
            return 0;
    }
}

void setMemSize(int memSize) {
    uint32_t value = RAM_SIZE & ~0x700;
    switch (memSize) {
        // The retail BIOS only implements the cases for 2 and 8 MB here,
        // however the 573 and ZN kernels have all cases implemented.
        case 2:
            RAM_SIZE = value;
            break;
        case 4:
            RAM_SIZE = value | 0x400;
            break;
        case 8:
            RAM_SIZE = value | 0x300;
            break;
        case 16:
            RAM_SIZE = value | 0x700;
            break;
        default:
            psxprintf("Effective memory must be 2/4/8/16 MBytes\n");
            return;
    }

    __globals60.ramsize = memSize;
    psxprintf("Change effective memory : %d MBytes\n", memSize);
}
