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

#pragma once

#include "common/hardware/hwregs.h"

#define CDROM_REG0 HW_U8(0x1f801800)
#define CDROM_REG1 HW_U8(0x1f801801)
#define CDROM_REG2 HW_U8(0x1f801802)
#define CDROM_REG3 HW_U8(0x1f801803)

#define CDROM_REG0_UC HW_U8(0xbf801800)
#define CDROM_REG1_UC HW_U8(0xbf801801)
#define CDROM_REG2_UC HW_U8(0xbf801802)
#define CDROM_REG3_UC HW_U8(0xbf801803)

enum {
    CDL_SYNC = 0,
    CDL_NOP = 1,
    CDL_SETLOC = 2,
    CDL_PLAY = 3,
    CDL_FORWARD = 4,
    CDL_BACKWARD = 5,
    CDL_READN = 6,
    CDL_STANDBY = 7,
    CDL_STOP = 8,
    CDL_PAUSE = 9,
    CDL_INIT = 10,
    CDL_MUTE = 11,
    CDL_DEMUTE = 12,
    CDL_SETFILTER = 13,
    CDL_SETMODE = 14,
    CDL_GETMODE = 15,
    CDL_GETLOCL = 16,
    CDL_GETLOCP = 17,
    CDL_READT = 18,
    CDL_GETTN = 19,
    CDL_GETTD = 20,
    CDL_SEEKL = 21,
    CDL_SEEKP = 22,
    CDL_SETCLOCK = 23,
    CDL_GETCLOCK = 24,
    CDL_TEST = 25,
    CDL_GETID = 26,
    CDL_READS = 27,
    CDL_RESET = 28,
    CDL_GETQ = 29,
    CDL_READTOC = 30,
};
