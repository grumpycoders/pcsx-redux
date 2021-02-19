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

#include "common/compiler/stdint.h"
#include "common/psxlibc/device.h"

enum {
    PSXENOERR,
    PSXEPERM,
    PSXENOENT,
    PSXESRCH,
    PSXEINTR,
    PSXEIO,
    PSXENXIO,
    PSXE2BIG,
    PSXENOEXEC,
    PSXEBADF,
    PSXECHILD,
    PSXEAGAIN,
    PSXENOMEM,
    PSXEACCESS,
    PSXEFAULT,
    PSXENOTBLK,
    PSXEBUSY,
    PSXEEXIST,
    PSXEXDEV,
    PSXENODEV,
    PSXENOTDIR,
    PSXEISDIR,
    PSXEINVAL,
    PSXENFILE,
    PSXEMFILE,
    PSXENOTTY,
    PSXETXTBSY,
    PSXEFBIG,
    PSXENOSPC,
    PSXESPIPE,
    PSXEROFS,
    PSXEFORMAT,
    PSXEPIPE,
    PSXEDOM,
    PSXERANGE,
    PSXEWOULDBLOCK,
    PSXEINPROGRESS,
    PSXEALREADY,
};

enum {
    PSXF_READ = 0x0001,
    PSXF_WRITE = 0x0002,
    PSXF_NBLOCK = 0x0004,
    PSXF_SCAN = 0x0008,
    PSXF_RLOCK = 0x0010,
    PSXF_WLOCK = 0x0020,
    PSXF_APPEND = 0x0100,
    PSXF_CREAT = 0x0200,
    PSXF_TRUNC = 0x0400,
    PSXF_SCAN2 = 0x1000,
    PSXF_RCOM = 0x2000,
    PSXF_NBUF = 0x4000,
    PSXF_ASYNC = 0x8000,
};

enum {
    PSXSEEK_SET = 0,
    PSXSEEK_CUR = 1,
    PSXSEEK_END = 2,
};

struct File {
    uint32_t flags /* PSXF_* */, deviceId;
    char* buffer;
    uint32_t count, offset, deviceFlags, errno;
    struct Device* device;
    uint32_t length, LBA, fd;
};
