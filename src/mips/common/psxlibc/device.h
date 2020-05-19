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

struct File;

enum FileAction {
    PSXREAD = 1,
    PSXWRITE = 2,
};

enum {
    PSXDTTYPE_CHAR  = 0x01,
    PSXDTTYPE_CONS  = 0x02,
    PSXDTTYPE_BLOCK = 0x04,
    PSXDTTYPE_RAW   = 0x08,
    PSXDTTYPE_FS    = 0x10,
};

typedef void (*device_init)();
typedef int (*device_open)(struct File *, const char * filename);
typedef int (*device_action)(struct File *, enum FileAction);
typedef int (*device_close)(struct File *);
typedef int (*device_ioctl)(struct File *, int cmd, int arg);
typedef int (*device_read)(struct File *, void * buffer, int size);
typedef int (*device_write)(struct File *, void * buffer, int size);
typedef void (*device_deinit)();

struct Device {
    char * name;
    uint32_t flags /* PSXDTTYPE_* */;
    uint32_t blockSize;
    char * desc;
    device_init init;
    device_open open;
    device_action action;
    device_close close;
    device_ioctl ioctl;
    device_read read;
    device_write write;
    void * erase, * undelete;
    void * firstfile, * nextfile, * format, * chdir, * rename;
    device_deinit deinit;
    void * check;
};
