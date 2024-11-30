/*

MIT License

Copyright (c) 2021 PCSX-Redux authors

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

#include <stddef.h>

#include "common/psxlibc/device.h"
#include "common/psxlibc/direntry.h"
#include "common/psxlibc/stdio.h"
#include "openbios/fileio/fileio.h"

struct DirEntry *firstFile(const char *filepath, struct DirEntry *entry) {
    struct DirEntry *ret;
    int deviceId;
    struct Device *device;
    struct File *file;

    if ((g_firstFile == NULL) && ((g_firstFile = findEmptyFile()) == NULL)) {
        psxerrno = PSXEMFILE;
        return NULL;
    }
    const char *filename = splitFilepathAndFindDevice(filepath, &device, &deviceId);
    file = g_firstFile;
    if (filename == ((char *)-1)) {
        psxerrno = PSXENODEV;
        ret = NULL;
        g_firstFile->flags = 0;
        return NULL;
    } else {
        g_firstFile->deviceId = deviceId;
        file->device = device;
        return device->firstFile(file, filename, entry);
    }
}

struct DirEntry *nextFile(struct DirEntry *entry) { return g_firstFile->device->nextFile(g_firstFile, entry); }

int format(const char *deviceName) {
    struct File *file = findEmptyFile();
    if (!file) {
        psxerrno = PSXEMFILE;
        return 0;
    }

    int deviceId;
    struct Device *device;

    const char *filename = splitFilepathAndFindDevice(deviceName, &device, &deviceId);
    if (filename == (const char *)-1) {
        psxerrno = PSXENODEV;
        file->flags = 0;
        return 0;
    }

    file->deviceId = deviceId;
    file->device = device;
    int res = device->format(file);
    file->flags = 0;
    if (!res) return 1;
    psxerrno = file->errno;
    return 0;
}
