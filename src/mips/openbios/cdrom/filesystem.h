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
#include "common/psxlibc/direntry.h"
#include "common/psxlibc/stdio.h"

extern char g_cdromCWD[128];

int cdromReadPathTable();
int dev_cd_open(struct File* file, char* filename);
int dev_cd_read(struct File* file, char* buffer, int size);
struct DirEntry* dev_cd_firstfile(struct File* file, const char* filename, struct DirEntry* entry);
struct DirEntry* dev_cd_nextfile(struct File* file, struct DirEntry* entry);
int dev_cd_chdir(struct File* file, char* name);
