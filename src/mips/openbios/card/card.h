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

#pragma once

#include "common/psxlibc/direntry.h"
#include "common/psxlibc/stdio.h"

int addMemoryCardDevice();
int initBackupUnit();
int cardInfo(int deviceId);
void buLowLevelOpCompleted();
int buReadTOC(int deviceId);
void buLowLevelOpError1();
void buLowLevelOpError2();
void buLowLevelOpError3();

int dev_bu_open(struct File *file, const char *filename, int mode);
int dev_bu_close(struct File *file);
int dev_bu_read(struct File *file, void *buffer, int size);
int dev_bu_write(struct File *file, void *buffer, int size);
void dev_bu_erase();
void dev_bu_undelete();
struct DirEntry *dev_bu_firstFile(struct File *file, const char *filename, struct DirEntry *entry);
struct DirEntry *dev_bu_nextFile(struct File *file, struct DirEntry *entry);
int dev_bu_format(struct File *file);
void dev_bu_rename();
void dev_bu_deinit();

extern int g_buOpSectorStart[2];
extern int g_buOpSectorCount[2];
extern int g_buOpActualSector[2];
extern char *g_buOpBuffer[2];
extern struct File *g_buOpFile[2];
int buRelativeToAbsoluteSector(int port, int block, int sector);
int buGetReallocated(int port, int sector);
