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

#include "common/psxlibc/device.h"
#include "common/psxlibc/stdio.h"

int psxopen(const char *fname, int mode);
int psxlseek(int fd, int offset, int whence);
int psxread(int fd, void *buffer, int size);
int psxwrite(int fd, void *buffer, int size);
int psxclose(int fd);
int psxioctl(int fd, int cmd, int arg);
void psxexit(int code);
int isFileConsole(int fd);
int psxgetc(int fd);
void psxputc(int c, int fd);

void psxputchar(int c);
int psxgetchar();
char *psxgets(char *storage);
void psxputs(const char *str);
int psxprintf(const char *msg, ...);
void ioabortraw(int code);

void setupFileIO(int installTTY);
void installStdIo(int installTTY);

struct Device *findDevice(const char *name);
int addDevice(struct Device *);
int removeDevice(const char *name);

struct File *getFileFromHandle(int fd);
struct File *findEmptyFile();

const char *splitFilepathAndFindDevice(const char *name, struct Device **device, int *deviceId);

extern uint32_t psxerrno;

void cdevscan();

struct DirEntry *firstFile(const char *filepath, struct DirEntry *entry);
int format(const char *deviceName);

extern struct File *g_firstFile;

int getDeviceStatus();
void setDeviceStatus(int deviceStatus);
