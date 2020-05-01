/***************************************************************************
 *   Copyright (C) 2020 PCSX-Redux authors                                 *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

#pragma once

#include "common/psxlibc/device.h"
#include "common/psxlibc/stdio.h"

int psxopen(const char * fname, int mode);
int psxlseek(int fd, int offset, int whence);
int psxread(int fd, void * buffer, int size);
int psxwrite(int fd, void * buffer, int size);
int psxclose(int fd);
int psxioctl(int fd, int cmd, int arg);
void psxexit();
int isFileConsole(int fd);
int psxgetc(int fd);
void psxputc(int c, int fd);

void psxputchar(int c);
int psxgetchar();
char * psxgets(char * storage);
void psxputs(const char * str);
int psxprintf(const char * msg, ...);
void ioabortraw(int code);

void setupFileIO(int installTTY);
void installStdIo(int installTTY);

struct Device * findDevice(const char * name);
int addDevice(struct Device *);
int removeDevice(const char * name);

struct File * getFileFromHandle(int fd);
struct File * findEmptyFile();

const char * splitFilepathAndFindDevice(const char * name, struct Device ** device, int * deviceId);

extern uint32_t psxerrno;

void cdevscan();
