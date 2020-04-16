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

#include <stdint.h>

#include "common/psxlibc/stdio.h"

enum FileAction {
    PSXREAD = 1,
    PSXWRITE = 2,
};

typedef void (*device_init)();
typedef int (*device_action)(struct File *, enum FileAction);
typedef int (*device_close)(struct File *);
typedef int (*device_ioctl)(struct File *, int cmd, int arg);
typedef int (*device_write)(struct File *, void * buffer, int size);
typedef void (*device_deinit)();

struct Device {
    char * name;
    uint32_t flags;
    uint32_t blockSize;
    char * desc;
    device_init init;
    void * open;
    device_action action;
    device_close close;
    device_ioctl ioctl;
    void * read;
    device_write write;
    void * erase, * undelete;
    void * firstfile, * nextfile, * format, * chdir, * rename;
    device_deinit deinit;
    void * check;
};
