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
    PSXF_READ   = 0x0001,
    PSXF_WRITE  = 0x0002,
    PSXF_NBLOCK = 0x0004,
    PSXF_SCAN   = 0x0008,
    PSXF_RLOCK  = 0x0010,
    PSXF_WLOCK  = 0x0020,
    PSXF_APPEND = 0x0100,
    PSXF_CREAT  = 0x0200,
    PSXF_TRUNC  = 0x0400,
    PSXF_SCAN2  = 0x1000,
    PSXF_RCOM   = 0x2000,
    PSXF_NBUF   = 0x4000,
    PSXF_ASYNC  = 0x8000,
};

enum {
    PSXSEEK_SET = 0,
    PSXSEEK_CUR = 1,
    PSXSEEK_END = 2,
};

struct File {
    uint32_t flags /* PSXF_* */, deviceId;
    char * buffer;
    uint32_t count, offset, deviceFlags, errno;
    struct Device * device;
    uint32_t length, LBA, fd;
};
