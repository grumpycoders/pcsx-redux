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
    PSXF_READ = 1,
    PSXF_WRITE = 2,
    PSXF_NBLOCK = 4,
    PSXF_SCAN = 8,
};

struct File {
    uint32_t flags, deviceId;
    char * buffer;
    uint32_t count, offset, deviceFlags, errno;
    struct Device * device;
    uint32_t length, LBA, fd;
};
