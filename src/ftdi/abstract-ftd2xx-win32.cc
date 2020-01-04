/***************************************************************************
 *   Copyright (C) 2019 PCSX-Redux authors                                 *
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

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#include "ftd2xx.h"
#include "ftdi/abstract.h"

static std::vector<PCSX::FTDI::Device> s_devices;

void PCSX::FTDI::DeviceList::scan() {
    FT_STATUS status;
    DWORD numDevs = 0;

    s_devices.clear();
    status = FT_CreateDeviceInfoList(&numDevs);

    if (status != FT_OK || numDevs == 0) return;

    FT_DEVICE_LIST_INFO_NODE* nodes = new FT_DEVICE_LIST_INFO_NODE[numDevs];

    status = FT_GetDeviceInfoList(nodes, &numDevs);

    if (status == FT_OK && numDevs != 0) {
        s_devices.resize(numDevs);
        for (DWORD i = 0; i < numDevs; i++) {
            const FT_DEVICE_LIST_INFO_NODE* n = nodes + i;
            s_devices[i].m_locked = n->Flags & FT_FLAGS_OPENED;
            s_devices[i].m_highSpeed = n->Flags & FT_FLAGS_HISPEED;
            s_devices[i].m_vendorID = (n->ID >> 16) & 0xffff;
            s_devices[i].m_deviceID = n->ID & 0xffff;
            s_devices[i].m_type = n->Type;
            s_devices[i].m_serial = n->SerialNumber;
            s_devices[i].m_description = n->Description;
        }
    }

    delete[] nodes;
}

const std::vector<PCSX::FTDI::Device>& PCSX::FTDI::DeviceList::get() { return s_devices; }

#endif
