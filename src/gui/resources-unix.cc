/***************************************************************************
 *   Copyright (C) 2021 PCSX-Redux authors                                 *
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

#ifndef _WIN32

#include "gui/resources.h"
#include "support/file.h"

void PCSX::Resources::loadIcon(std::function<void(const uint8_t*, uint32_t)> process) {
    std::filesystem::path fname = "pcsx-redux.ico";
    std::filesystem::path dir = "resources";
    File* ico = nullptr;
    ico = new File(fname);
    if (ico->failed()) {
        delete ico;
        ico = new File(dir / fname);
    }
    if (ico->failed()) {
        delete ico;
        ico = new File(g_system->getBinDir() / fname);
    }
    if (ico->failed()) {
        delete ico;
        ico = new File(g_system->getBinDir() / dir / fname);
    }
    if (ico->failed()) {
        delete ico;
        ico = new File(std::filesystem::current_path() / fname);
    }
    if (ico->failed()) {
        delete ico;
        ico = new File(std::filesystem::current_path() / dir / fname);
    }
    if (ico->failed()) {
        delete ico;
        ico = new File(g_system->getBinDir() / ".." / "share" / "pcsx-redux" / fname);
    }
    do {
        if (ico->failed()) break;
        if (ico->read<uint16_t>() != 0) break;
        if (ico->read<uint16_t>() != 1) break;
        uint16_t count = ico->read<uint16_t>();
        struct {
            uint32_t size, offset;
        } info[count];
        for (unsigned i = 0; i < count; i++) {
            ico->read<uint32_t>();
            ico->read<uint32_t>();
            info[i].size = ico->read<uint32_t>();
            info[i].offset = ico->read<uint32_t>();
        }
        for (unsigned i = 0; i < count; i++) {
            ico->seek(info[i].offset, SEEK_SET);
            auto slice = ico->read(info[i].size);
            process(reinterpret_cast<const uint8_t*>(slice.data()), slice.size());
        }
    } while (false);
    delete ico;
}

#endif
