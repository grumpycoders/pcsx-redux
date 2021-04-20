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

#include <stdint.h>

namespace n2e_d {

// see the file n2e-d.S for the source of this code
// its source is a bit too complex for the compile-time encoder

static constexpr uint32_t code[] = {
    0x03e0c825, 0x00004025, 0x240a0001, 0x3c0e00ff, 0x04110046, 0x00000000, 0x10400006, 0x240b0001, 0x90890000,
    0x24840001, 0xa0a90000, 0x1000fff8, 0x24a50001, 0x0411003d, 0x000b5840, 0x0411003b, 0x01625821, 0x14400005,
    0x256bffff, 0x04110037, 0x000b5840, 0x1000fff7, 0x01625821, 0x256bffff, 0x15600005, 0x00000000, 0x04110030,
    0x01405825, 0x1000000e, 0x00406025, 0x256bffff, 0x90890000, 0x000b5a00, 0x24840001, 0x01695821, 0x25690001,
    0x15200002, 0x00000000, 0x03200008, 0x312c0001, 0x000b5842, 0x256b0001, 0x01605025, 0x0411001f, 0x00000000,
    0x11800003, 0x00000000, 0x1000000f, 0x244c0003, 0x1440000a, 0x00000000, 0x258c0001, 0x04110016, 0x000c6040,
    0x04110014, 0x01826021, 0x1040fffb, 0x00000000, 0x10000004, 0x258c0005, 0x0411000e, 0x00000000, 0x244c0005,
    0x2d690501, 0x01896023, 0x00ab6823, 0x91a90000, 0x25ad0001, 0xa0a90000, 0x00000000, 0x258cffff, 0x1580fffa,
    0x24a50001, 0x1000ffba, 0x00000000, 0x010e4824, 0x15200004, 0x00000000, 0x90890000, 0x24840001, 0x012e4025,
    0x000811c2, 0x00084040, 0x03e00008, 0x30420001,
};

}  // namespace n2e_d
