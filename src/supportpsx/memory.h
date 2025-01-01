/***************************************************************************
 *   Copyright (C) 2025 PCSX-Redux authors                                 *
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

#include <optional>

namespace PCSX {

struct PSXAddress {
    explicit PSXAddress(uint32_t virt) {
        physical = virt & 0x1fffffff;
        if (virt == 0xfffe0130) {
            segment = Segment::Internal;
            type = Type::Internal;
            return;
        }
        uint32_t top = virt >> 29;
        switch (top) {
            case 0:
                segment = Segment::KUSEG;
                break;
            case 4:
                segment = Segment::KSEG0;
                break;
            case 5:
                segment = Segment::KSEG1;
                break;
            default:
                segment = Segment::Invalid;
                return;
                break;
        }
        if (physical < 0x1f000000) {
            type = Type::RAM;
        } else if (physical < 0x1f800000) {
            type = Type::EXP1;
            physical -= 0x1f000000;
        } else if (physical < 0x1f801000) {
            type = Type::ScratchPad;
            physical -= 0x1f800000;
        } else if (physical < 0x1f802000) {
            type = Type::HardwareRegisters;
            physical -= 0x1f801000;
        } else if (physical < 0x1fa00000) {
            type = Type::EXP2;
            physical -= 0x1f802000;
        } else if (physical < 0x1fc00000) {
            physical -= 0x1fa00000;
            type = Type::EXP3;
        } else {
            physical -= 0x1fc00000;
            type = Type::ROM;
        }
    }
    std::optional<uint32_t> toVirtual() const {
        if ((segment == Segment::Internal) && (type == Type::Internal)) {
            return 0xfffe0130;
        }
        if (segment == Segment::Invalid) return {};
        uint32_t ret = physical;
        switch (type) {
            case Type::RAM:
                break;
            case Type::EXP1:
                ret += 0x1f000000;
                break;
            case Type::ScratchPad:
                ret += 0x1f800000;
                break;
            case Type::HardwareRegisters:
                ret += 0x1f801000;
                break;
            case Type::EXP2:
                ret += 0x1f802000;
                break;
            case Type::EXP3:
                ret += 0x1fa00000;
                break;
            case Type::ROM:
                ret += 0x1fc00000;
                break;
        }
        switch (segment) {
            case Segment::KUSEG:
                return ret;
            case Segment::KSEG0:
                return ret | 0x80000000;
            case Segment::KSEG1:
                return ret | 0xa0000000;
        }
    }

    uint32_t physical = 0;
    enum class Type {
        RAM,
        EXP1,
        ScratchPad,
        HardwareRegisters,
        EXP2,
        EXP3,
        ROM,
        Internal,
    } type = Type::RAM;
    enum class Segment {
        KUSEG,
        KSEG0,
        KSEG1,
        Internal,
        Invalid,
    } segment = Segment::Invalid;
};

}  // namespace PCSX
