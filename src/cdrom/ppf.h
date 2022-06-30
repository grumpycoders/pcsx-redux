/***************************************************************************
 *   Copyright (C) 2022 PCSX-Redux authors                                 *
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

#include <filesystem>
#include <list>
#include <string>
#include <string_view>
#include <utility>

#include "cdrom/iec-60908b.h"
#include "support/hashtable.h"

namespace PCSX {

class PPF {
  public:
    ~PPF() { clear(); }
    void clear() { m_patches.destroyAll(); }
    // given an input iso filename, attempt to load its corresponding ppf
    bool load(std::filesystem::path iso);
    // given an input iso filename, create a new ppf1 file for it from memory patches
    void save(std::filesystem::path iso);
    // apply ppf patches to a sector
    void maybePatchSector(uint8_t *sector, IEC60908b::MSF) const;
    // inject a new patch in memory based on the difference between two sectors
    void calculatePatch(const uint8_t *in, const uint8_t *out, IEC60908b::MSF);
    // inject a new patch in memory using an offset - this allowed to straddle across sectors
    void injectPatch(std::string_view data, uint32_t offset, IEC60908b::MSF);

    void simplify();
    void simplify(IEC60908b::MSF msf);

    std::string m_description;
    std::string m_fileIdDiz;

  private:
    struct Patch;
    void simplify(Patch &);
    struct MSFHash {
        static constexpr uint32_t hash(const IEC60908b::MSF &key) {
            uint32_t a = key.toLBA();
            a = (a ^ 61) ^ (a >> 16);
            a += (a << 3);
            a ^= (a >> 4);
            a *= 0x27d4eb2f;
            a ^= (a >> 15);
            return a;
        }
        static constexpr bool isEqual(const IEC60908b::MSF &lhs, const IEC60908b::MSF &rhs) {
            return std::equal_to<const IEC60908b::MSF>{}(lhs, rhs);
        }
    };
    typedef Intrusive::HashTable<IEC60908b::MSF, Patch, MSFHash> Patches;
    struct Patch : public Patches::Node {
        std::list<std::pair<uint32_t, std::string>> data;
        Patch() = default;
        Patch(const Patch &) = default;
        Patch(Patch &&) = default;
        ~Patch() = default;
    };
    Patches m_patches;
    unsigned m_version;
};

}  // namespace PCSX
