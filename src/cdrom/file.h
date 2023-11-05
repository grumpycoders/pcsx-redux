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

#include <memory>
#include <string_view>

#include "cdrom/common.h"
#include "support/file.h"

namespace PCSX {

class CDRIso;

class CDRIsoFile : public File {
  public:
    virtual ~CDRIsoFile() {}

    static constexpr uint32_t c_sectorSizes[] = {2352, 2352, 2048, 2336, 2048, 2324};
    static constexpr size_t c_sectorOffsets[] = {0, 0, 16, 16, 24, 24};
    CDRIsoFile(std::shared_ptr<CDRIso> iso, uint32_t lba, int32_t size = -1, SectorMode = SectorMode::GUESS);
    virtual bool failed() final override { return m_failed; }
    virtual ssize_t rSeek(ssize_t pos, int wheel) override;
    virtual ssize_t rTell() override { return m_ptrR; }
    virtual ssize_t wSeek(ssize_t pos, int wheel) override;
    virtual ssize_t wTell() override { return m_ptrW; }
    virtual size_t size() override { return m_size; }
    virtual ssize_t read(void* dest, size_t size) override;
    virtual ssize_t write(const void* src, size_t size) override;
    virtual File* dup() override { return new CDRIsoFile(m_iso, m_lba, m_size, m_mode); };

  private:
    std::shared_ptr<CDRIso> m_iso;
    uint8_t m_cachedSector[2352];
    int32_t m_cachedLBA = -1;
    uint32_t m_lba;
    uint32_t m_size;
    SectorMode m_mode;
    size_t m_ptrR = 0;
    size_t m_ptrW = 0;

    bool m_failed = false;
};

}  // namespace PCSX
