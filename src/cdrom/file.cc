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

#include "cdrom/file.h"

#include "cdrom/cdriso.h"

PCSX::CDRIsoFile::CDRIsoFile(std::shared_ptr<CDRIso> iso, uint32_t lba, int32_t size, SectorMode mode)
    : File(RO_SEEKABLE), m_iso(iso), m_lba(lba) {}

PCSX::CDRIsoFile::CDRIsoFile(std::shared_ptr<CDRIso> iso, const std::string_view& filename)
    : File(RO_SEEKABLE), m_iso(iso) {}
