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

#if defined(__APPLE__) && defined(__MACH__)

#include <stdlib.h>

#include "fmt/format.h"
#include "support/version.h"
#include "support/zip.h"

bool PCSX::Update::canFullyApply() { return false; }

bool PCSX::Update::applyUpdate(const std::filesystem::path& binDir) {
    if (!m_hasUpdate) return false;
    auto outName = std::filesystem::temp_directory_path() / fmt::format("PCSX-Redux-{}.dmg", m_updateVersion);
    IO<File> out(new UvFile(outName, FileOps::TRUNCATE));
    if (out->failed()) return false;
    Slice data = m_download.asA<File>()->read(m_download->size());
    out->write(std::move(data));
    std::string cmd = fmt::format("open \"{}\"", outName.string());
    system(cmd.c_str());
    return true;
}

#endif
