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

#include <uv.h>

#include <filesystem>
#include <functional>
#include <string>

#include "json.hpp"
#include "support/file.h"
#include "support/uvfile.h"

namespace PCSX {

struct VersionInfo {
    std::string version;
    std::string changeset;
    std::string updateCatalog;
    std::string updateInfoBase;
    void loadFromFile(IO<File> file);
    bool failed() const { return version.empty(); }
    void clear() {
        version.clear();
        changeset.clear();
        updateCatalog.clear();
        updateInfoBase.clear();
    }
};

class Update {
  public:
    bool downloadUpdateInfo(const VersionInfo&, std::function<void(bool)> callback, uv_loop_t* loop);
    bool downloadUpdate(const VersionInfo&, std::function<void(bool)> callback, uv_loop_t* loop);
    bool applyUpdate(const std::filesystem::path& binDir);
    bool canFullyApply();

    float progress() {
        if (m_download && !m_download->failed()) return m_download->cacheProgress();
        return 0.0f;
    }

    bool hasUpdate() const { return m_hasUpdate; }

  private:
    using json = nlohmann::json;
    json m_updateCatalog;
    json m_updateInfo;
    IO<UvFile> m_download;
    unsigned m_updateId;
    bool m_hasUpdate = false;
};

}  // namespace PCSX
