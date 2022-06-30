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

#include "support/version.h"

#include <algorithm>

#include "json.hpp"
#include "support/container-file.h"

void PCSX::VersionInfo::loadFromFile(IO<File> file) {
    clear();
    if (file->failed()) return;
    nlohmann::json json;
    FileAsContainer container(file);
    json = nlohmann::json::parse(container.begin(), container.end());

    try {
        version = json["version"];
        changeset = json["changeset"];
        timestamp = json["timestamp"];
        updateCatalog = json["updateInfo"][0]["updateCatalog"];
        updateInfoBase = json["updateInfo"][0]["updateInfoBase"];
    } catch (...) {
        clear();
    }
}

bool PCSX::Update::downloadUpdateInfo(const VersionInfo& versionInfo, std::function<void(bool)> callback,
                                      uv_loop_t* loop) {
    if (versionInfo.failed()) return false;
    m_hasUpdate = false;
    m_download = new UvFile(
        versionInfo.updateCatalog,
        [this, callback, versionInfo]() {
            if (m_download->failed()) {
                callback(false);
            }
            try {
                FileAsContainer container(m_download);
                nlohmann::json catalog;
                catalog = nlohmann::json::parse(container.begin(), container.end());
                if (!catalog.is_array()) {
                    callback(false);
                    return;
                }
                std::sort(catalog.begin(), catalog.end(),
                          [](const nlohmann::json& a, const nlohmann::json& b) { return a["id"] > b["id"]; });
                auto latest = catalog[0];
                if (latest["version"] == versionInfo.version) {
                    callback(false);
                    return;
                }
                m_updateId = latest["id"];
                m_updateVersion = latest["version"];
            } catch (...) {
                callback(false);
                return;
            }
            callback(true);
            m_download.reset();
        },
        loop, UvFile::DOWNLOAD_URL);
    return true;
}

bool PCSX::Update::downloadAndApplyUpdate(const VersionInfo& versionInfo, std::function<void(bool)> callback,
                                          uv_loop_t* loop) {
    if (versionInfo.failed()) return false;
    m_hasUpdate = false;
    m_download = new UvFile(
        versionInfo.updateInfoBase + std::to_string(m_updateId),
        [this, loop, callback]() {
            if (m_download->failed()) {
                callback(false);
            }
            std::string url;
            try {
                FileAsContainer container(m_download);
                nlohmann::json update;
                update = nlohmann::json::parse(container.begin(), container.end());
                url = update["download_url"];
            } catch (...) {
                callback(false);
                return;
            }
            m_download = new UvFile(
                url,
                [this, callback]() {
                    if (m_download->failed()) {
                        callback(false);
                    }
                    m_hasUpdate = true;
                    callback(true);
                },
                loop, UvFile::DOWNLOAD_URL);
        },
        loop, UvFile::DOWNLOAD_URL);
    return true;
}

bool PCSX::Update::getDownloadUrl(const VersionInfo& versionInfo, std::function<void(std::string)> callback,
                                  uv_loop_t* loop) {
    if (versionInfo.failed()) return false;
    m_hasUpdate = false;
    m_download = new UvFile(
        versionInfo.updateInfoBase + std::to_string(m_updateId),
        [this, callback]() {
            if (m_download->failed()) {
                callback("");
            }
            std::string url;
            try {
                FileAsContainer container(m_download);
                nlohmann::json update;
                update = nlohmann::json::parse(container.begin(), container.end());
                url = update["download_url"];
            } catch (...) {
                callback("");
                return;
            }
            callback(url);
        },
        loop, UvFile::DOWNLOAD_URL);
    return true;
}

// All these defines need to be matching what we see in version-{platform}.cc
#if (!defined(__APPLE__) || !defined(__MACH__)) && !defined(__linux__) && !defined(_WIN32) && !defined(_WIN64)
bool PCSX::Update::applyUpdate(const std::filesystem::path& binDir) {
    throw std::runtime_exception("No platform support for updates");
    return false;
}
#endif
