/*

MIT License

Copyright (c) 2022 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

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
        version = json["version"].template get<std::string>();
        changeset = json["changeset"].template get<std::string>();
        timestamp = json["timestamp"].template get<std::time_t>();
        updateCatalog = json["updateInfo"][0]["updateCatalog"].template get<std::string>();
        updateInfoBase = json["updateInfo"][0]["updateInfoBase"].template get<std::string>();
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
                if (latest["version"].template get<std::string>() == versionInfo.version) {
                    callback(false);
                    return;
                }
                m_updateId = latest["id"].template get<unsigned>();
                m_updateVersion = latest["version"].template get<std::string>();
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
                url = update["download_url"].template get<std::string>();
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
                url = update["download_url"].template get<std::string>();
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
