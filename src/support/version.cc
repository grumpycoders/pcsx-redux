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
    } catch (...) {
        clear();
        return;
    }
    auto getString = [&json](const std::string& key) -> std::string {
        try {
            return json["updateInfo"][0][key].template get<std::string>();
        } catch (...) {
            return "";
        }
    };
    try {
        buildId = json["buildId"];
    } catch (...) {
        buildId = std::nullopt;
    }
    updateMethod = getString("method");
    updateChannel = getString("channel");
    updateCatalog = getString("updateCatalog");
    updateInfoBase = getString("updateInfoBase");
    updateStorageUrl = getString("updateStorageUrl");
}

bool PCSX::Update::downloadUpdateInfo(const VersionInfo& versionInfo, std::function<void(bool)> callback,
                                      uv_loop_t* loop) {
    if (versionInfo.failed() || !versionInfo.hasUpdateInfo()) return false;
    m_hasUpdate = false;
    if (versionInfo.updateMethod == "appdistrib") {
        m_download = new UvFile(
            versionInfo.updateCatalog,
            [this, callback, version = versionInfo.buildId]() {
                if (m_download->failed()) {
                    callback(false);
                }
                try {
                    FileAsContainer container(m_download);
                    nlohmann::json catalog;
                    catalog = nlohmann::json::parse(container.begin(), container.end());
                    if (!catalog.is_object() || !catalog["builds"].is_array()) {
                        callback(false);
                        return;
                    }
                    auto builds = catalog["builds"];
                    std::sort(builds.begin(), builds.end(),
                              [](const nlohmann::json& a, const nlohmann::json& b) { return a["id"] > b["id"]; });
                    auto latest = builds[0];
                    if (latest["id"] == version) {
                        callback(false);
                        return;
                    }
                    m_updateId = latest["id"];
                } catch (...) {
                    callback(false);
                    return;
                }
                callback(true);
                m_download.reset();
            },
            loop, UvFile::DOWNLOAD_URL);
        return true;
    } else if (versionInfo.updateMethod == "appcenter") {
        m_download = new UvFile(
            versionInfo.updateCatalog,
            [this, callback, version = versionInfo.version]() {
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
                    if (latest["version"] == version) {
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
    } else {
        return false;
    }
}

bool PCSX::Update::downloadAndApplyUpdate(const VersionInfo& versionInfo, std::function<void(bool)> callback,
                                          uv_loop_t* loop) {
    if (versionInfo.failed() || !versionInfo.hasUpdateInfo()) return false;
    m_hasUpdate = false;
    if (versionInfo.updateMethod == "appdistrib") {
        m_download = new UvFile(
            versionInfo.updateInfoBase + "manifest-" + std::to_string(m_updateId) + ".json",
            [this, loop, callback, updateStorageUrl = versionInfo.updateStorageUrl]() {
                if (m_download->failed()) {
                    callback(false);
                }
                std::string url;
                try {
                    FileAsContainer container(m_download);
                    nlohmann::json update;
                    update = nlohmann::json::parse(container.begin(), container.end());
                    auto& manifest = update["manifest"];
                    m_updateVersion = manifest["version"].template get<std::string>();
                    url = updateStorageUrl + update["path"].template get<std::string>();
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
    } else if (versionInfo.updateMethod == "appcenter") {
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
    } else {
        return false;
    }
}

bool PCSX::Update::getDownloadUrl(const VersionInfo& versionInfo, std::function<void(std::string)> callback,
                                  uv_loop_t* loop) {
    if (versionInfo.failed() || !versionInfo.hasUpdateInfo()) return false;
    m_hasUpdate = false;
    if (versionInfo.updateMethod == "appdistrib") {
        m_download = new UvFile(
            versionInfo.updateInfoBase + "manifest-" + std::to_string(m_updateId) + ".json",
            [this, callback, updateStorageUrl = versionInfo.updateStorageUrl]() {
                if (m_download->failed()) {
                    callback("");
                }
                std::string url;
                try {
                    FileAsContainer container(m_download);
                    nlohmann::json update;
                    update = nlohmann::json::parse(container.begin(), container.end());
                    auto& manifest = update["manifest"];
                    m_updateVersion = manifest["version"].template get<std::string>();
                    url = updateStorageUrl + update["path"].template get<std::string>();
                } catch (...) {
                    callback("");
                    return;
                }
                callback(url);
            },
            loop, UvFile::DOWNLOAD_URL);
        return true;
    } else if (versionInfo.updateMethod == "appcenter") {
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
    } else {
        return false;
    }
}

// All these defines need to be matching what we see in version-{platform}.cc
#if (!defined(__APPLE__) || !defined(__MACH__)) && !defined(__linux__) && !defined(_WIN32) && !defined(_WIN64)
bool PCSX::Update::applyUpdate(const std::filesystem::path& binDir) {
    throw std::runtime_exception("No platform support for updates");
    return false;
}
#endif
