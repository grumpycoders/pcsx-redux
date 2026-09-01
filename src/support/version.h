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

#pragma once

#include <uv.h>

#include <ctime>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>

#include "json.hpp"
#include "support/file.h"
#include "support/uvfile.h"

namespace PCSX {

struct VersionInfo {
    std::string version;
    std::optional<unsigned> buildId;
    std::string changeset;
    std::time_t timestamp;
    std::string updateMethod;
    std::string updateChannel;
    std::string updateCatalog;
    std::string updateInfoBase;
    std::string updateStorageUrl;
    void loadFromFile(IO<File> file);
    bool failed() const { return version.empty(); }
    bool hasUpdateInfo() const {
        if (version.empty()) return false;
        if (updateCatalog.empty() || updateInfoBase.empty()) return false;
        if (updateMethod == "appdistrib") {
            return buildId.has_value() && !updateStorageUrl.empty();
        }
        return (updateMethod == "appcenter");
    }
    void clear() {
        version.clear();
        buildId = std::nullopt;
        changeset.clear();
        timestamp = 0;
        updateMethod.clear();
        updateChannel.clear();
        updateCatalog.clear();
        updateInfoBase.clear();
        updateStorageUrl.clear();
    }
};

class Update {
  public:
    bool downloadUpdateInfo(const VersionInfo&, std::function<void(bool)> callback, uv_loop_t* loop);
    bool downloadAndApplyUpdate(const VersionInfo&, std::function<void(bool)> callback, uv_loop_t* loop);
    bool getDownloadUrl(const VersionInfo&, std::function<void(std::string)> callback, uv_loop_t* loop);
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
    std::string m_updateVersion;
    bool m_hasUpdate = false;
};

}  // namespace PCSX
