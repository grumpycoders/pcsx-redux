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

// VersionInfo alone, split out of version.h so that core/system.h can name it
// without pulling in Update - which needs UvFile, and through it libuv.

#include <ctime>
#include <filesystem>
#include <optional>
#include <string>

#include "json.hpp"
#include "support/file.h"

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

}  // namespace PCSX
