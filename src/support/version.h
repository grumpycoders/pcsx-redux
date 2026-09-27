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

// Forward-declare instead of including <uv.h>. Only uv_loop_t* appears in this
// header, and this is libuv's own declaration of it. Including the real header
// here dragged libuv into 25 translation units that only wanted VersionInfo
// and Update; the uvfile.h include that sat below it dragged libcurl too.
struct uv_loop_s;
typedef struct uv_loop_s uv_loop_t;

#include <ctime>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>

#include "json.hpp"
#include "support/file.h"
#include "support/version-info.h"

namespace PCSX {


class Update {
  public:
    bool downloadUpdateInfo(const VersionInfo&, std::function<void(bool)> callback, uv_loop_t* loop);
    bool downloadAndApplyUpdate(const VersionInfo&, std::function<void(bool)> callback, uv_loop_t* loop);
    bool getDownloadUrl(const VersionInfo&, std::function<void(std::string)> callback, uv_loop_t* loop);
    bool applyUpdate(const std::filesystem::path& binDir);
    bool canFullyApply();

    float progress();

    bool hasUpdate() const { return m_hasUpdate; }

  private:
    using json = nlohmann::json;
    json m_updateCatalog;
    json m_updateInfo;
    // IO<File>, not IO<UvFile>: the IO<T> constraint needs T complete, so holding
    // the concrete type here forces uvfile.h on every includer. The .cc still
    // assigns a UvFile and downcasts where it needs the caching API.
    IO<File> m_download;
    unsigned m_updateId;
    std::string m_updateVersion;
    bool m_hasUpdate = false;
};

}  // namespace PCSX
