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
