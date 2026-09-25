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

#ifdef __linux__

#include <stdlib.h>

#include <filesystem>

#include "fmt/format.h"
#include "support/version.h"
#include "support/zip.h"

bool PCSX::Update::canFullyApply() { return false; }

bool PCSX::Update::applyUpdate(const std::filesystem::path& binDir) {
    if (!m_hasUpdate) return false;
    auto tmp = std::filesystem::temp_directory_path();

    ZipArchive zip(m_download);
    if (zip.failed()) return false;

    std::filesystem::path filename;

    zip.listAllFiles([&zip, &filename, &tmp](std::string_view name) {
        IO<File> out(new UvFile(tmp / name, FileOps::TRUNCATE));
        IO<File> in(zip.openFile(std::string(name)));
        Slice data = in->read(in->size());
        out->write(std::move(data));
        filename = out->filename();
    });

    std::filesystem::permissions(filename,
                                 std::filesystem::perms::owner_all | std::filesystem::perms::group_exec |
                                     std::filesystem::perms::group_read | std::filesystem::perms::others_exec |
                                     std::filesystem::perms::others_read,
                                 std::filesystem::perm_options::replace);

    std::string cmd = fmt::format(
        "dbus-send --session --print-reply --dest=org.freedesktop.FileManager1 --type=method_call "
        "/org/freedesktop/FileManager1 org.freedesktop.FileManager1.ShowItems array:string:\"file://{}\" string:\"\"",
        filename.string());
    system(cmd.c_str());

    return true;
}

#endif
