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

#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include "support/file.h"

namespace PCSX {

class ZipArchive {
  public:
    ZipArchive(IO<File> file);
    bool failed() { return m_failed; }
    void listAllFiles(std::function<void(std::string_view)> walker) {
        listFiles([walker](std::string_view name) -> bool {
            walker(name);
            return true;
        });
    }
    void listAllDirectories(std::function<void(std::string_view)> walker) {
        listDirectories([walker](std::string_view name) -> bool {
            walker(name);
            return true;
        });
    }
    void listFiles(std::function<bool(std::string_view)> walker);
    void listDirectories(std::function<bool(std::string_view)> walker);
    File *openFile(std::string path);

    std::filesystem::path archiveFilename() { return m_file->filename(); }

  private:
    IO<File> m_file;

    struct CompressedFile {
        bool isDirectory() {
            if (size != 0) return false;
            if (compressedSize != 0) return false;
            if (name.empty()) return false;
            auto pos = name.length() - 1;
            if (name[pos] != '/') return false;
            return true;
        }
        uint32_t offset;
        uint32_t size;
        uint32_t compressedSize;
        std::string name;
        bool compressed;
    };

    std::vector<CompressedFile> m_files;
    bool m_failed = false;
};

}  // namespace PCSX
