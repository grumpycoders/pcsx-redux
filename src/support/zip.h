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
    void listAllFiles(std::function<void(const std::string_view &)> walker) {
        listFiles([walker](const std::string_view &name) -> bool {
            walker(name);
            return true;
        });
    }
    void listAllDirectories(std::function<void(const std::string_view &)> walker) {
        listDirectories([walker](const std::string_view &name) -> bool {
            walker(name);
            return true;
        });
    }
    void listFiles(std::function<bool(const std::string_view &)> walker);
    void listDirectories(std::function<bool(const std::string_view &)> walker);
    File *openFile(const std::string_view &path);

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
