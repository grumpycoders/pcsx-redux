/***************************************************************************
 *   Copyright (C) 2019 PCSX-Redux authors                                 *
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

#include <filesystem>
#include <string>
#include <vector>

namespace PCSX {
namespace Widgets {

class FileDialog {
  public:
    FileDialog(const char* title) : m_title(title) { setToCurrentPath(); }
    void setToCurrentPath() {
        m_currentPath = std::filesystem::current_path();
        nukeCache();
    }
    void openDialog();
    std::string selected() { return m_selected; }
    bool draw();

  private:
    void nukeCache() { m_cacheDirty = true; }
    bool m_cacheDirty = true;
    std::filesystem::path m_currentPath;
    const std::string m_title;
    std::vector<std::string> m_directories;
    struct File {
        std::string filename;
        std::uintmax_t size;
        std::string dateTime;
        std::time_t dateTimeTimeT;
        bool selected;
    };
    std::vector<File> m_files;
    std::string m_selected;
    enum sort { UNSORTED, SORT_DOWN, SORT_UP };
    struct {
        bool operator()(const File& a, const File& b) const {
            switch (name) {
                case SORT_DOWN:
                    return a.filename < b.filename;
                case SORT_UP:
                    return a.filename > b.filename;
            }
            switch (size) {
                case SORT_DOWN:
                    return a.size < b.size;
                case SORT_UP:
                    return a.size > b.size;
            }
            switch (date) {
                case SORT_DOWN:
                    return a.dateTimeTimeT < b.dateTimeTimeT;
                case SORT_UP:
                    return a.dateTimeTimeT > b.dateTimeTimeT;
            }
        }
        sort name = UNSORTED;
        sort size = UNSORTED;
        sort date = UNSORTED;
    } m_sorter;
};

}  // namespace Widgets
}  // namespace PCSX
