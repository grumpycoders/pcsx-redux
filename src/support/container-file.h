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

#include "support/file.h"

namespace PCSX {

class FileAsContainer;

struct FileIterator {
    using difference_type = std::ptrdiff_t;
    using value_type = char;
    using pointer = const char*;
    using reference = const char&;
    using iterator_category = std::input_iterator_tag;

    FileIterator& operator++();
    reference operator*() const;
    bool operator!=(const FileIterator& rhs) const { return rhs.target != target; }
    FileAsContainer* target = nullptr;
};

class FileAsContainer {
  public:
    FileAsContainer(IO<File> file) : m_file(file) {}
    void advance() { m_ptr++; }
    const char& getCurrent() {
        m_current = m_file->readAt<char>(m_ptr);
        return m_current;
    }
    FileIterator begin() { return FileIterator{this}; }
    FileIterator end() { return {}; }

  private:
    IO<File> m_file;
    size_t m_ptr = 0;
    char m_current;
};

}  // namespace PCSX
