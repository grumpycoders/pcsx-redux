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
