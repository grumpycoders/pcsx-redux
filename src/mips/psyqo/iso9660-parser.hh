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

#include <EASTL/fixed_string.h>
#include <EASTL/functional.h>
#include <EASTL/string_view.h>

#include "psyqo/cdrom.hh"
#include "psyqo/task.hh"

namespace psyqo {

class ISO9660Parser {
  public:
    struct DirEntry {
        uint32_t LBA = 0;
        uint32_t size = 0;
        eastl::fixed_string<char, 15, false> name;
        enum { INVALID, FILE, DIRECTORY, CURRENT_DIR, PARENT_DIR } type = INVALID;
    };
    struct ReadRequest {
        struct DirEntry entry;
        uint8_t* buffer = nullptr;
    };
    ISO9660Parser(CDRom* cdrom) : m_cdrom(cdrom) {}
    void initialize(eastl::function<void(bool success)> callback);
    TaskQueue::Task scheduleInitialize();
    void getDirentry(eastl::string_view path, DirEntry* entry, eastl::function<void(bool success)> callback);
    TaskQueue::Task scheduleGetDirentry(eastl::string_view path, DirEntry* entry);
    TaskQueue::Task scheduleReadRequest(ReadRequest* request);

  private:
    void parseDirEntry(const uint8_t* data, DirEntry* entry);
    eastl::string_view getEntryName(const uint8_t* data);
    void findDirEntry();

    uint8_t m_buffer[2048];
    eastl::function<void(bool success)> m_callback = nullptr;
    eastl::string_view m_path;
    DirEntry* m_dirEntry = nullptr;
    CDRom* m_cdrom = nullptr;
    uint32_t m_cachedLBA = 0;
    DirEntry m_root;
    DirEntry m_cachedEntry;
    eastl::fixed_string<char, 128> m_cachedPath;
    bool m_initialized = false;
};

}  // namespace psyqo
