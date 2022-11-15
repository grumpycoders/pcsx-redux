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

/**
 * @brief An ISO9660 parser.
 *
 * @details This class is a simple ISO9660 parser. It is not meant to be a full
 * implementation, but rather a simple parser that can be used to find the
 * files to be loaded.
 */

class ISO9660Parser {
  public:
    /**
     * @brief An ISO9660 directory entry.
     *
     * @details This struct represents a single directory entry in an ISO9660.
     * It's not necessarily complete at the moment.
     */
    struct DirEntry {
        uint32_t LBA = 0;
        uint32_t size = 0;
        eastl::fixed_string<char, 15, false> name;
        enum { INVALID, FILE, DIRECTORY, CURRENT_DIR, PARENT_DIR } type = INVALID;
    };

    /**
     * @brief An asynchronous read request.
     *
     * @details This struct serves as a persistent storage for an asynchronous read
     * request. Its purpose is to be embedded outside of the parser, so it can
     * keep track of the current state of the request.
     */
    struct ReadRequest {
        struct DirEntry entry;
        void* buffer = nullptr;
    };

    /**
     * @brief The ISO9660Parser constructor.
     *
     * @details This constructor takes a CDRom device as a parameter. It will
     * use that device to read the structure of the ISO9660 filesystem.
     *
     * @param cdrom The CDRom device to use.
     */
    ISO9660Parser(CDRom* cdrom) : m_cdrom(cdrom) {}

    /**
     * @brief Initializes the parser.
     *
     * @details This method initializes the basic internal structures of the parser.
     * It must be called before any other method. If the underlying CDRom device
     * fails reading, or if the filesystem is not an ISO9660, the callback or task
     * will fail. It can be called multiple times, and has to be called when the user
     * changes the disc in the drive.
     */
    void initialize(eastl::function<void(bool success)> callback);
    TaskQueue::Task scheduleInitialize();

    /**
     * @brief Get the Direntry object for a given path.
     *
     * @details This method looks up the directory entry for a given path. It will
     * fail if the CDRom device fails reading the disk, or if the parser hasn't been
     * initialized yet. If the directory entry is not found, the callback or task
     * will still be successful, but the directory entry will be invalid.
     *
     * @param[in] path The path to look for.
     * @param[out] entry The DirEntry object to fill.
     */
    void getDirentry(eastl::string_view path, DirEntry* entry, eastl::function<void(bool success)> callback);
    TaskQueue::Task scheduleGetDirentry(eastl::string_view path, DirEntry* entry);

    /**
     * @brief Read a file asynchronously.
     *
     * @details This method reads a file asynchronously. It will read the file
     * from the given `entry` in the `ReadRequest`, and will read the number of
     * sectors corresponding to the entry's size. The buffer is specified by
     * the `buffer` field in the `ReadRequest`, and must be large enough to
     * hold the whole file. This method is mainly a helper around the CDRom
     * device's `readSectors` method.
     *
     * @param[in] request The request to fill.
     */
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
