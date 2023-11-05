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

#include "psyqo/iso9660-parser.hh"

#include "psyqo/kernel.hh"
#include "psyqo/strings-helpers.hh"

void psyqo::ISO9660Parser::initialize(eastl::function<void(bool success)> callback) {
    Kernel::assert(m_callback == nullptr, "Only one outstanding async operation allowed");
    m_callback = eastl::move(callback);
    m_cdrom->readSectors(16, 1, m_buffer, [this](bool success) {
        m_cachedLBA = 0;
        m_initialized = false;
        if (!success) {
            auto callback = eastl::move(m_callback);
            m_callback = nullptr;
            callback(false);
            return;
        }
        uint32_t* pvd = reinterpret_cast<uint32_t*>(m_buffer);
        // This isn't exactly correct, but no working PSX CD-Rom has more than 1 volume.
        if ((pvd[0] != 0x30444301) || (pvd[1] != 0x00013130)) {
            auto callback = eastl::move(m_callback);
            m_callback = nullptr;
            callback(false);
            return;
        }
        parseDirEntry(&m_buffer[156], &m_root);
        m_cachedEntry = m_root;
        m_cdrom->readSectors(m_root.LBA, 1, m_buffer, [this](bool success) {
            if (success) {
                m_cachedLBA = m_root.LBA;
                m_cachedEntry = m_root;
                m_cachedPath.clear();
                m_initialized = true;
            }
            auto callback = eastl::move(m_callback);
            m_callback = nullptr;
            callback(success);
        });
    });
}

psyqo::TaskQueue::Task psyqo::ISO9660Parser::scheduleInitialize() {
    return TaskQueue::Task([this](auto task) { initialize([task](bool success) { task->complete(success); }); });
}

void psyqo::ISO9660Parser::getDirentry(eastl::string_view path, DirEntry* entry,
                                       eastl::function<void(bool success)> callback) {
    if (!m_initialized) {
        callback(false);
        return;
    }

    if (path.empty()) {
        *entry = m_root;
        callback(true);
        return;
    }

    if (path[0] == '/') {
        path.remove_prefix(1);
    }

    eastl::string_view cachedPath = m_cachedPath;

    if ((cachedPath.length() > 0) && (cachedPath[0] == '/')) {
        cachedPath.remove_prefix(1);
    }

    if (startsWith(path, cachedPath) && (path.length() > cachedPath.length()) && (path[cachedPath.length()] == '/')) {
        path.remove_prefix(cachedPath.length() + 1);
    } else if (m_cachedLBA != m_root.LBA) {
        m_cachedEntry.type = DirEntry::INVALID;
    }

    Kernel::assert(m_callback == nullptr, "Only one outstanding async operation allowed");
    m_callback = eastl::move(callback);
    m_path = path;
    m_dirEntry = entry;
    entry->type = DirEntry::INVALID;
    findDirEntry();
}

psyqo::TaskQueue::Task psyqo::ISO9660Parser::scheduleGetDirentry(eastl::string_view path, DirEntry* entry) {
    m_path = path;
    m_dirEntry = entry;
    return TaskQueue::Task(
        [this](auto task) { getDirentry(m_path, m_dirEntry, [task](bool success) { task->complete(success); }); });
}

psyqo::TaskQueue::Task psyqo::ISO9660Parser::scheduleReadRequest(ReadRequest* request) {
    return TaskQueue::Task([this, request](auto task) {
        unsigned count = (request->entry.size + 2047) / 2048;
        m_cdrom->readSectors(request->entry.LBA, count, request->buffer,
                             [task](bool success) { task->complete(success); });
    });
}

void psyqo::ISO9660Parser::parseDirEntry(const uint8_t* data, DirEntry* entry) {
    entry->LBA = (data[5] << 24) | (data[4] << 16) | (data[3] << 8) | data[2];
    entry->size = (data[13] << 24) | (data[12] << 16) | (data[11] << 8) | data[10];
    entry->name.clear();
    auto len = data[32];
    entry->name.append(reinterpret_cast<const char*>(data + 33), len);
    if ((data[25] & 2) == 0) {
        entry->type = DirEntry::FILE;
    } else {
        if (len == 0) {
            entry->name = ".";
            entry->type = DirEntry::CURRENT_DIR;
        } else if ((len == 1) && (data[33] == 1)) {
            entry->name = "..";
            entry->type = DirEntry::PARENT_DIR;
        } else {
            entry->type = DirEntry::DIRECTORY;
        }
    }
}

eastl::string_view psyqo::ISO9660Parser::getEntryName(const uint8_t* data) {
    if (data[0] == 0) {
        return eastl::string_view();
    }
    if (data[32] == 1) {
        if (data[33] == 0) {
            return ".";
        } else if (data[33] == 1) {
            return "..";
        }
    }
    return eastl::string_view(reinterpret_cast<const char*>(data + 33), data[32]);
}

void psyqo::ISO9660Parser::findDirEntry() {
    if (m_path.empty()) {
        *m_dirEntry = m_cachedEntry;
        auto callback = eastl::move(m_callback);
        m_callback = nullptr;
        callback(true);
        return;
    }

    auto pos = m_path.find('/');
    if (pos == eastl::string_view::npos) {
        pos = m_path.length();
    }

    auto name = m_path.substr(0, pos);
    m_path.remove_prefix(pos);
    if ((m_path.length() > 0) && (m_path[0] == '/')) {
        m_path.remove_prefix(1);
    }

    if (m_cachedEntry.type == DirEntry::INVALID) {
        m_cachedPath.clear();
        m_cachedLBA = 0;
        m_cdrom->readSectors(m_root.LBA, 1, m_buffer, [this](bool success) {
            if (!success) {
                auto callback = eastl::move(m_callback);
                m_callback = nullptr;
                callback(false);
                return;
            }
            m_cachedLBA = m_root.LBA;
            m_cachedEntry = m_root;
            findDirEntry();
        });
        return;
    }

    if (m_cachedEntry.type != DirEntry::DIRECTORY) {
        auto callback = eastl::move(m_callback);
        m_callback = nullptr;
        callback(true);
        return;
    }

    uint32_t offset = 0;
    while (offset < 2048) {
        auto entry = &m_buffer[offset];
        if (entry[0] == 0) break;
        auto entryName = getEntryName(entry);
        if (entryName == name) {
            if (m_path.empty()) {
                parseDirEntry(entry, m_dirEntry);
                auto callback = eastl::move(m_callback);
                m_callback = nullptr;
                callback(true);
                return;
            } else {
                if ((entry[25] & 2) == 0) {
                    auto callback = eastl::move(m_callback);
                    m_callback = nullptr;
                    callback(true);
                    return;
                }
                m_cachedPath.append("/");
                parseDirEntry(entry, &m_cachedEntry);
                m_cachedPath.append(name.data(), name.length());
                m_cachedLBA = 0;
                m_cdrom->readSectors(m_cachedEntry.LBA, 1, m_buffer, [this](bool success) {
                    if (!success) {
                        auto callback = eastl::move(m_callback);
                        m_callback = nullptr;
                        callback(false);
                        return;
                    }
                    m_cachedLBA = m_cachedEntry.LBA;
                    findDirEntry();
                });
                return;
            }
        }
        offset += entry[0];
    }

    unsigned current = m_cachedLBA - m_cachedEntry.LBA;
    unsigned count = m_cachedEntry.size / 2048;

    if (current + 1 < count) {
        uint32_t sectorToRead = m_cachedLBA + 1;
        m_cachedLBA = 0;
        m_cdrom->readSectors(sectorToRead, 1, m_buffer, [this, sectorToRead](bool success) {
            if (!success) {
                auto callback = eastl::move(m_callback);
                m_callback = nullptr;
                callback(false);
                return;
            }
            m_cachedLBA = sectorToRead;
            findDirEntry();
        });
        return;
    }

    auto callback = eastl::move(m_callback);
    m_callback = nullptr;
    callback(true);
}
