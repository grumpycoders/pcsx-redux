/*

MIT License

Copyright (c) 2025 PCSX-Redux authors

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

#include "psyqo-paths/archive-manager.hh"

#include "EASTL/algorithm.h"
#include "lz4/lz4.h"
#include "psyqo/kernel.hh"
#include "psyqo/utility-polyfill.h"
#include "ucl-demo/n2e-d.h"

eastl::array<void (psyqo::paths::ArchiveManager::*)(const psyqo::paths::ArchiveManager::IndexEntry*), 3>
    psyqo::paths::ArchiveManager::s_decompressors = {nullptr};

void psyqo::paths::ArchiveManager::setupInitQueue(eastl::string_view archiveName, ISO9660Parser& parser,
                                                  eastl::function<void(bool)>&& callback) {
    setupInitQueue(0, *parser.getCDRom(), eastl::move(callback));
    m_queueInitFilename.reset();
    m_queueInitFilename.startWith([](auto task) { task->resolve(); });
    if (!parser.initialized()) {
        m_queueInitFilename.then(parser.scheduleInitialize());
    }
    m_queueInitFilename.then(parser.scheduleGetDirentry(archiveName, &m_archiveDirentry))
        .then([this](auto task) {
            m_index.resize(2048 / sizeof(IndexEntry));
            m_request.LBA = m_archiveDirentry.LBA;
            m_request.count = 1;
            m_request.buffer = m_index.data();
            task->resolve();
        })
        .then(m_queue.schedule());
}

void psyqo::paths::ArchiveManager::setupInitQueue(uint32_t LBA, CDRom& device, eastl::function<void(bool)>&& callback) {
    Kernel::assert(!m_pending, "Only one action can be performed at a time");
    m_queue.reset();
    m_pending = true;
    m_success = false;
    m_initCallback = eastl::move(callback);
    m_request.LBA = LBA;
    m_request.count = 1;
    m_request.buffer = m_index.data();
    m_queue.startWith(device.scheduleReadRequest(&m_request))
        .then([this](auto task) {
            eastl::string_view signature = {reinterpret_cast<const char*>(m_index.data()), 8};
            if (signature != "PSX-ARC1") {
                task->reject();
                return;
            }
            m_index.resize(getIndexSectorCount() * 2048 / sizeof(IndexEntry));
            m_request.count = getIndexSectorCount();
            m_request.buffer = m_index.data();
            task->resolve();
        })
        .then(device.scheduleReadRequest(&m_request))
        .then([this](auto task) {
            m_success = true;
            m_index.resize(getIndexCount() + 1);
            task->resolve();
        })
        .finally([this](auto queue) {
            m_pending = false;
            auto callback = eastl::move(m_initCallback);
            m_initCallback = nullptr;
            callback(m_success);
        });
}

const psyqo::paths::ArchiveManager::IndexEntry* psyqo::paths::ArchiveManager::getIndexEntry(
    eastl::string_view path) const {
    uint64_t hash = djb::hash<uint64_t>(path.data(), path.size());
    return getIndexEntry(hash);
}

const psyqo::paths::ArchiveManager::IndexEntry* psyqo::paths::ArchiveManager::getIndexEntry(uint64_t hash) const {
    const IndexEntry* first = &m_index[1];
    const IndexEntry* last = first + getIndexCount();
    const IndexEntry* entry =
        eastl::lower_bound(first, last, hash, [](const IndexEntry& e, uint64_t hash) { return e.hash < hash; });
    if (entry != last && entry->hash == hash) {
        return entry;
    }
    return nullptr;
}

void psyqo::paths::ArchiveManager::setupQueue(const IndexEntry* entry, CDRom& device,
                                              eastl::function<void(Buffer<uint8_t>&&)>&& callback) {
    Kernel::assert(!m_pending, "Only one action can be performed at a time");
    m_queue.reset();
    m_pending = true;
    m_callback = eastl::move(callback);
    if (!entry) {
        m_queue.startWith([this](auto task) {
            m_data.clear();
            m_pending = false;
            auto callback = eastl::move(m_callback);
            m_callback = nullptr;
            callback(eastl::move(m_data));
        });
        return;
    }
    const auto method = entry->getCompressionMethod();
    const uint32_t sectorCount = entry->getCompressedSize();
    const uint32_t decompSize = entry->getDecompSize();
    m_request.LBA = m_archiveDirentry.LBA + entry->getSectorOffset();
    m_request.count = sectorCount;
    if (method == IndexEntry::Method::NONE) {
        m_data.resize(sectorCount * 2048);
        m_request.buffer = m_data.data();
    } else {
        uint32_t actualSize = eastl::max<uint32_t>(((decompSize + 3) & ~3) + 16, sectorCount * 2048);
        m_data.resize(actualSize);
        m_request.buffer = m_data.data() + actualSize - sectorCount * 2048;
    }
    m_queue.startWith(device.scheduleReadRequest(&m_request))
        .then([this, entry](auto task) {
            auto decompress = s_decompressors[toUnderlying(entry->getCompressionMethod())];
            if (decompress) (this->*decompress)(entry);
            uint32_t decompSize = entry->getDecompSize();
            if (decompSize) m_data.resize(decompSize);
            task->resolve();
        })
        .butCatch([this](auto task) { m_data.resize(0); })
        .finally([this, decompSize](auto queue) {
            m_pending = false;
            auto callback = eastl::move(m_callback);
            m_callback = nullptr;
            callback(eastl::move(m_data));
        });
}

void psyqo::paths::ArchiveManager::decompressUCL_NRV2E(const IndexEntry* entry) {
    uint32_t padding = entry->getPadding();
    n2e_decompress(reinterpret_cast<uint8_t*>(m_request.buffer) + padding, m_data.data());
}

void psyqo::paths::ArchiveManager::decompressLZ4(const IndexEntry* entry) {
    uint32_t padding = entry->getPadding();
    uint32_t srcSize = entry->getCompressedSize() * 2048 - padding;
    uint8_t* src = reinterpret_cast<uint8_t*>(m_request.buffer) + padding;
    lz4_decompress_block(src, src + srcSize, m_data.data());
}
