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

#pragma once

#include <EASTL/array.h>
#include <EASTL/functional.h>
#include <EASTL/string_view.h>
#include <stdint.h>

#include <coroutine>

#include "common/util/bitfield.hh"
#include "common/util/djbhash.h"
#include "psyqo/buffer.hh"
#include "psyqo/iso9660-parser.hh"
#include "psyqo/task.hh"
#include "psyqo/utility-polyfill.h"

namespace psyqo::paths {

/**
 * @brief This class manages the reading and decompression of files from an archive.
 *
 * @details The ArchiveManager class is a helper class that manages the reading and
 * decompression of files from an archive. The archive format is specified in the
 * mkarchive.lua tool available in the tools directory, and this is where the reader
 * can find rationales and details on the format itself. The archive is a collection
 * of files that are compressed using different compression methods, and is designed
 * to be used specifically with the PlayStation 1. Parsing the iso9660 filesystem is
 * an expensive operation, so using a single archive for all files will speed up
 * loading times, as the archive index is kept in memory in a compact and efficient
 * format.
 *
 * If multiple archives are used, it is reasonable to create and destroy the
 * ArchiveManager object multiple times, or to have multiple ArchiveManager objects.
 * The latter is recommended, as it allows for caching of the index in memory, and
 * allows for faster loading times.
 */
class ArchiveManager {
    struct InitAwaiterWithFilename {
        InitAwaiterWithFilename(eastl::string_view name, ISO9660Parser &parser, ArchiveManager &manager)
            : m_name(name), m_parser(parser), m_manager(manager) {}
        bool await_ready() const { return false; }
        template <typename U>
        void await_suspend(std::coroutine_handle<U> handle) {
            m_manager.initialize(m_name, m_parser, [handle, this](bool success) {
                m_success = success;
                handle.resume();
            });
        }
        bool await_resume() { return m_success; }

      private:
        eastl::string_view m_name;
        ISO9660Parser &m_parser;
        ArchiveManager &m_manager;
        bool m_success;
    };
    struct InitAwaiter {
        InitAwaiter(uint32_t LBA, CDRom &device, ArchiveManager &manager)
            : m_LBA(LBA), m_device(device), m_manager(manager) {}
        bool await_ready() const { return false; }
        template <typename U>
        void await_suspend(std::coroutine_handle<U> handle) {
            m_manager.initialize(m_LBA, m_device, [handle, this](bool success) {
                m_success = success;
                handle.resume();
            });
        }
        bool await_resume() { return m_success; }

      private:
        uint32_t m_LBA;
        CDRom &m_device;
        ArchiveManager &m_manager;
        bool m_success;
    };

  public:
    union IndexEntry;

  private:
    struct ReadFileAwaiter {
        ReadFileAwaiter(const IndexEntry *entry, CDRom &device, ArchiveManager &manager)
            : m_entry(entry), m_device(device), m_manager(manager) {}
        constexpr bool await_ready() const { return false; }
        template <typename U>
        void await_suspend(std::coroutine_handle<U> handle) {
            m_manager.readFile(m_entry, m_device, [handle, this](Buffer<uint8_t> &&data) {
                m_data = eastl::move(data);
                handle.resume();
            });
        }
        Buffer<uint8_t> await_resume() { return eastl::move(m_data); }

      private:
        const IndexEntry *m_entry;
        CDRom &m_device;
        ArchiveManager &m_manager;
        Buffer<uint8_t> m_data;
    };

  public:
    /**
     * @brief The IndexEntry struct represents an entry in the archive index.
     *
     * @details The IndexEntry struct contains information about a file in the
     * archive, including its hash, decompressed size, padding size, sector offset,
     * compressed size, and compression method. While technically used by the
     * archive manager itself, the user can also use this struct to access the
     * information about the file in the archive and make decisions based on it.
     */
    union IndexEntry {
        enum class Method : uint32_t {
            NONE = 0,
            UCL_NRV2E = 1,
            LZ4 = 2,
            COUNT = 3,
        };
        typedef Utilities::BitSpan<uint32_t, 21> DecompSizeField;
        typedef Utilities::BitSpan<uint32_t, 11> PaddingField;
        typedef Utilities::BitSpan<uint32_t, 19> SectorOffsetField;
        typedef Utilities::BitSpan<uint32_t, 10> CompressedSizeField;
        typedef Utilities::BitSpan<Method, 3> MethodField;
        typedef Utilities::BitField<DecompSizeField, PaddingField, SectorOffsetField, CompressedSizeField, MethodField>
            CompressedEntry;
        // Return the decompressed size of the file in bytes.
        uint32_t getDecompSize() const { return entry.get<DecompSizeField>(); }
        // Return the padding size in bytes. This is only relevant for
        // compressed files. The padding is used at the beginning of the
        // compressed data to align it to a 2048 byte boundary, and
        // allows in-place decompression of the data.
        uint32_t getPadding() const { return entry.get<PaddingField>(); }
        // Return the offset from the beginning of the archive to the compressed data in sectors.
        // This includes the index sectors at the beginning of the archive.
        uint32_t getSectorOffset() const { return entry.get<SectorOffsetField>(); }
        // Return the size of the compressed data in sectors. For uncompressed
        // data, this is the same as the size of the data in bytes, just rounded
        // up to the next 2048 byte boundary.
        uint32_t getCompressedSize() const { return entry.get<CompressedSizeField>(); }
        // Return the compression method used to compress the data.
        Method getCompressionMethod() const { return entry.get<MethodField>(); }
        uint32_t asArray[4];
        struct {
            uint64_t hash;
            CompressedEntry entry;
        };
    };

    /**
     * @brief Asynchronous initialization of the archive manager.
     *
     * @details This function initializes the archive manager asynchronously.
     * There are two overloads of this function. The first one takes a filename
     * and an ISO9660Parser object, and the second one takes a LBA and a CDRom
     * object. The first overload is when the user wants the system to find the
     * archive in the ISO9660 filesystem, while the second one is when the user
     * already knows the LBA of the archive. Note that using exclusively the
     * second overload means the iso9660 filesystem parsing code will not be
     * used, which is a further reduction in the final binary's code footprint.
     */
    void initialize(eastl::string_view archiveName, ISO9660Parser &parser, eastl::function<void(bool)> &&callback) {
        setupInitQueue(archiveName, parser, eastl::move(callback));
        m_queueInitFilename.run();
    }
    psyqo::TaskQueue::Task scheduleInitialize(eastl::string_view archiveName, ISO9660Parser &parser) {
        setupInitQueue(archiveName, parser, {});
        return m_queueInitFilename.schedule();
    }
    InitAwaiterWithFilename initialize(eastl::string_view archiveName, ISO9660Parser &parser) {
        return {archiveName, parser, *this};
    }
    void initialize(uint32_t LBA, CDRom &device, eastl::function<void(bool)> &&callback) {
        setupInitQueue(LBA, device, eastl::move(callback));
        m_queue.run();
    }
    psyqo::TaskQueue::Task scheduleInitialize(uint32_t LBA, CDRom &device) {
        setupInitQueue(LBA, device, {});
        return m_queue.schedule();
    }
    InitAwaiter initialize(uint32_t LBA, CDRom &device) { return {LBA, device, *this}; }

    /**
     * @brief Get the First IndexEntry object.
     *
     * @details This function returns a pointer to the first IndexEntry object
     * in the index. In case the user has used a custom hashing mechanism for
     * locating the files, this function becomes relevant in order to do any
     * sort of custom search over the index. If the archive manager was not
     * initialized, or failed to initialize, this function will return nullptr.
     *
     * @return IndexEntry* Pointer to the first IndexEntry object in the index.
     */
    const IndexEntry *getFirstIndexEntry() const {
        if (m_index.size() == 0) {
            return nullptr;
        }
        return &m_index[1];
    }

    /**
     * @brief Get the number of entries in the index.
     *
     * @details This function returns the number of entries in the index.
     * Calling this function before the archive manager is initialized
     * successfully is undefined behavior.
     *
     * @return uint32_t The number of entries in the index.
     */
    uint32_t getIndexCount() const { return m_index[0].asArray[2]; }

    /**
     * @brief Get the IndexEntry object for a given path.
     *
     * @details This function returns a pointer to the IndexEntry object
     * corresponding to the given path. The path is hashed using the djb2
     * hash function, and the resulting hash is used to look up the entry
     * in the index using a binary search. If the archive manager was not
     * initialized, failed to initialize, or the path was not found in the
     * index, this function will return nullptr.
     *
     * @param path The path to look up.
     * @return IndexEntry* Pointer to the IndexEntry object corresponding to the path.
     */
    const IndexEntry *getIndexEntry(eastl::string_view path) const;
    template <unsigned S>
    const IndexEntry *getIndexEntry(const char (&path)[S]) const {
        return getIndexEntry(djb::hash<uint64_t>(path));
    }
    const IndexEntry *getIndexEntry(uint64_t hash) const;

    /**
     * @brief Get the LBA of the first sector of the file in the archive.
     *
     * @param entry The IndexEntry object for the file.
     * @return uint32_t The LBA of the first sector of the file in the archive.
     */
    uint32_t getIndexEntrySectorStart(const IndexEntry *entry) const {
        return m_archiveDirentry.LBA + entry->getSectorOffset();
    }

    /**
     * @brief Set the Buffer object for the next read operation.
     *
     * @details This function sets the buffer to be used for the next read
     * operation. By default, the archive manager will allocate a buffer of the
     * appropriate size for the file being read. However, if the user wants to
     * use an already allocated buffer, they can use this function to set the buffer
     * to be used.
     *
     * @param buffer The buffer to be used for the next read operation.
     */
    void setBuffer(Buffer<uint8_t> &&buffer) { m_data = eastl::move(buffer); }

    /**
     * @brief Read a file from the archive.
     *
     * @details This function reads a file from the archive. The file may
     * be specified by its path, hash, or IndexEntry object. The callback
     * will be called with the data of the file, or an empty buffer if the
     * file could not be read. Note that the template variants of this
     * function should be guaranteed to be computing the hash of the
     * string at compile time.
     */
    template <unsigned S>
    void readFile(const char (&path)[S], CDRom &device, eastl::function<void(Buffer<uint8_t> &&)> &&callback) {
        setupQueue(getIndexEntry(path), device, eastl::move(callback));
        m_queue.run();
    }
    void readFile(eastl::string_view path, CDRom &device, eastl::function<void(Buffer<uint8_t> &&)> &&callback) {
        setupQueue(getIndexEntry(path), device, eastl::move(callback));
        m_queue.run();
    }
    void readFile(uint64_t hash, CDRom &device, eastl::function<void(Buffer<uint8_t> &&)> &&callback) {
        setupQueue(getIndexEntry(hash), device, eastl::move(callback));
        m_queue.run();
    }
    void readFile(const IndexEntry *entry, CDRom &device, eastl::function<void(Buffer<uint8_t> &&)> &&callback) {
        setupQueue(entry, device, eastl::move(callback));
        m_queue.run();
    }
    template <unsigned S>
    psyqo::TaskQueue::Task scheduleReadFile(const char (&path)[S], CDRom &device) {
        setupQueue(getIndexEntry(path), device, {});
        return m_queue.schedule();
    }
    psyqo::TaskQueue::Task scheduleReadFile(eastl::string_view path, CDRom &device) {
        setupQueue(getIndexEntry(path), device, {});
        return m_queue.schedule();
    }
    psyqo::TaskQueue::Task scheduleReadFile(uint64_t hash, CDRom &device) {
        setupQueue(getIndexEntry(hash), device, {});
        return m_queue.schedule();
    }
    psyqo::TaskQueue::Task scheduleReadFile(const IndexEntry *entry, CDRom &device) {
        setupQueue(entry, device, {});
        return m_queue.schedule();
    }
    template <unsigned S>
    ReadFileAwaiter readFile(const char (&path)[S], CDRom &device) {
        return {getIndexEntry(path), device, *this};
    }
    ReadFileAwaiter readFile(eastl::string_view path, CDRom &device) { return {getIndexEntry(path), device, *this}; }
    ReadFileAwaiter readFile(uint64_t hash, CDRom &device) { return {getIndexEntry(hash), device, *this}; }
    ReadFileAwaiter readFile(const IndexEntry *entry, CDRom &device) { return {entry, device, *this}; }

    /**
     * @brief Register a decompressor for a specific compression method.
     *
     * @details In the spirit of paying for what you use, these functions allow
     * the user to register a decompressor for a specific compression method.
     * For instance, if the user knows that the archive will only contain
     * LZ4 compressed files, they can register the LZ4 decompressor and the
     * UCL_NRV2E decompressor will not be registered. This will reduce the
     * final binary size of the program, as the decompressor code will not
     * be included in the final binary. The UCL_NRV2E decompressor takes
     * 340 bytes of code, while the LZ4 decompressor takes 200 bytes of code.
     * It is also reasonable to not register any decompressors at all, if the
     * user is sure that the archive will not contain any compressed files.
     */
    static void registerUCL_NRV2EDecompressor() {
        s_decompressors[toUnderlying(IndexEntry::Method::UCL_NRV2E)] = &ArchiveManager::decompressUCL_NRV2E;
    }
    static void registerLZ4Decompressor() {
        s_decompressors[toUnderlying(IndexEntry::Method::LZ4)] = &ArchiveManager::decompressLZ4;
    }

    /**
     * @brief Register all decompressors.
     *
     * @details This function registers all decompressors. This is in the case
     * the user doesn't know which decompressors will be used, or if the user wants
     * to use all decompressors. This will increase the final binary size of the
     * program, as all decompressor code will be included in the final binary.
     */
    static void registerAllDecompressors() {
        registerUCL_NRV2EDecompressor();
        registerLZ4Decompressor();
    }

  private:
    eastl::function<void(bool)> m_initCallback;
    eastl::function<void(Buffer<uint8_t> &&)> m_callback;
    psyqo::TaskQueue m_queueInitFilename;
    psyqo::TaskQueue m_queue;
    Buffer<uint8_t> m_data;
    Buffer<IndexEntry> m_index;
    ISO9660Parser::DirEntry m_archiveDirentry;
    CDRom::ReadRequest m_request;
    bool m_pending = false;
    bool m_success = false;

    void setupInitQueue(eastl::string_view archiveName, ISO9660Parser &parser, eastl::function<void(bool)> &&callback);
    void setupInitQueue(uint32_t LBA, CDRom &device, eastl::function<void(bool)> &&callback);
    void setupQueue(const IndexEntry *entry, CDRom &device, eastl::function<void(Buffer<uint8_t> &&)> &&callback);
    uint32_t getIndexSectorCount() const {
        static_assert(sizeof(IndexEntry) == 16, "IndexEntry size is not 16 bytes");
        uint32_t indexSize = (getIndexCount() + 1) * sizeof(IndexEntry);
        return (indexSize + 2047) / 2048;
    }
    static eastl::array<void (ArchiveManager::*)(const IndexEntry *), toUnderlying(IndexEntry::Method::COUNT)>
        s_decompressors;
    void decompressUCL_NRV2E(const IndexEntry *entry);
    void decompressLZ4(const IndexEntry *entry);
};

}  // namespace psyqo::paths
