/*

MIT License

Copyright (c) 2026 PCSX-Redux authors

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

#include "supportpsx/iso9660-isobuilder.h"

#include <atomic>
#include <cstring>
#include <queue>
#include <semaphore>
#include <thread>

#include "iec-60908b/edcecc.h"

namespace {

// Write a 32-bit value in little-endian to a buffer.
void writeLE32(uint8_t* buf, uint32_t val) {
    buf[0] = val & 0xff;
    buf[1] = (val >> 8) & 0xff;
    buf[2] = (val >> 16) & 0xff;
    buf[3] = (val >> 24) & 0xff;
}

// Write a 32-bit value in big-endian to a buffer.
void writeBE32(uint8_t* buf, uint32_t val) {
    buf[0] = (val >> 24) & 0xff;
    buf[1] = (val >> 16) & 0xff;
    buf[2] = (val >> 8) & 0xff;
    buf[3] = val & 0xff;
}

// Write a 16-bit value in little-endian to a buffer.
void writeLE16(uint8_t* buf, uint16_t val) {
    buf[0] = val & 0xff;
    buf[1] = (val >> 8) & 0xff;
}

// Write a 16-bit value in big-endian to a buffer.
void writeBE16(uint8_t* buf, uint16_t val) {
    buf[0] = (val >> 8) & 0xff;
    buf[1] = val & 0xff;
}

// Write both-endian 32-bit pair.
void writeBothEndian32(uint8_t* buf, uint32_t val) {
    writeLE32(buf, val);
    writeBE32(buf + 4, val);
}

// Write both-endian 16-bit pair.
void writeBothEndian16(uint8_t* buf, uint16_t val) {
    writeLE16(buf, val);
    writeBE16(buf + 2, val);
}

uint32_t ceilDiv(uint32_t a, uint32_t b) { return (a + b - 1) / b; }

static const uint8_t c_sync[12] = {0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00};

// Prepare a raw 2352-byte M2 Form 1 sector frame.
void prepareM2F1Frame(uint8_t* frame, uint32_t lba, const uint8_t* data2048) {
    memset(frame, 0, 2352);
    memcpy(frame, c_sync, 12);
    PCSX::IEC60908b::MSF msf(lba + 150);
    msf.toBCD(frame + 12);
    frame[15] = 2;  // mode 2
    // Subheader: file 0, channel 0, submode 0x08 (data), coding 0
    frame[16] = frame[20] = 0;
    frame[17] = frame[21] = 0;
    frame[18] = frame[22] = 0x08;
    frame[19] = frame[23] = 0;
    memcpy(frame + 24, data2048, 2048);
    compute_edcecc(frame);
}

// Prepare a raw M2F1 frame without computing EDC/ECC (for parallel processing).
void prepareM2F1FrameNoECC(uint8_t* frame, uint32_t lba, const uint8_t* data2048) {
    memset(frame, 0, 2352);
    memcpy(frame, c_sync, 12);
    PCSX::IEC60908b::MSF msf(lba + 150);
    msf.toBCD(frame + 12);
    frame[15] = 2;
    frame[16] = frame[20] = 0;
    frame[17] = frame[21] = 0;
    frame[18] = frame[22] = 0x08;
    frame[19] = frame[23] = 0;
    memcpy(frame + 24, data2048, 2048);
}

// Prepare a raw M2F2 frame without computing EDC/ECC.
void prepareM2F2FrameNoECC(uint8_t* frame, uint32_t lba, const uint8_t* data2324,
                            uint8_t fileNum = 0, uint8_t channelNum = 0, uint8_t submode = 0x08,
                            uint8_t codingInfo = 0) {
    memset(frame, 0, 2352);
    memcpy(frame, c_sync, 12);
    PCSX::IEC60908b::MSF msf(lba + 150);
    msf.toBCD(frame + 12);
    frame[15] = 2;
    frame[16] = frame[20] = fileNum;
    frame[17] = frame[21] = channelNum;
    frame[18] = frame[22] = submode | 0x20;  // form 2 flag
    frame[19] = frame[23] = codingInfo;
    memcpy(frame + 24, data2324, 2324);
}

}  // namespace

PCSX::ISO9660::IsoBuilder::IsoBuilder(IO<File> output) : m_sectorWriter(output) { m_pvd.reset(); }

void PCSX::ISO9660::IsoBuilder::writeLicense(IO<File> licenseFile) {
    m_licenseFile = licenseFile;
    m_licenseWritten = false;
}

PCSX::ISO9660::DirTree* PCSX::ISO9660::IsoBuilder::createRoot(unsigned sectorCount) {
    auto node = std::make_unique<DirTree>();
    node->m_name = "\x01";  // root name in path table
    node->m_isDir = true;
    node->m_dirSectorCount = sectorCount;
    node->m_hasXA = true;
    m_root = node.get();
    m_nodes.push_back(std::move(node));
    return m_root;
}

PCSX::ISO9660::DirTree* PCSX::ISO9660::IsoBuilder::createDir(DirTree* parent, const std::string& name,
                                                               unsigned sectorCount) {
    auto node = std::make_unique<DirTree>();
    node->m_name = name;
    node->m_isDir = true;
    node->m_dirSectorCount = sectorCount;
    node->m_hasXA = parent->m_hasXA;
    node->m_date = parent->m_date;
    auto* raw = node.get();
    m_nodes.push_back(std::move(node));
    appendChild(parent, raw);
    return raw;
}

PCSX::ISO9660::DirTree* PCSX::ISO9660::IsoBuilder::createFile(DirTree* parent, const std::string& name,
                                                                IO<File> content) {
    auto node = std::make_unique<DirTree>();
    node->m_name = name;
    node->m_isDir = false;
    node->m_content = content;
    node->m_hasXA = parent->m_hasXA;
    node->m_date = parent->m_date;
    auto* raw = node.get();
    m_nodes.push_back(std::move(node));
    appendChild(parent, raw);
    return raw;
}

void PCSX::ISO9660::IsoBuilder::appendChild(DirTree* parent, DirTree* child) {
    child->m_parent = parent;
    if (!parent->m_firstChild) {
        parent->m_firstChild = child;
    } else {
        // Append to end of sibling list to maintain insertion order.
        DirTree* p = parent->m_firstChild;
        while (p->m_nextSibling) p = p->m_nextSibling;
        p->m_nextSibling = child;
    }
}

// Compute the serialized size of a single DirEntry record for a node.
uint32_t PCSX::ISO9660::IsoBuilder::computeDirEntrySize(const DirTree* node) const {
    // For "." and ".." entries, filename is 1 byte (\x00 or \x01).
    // For regular entries, filename is the name length (plus ";1" suffix for files).
    uint32_t nameLen = node->m_name.size();
    if (!node->m_isDir) nameLen += 2;  // ";1" suffix
    uint32_t size = 33 + nameLen;
    if (nameLen % 2 == 0) size++;  // padding byte for even-length filenames
    if (node->m_hasXA) size += 14;
    return size;
}

// Compute total bytes needed for a directory extent (all entries including "." and "..").
uint32_t PCSX::ISO9660::IsoBuilder::computeDirExtentSize(const DirTree* dir) const {
    // "." entry: name = \x00, length 1
    uint32_t dotSize = 33 + 1;  // name length 1, odd -> no padding
    if (dir->m_hasXA) dotSize += 14;

    // ".." entry: name = \x01, length 1
    uint32_t dotdotSize = dotSize;  // same structure

    uint32_t total = 0;
    uint32_t posInSector = 0;

    // Add "." entry
    if (posInSector + dotSize > 2048) {
        total += 2048 - posInSector;
        posInSector = 0;
    }
    total += dotSize;
    posInSector += dotSize;

    // Add ".." entry
    if (posInSector + dotdotSize > 2048) {
        total += 2048 - posInSector;
        posInSector = 0;
    }
    total += dotdotSize;
    posInSector += dotdotSize;

    // Add child entries
    for (DirTree* child = dir->m_firstChild; child; child = child->m_nextSibling) {
        uint32_t entrySize = computeDirEntrySize(child);
        if (posInSector + entrySize > 2048) {
            total += 2048 - posInSector;
            posInSector = 0;
        }
        total += entrySize;
        posInSector += entrySize;
    }

    return total;
}

uint32_t PCSX::ISO9660::IsoBuilder::computePathTableSize() const {
    uint32_t size = 0;
    for (auto* dir : m_dirsInBFSOrder) {
        uint8_t nameLen;
        if (dir == m_root) {
            nameLen = 1;  // root name is \x01
        } else {
            nameLen = dir->m_name.size();
        }
        size += 8 + nameLen;
        if (nameLen % 2 == 1) size++;  // padding for odd-length names
    }
    return size;
}

void PCSX::ISO9660::IsoBuilder::computeLayout() {
    // Build BFS order list of directories.
    m_dirsInBFSOrder.clear();
    m_filesInOrder.clear();

    if (!m_root) return;

    // BFS traversal for directories.
    std::queue<DirTree*> bfsQueue;
    bfsQueue.push(m_root);
    while (!bfsQueue.empty()) {
        DirTree* dir = bfsQueue.front();
        bfsQueue.pop();
        m_dirsInBFSOrder.push_back(dir);
        for (DirTree* child = dir->m_firstChild; child; child = child->m_nextSibling) {
            if (child->m_isDir) bfsQueue.push(child);
        }
    }

    // Collect files in insertion order (DFS through children).
    std::function<void(DirTree*)> collectFiles = [&](DirTree* dir) {
        for (DirTree* child = dir->m_firstChild; child; child = child->m_nextSibling) {
            if (!child->m_isDir) {
                m_filesInOrder.push_back(child);
            } else {
                collectFiles(child);
            }
        }
    };
    collectFiles(m_root);

    // Assign path table indices (1-based, BFS order).
    for (uint16_t i = 0; i < m_dirsInBFSOrder.size(); i++) {
        m_dirsInBFSOrder[i]->m_pathTableIndex = i + 1;
    }

    // Compute path table size.
    m_pathTableSize = computePathTableSize();
    uint32_t ptSectors = ceilDiv(m_pathTableSize, 2048);

    // Assign LBAs.
    uint32_t currentSector = 16;  // after system area (sectors 0-15)

    // Sector 16: PVD
    currentSector++;  // 17

    // Sector 17: VD Set Terminator
    currentSector++;  // 18

    // Path tables: 4 copies (LE, LE optional, BE, BE optional)
    m_pathTableSectorLE = currentSector;
    currentSector += ptSectors;
    m_pathTableSectorLEOpt = currentSector;
    currentSector += ptSectors;
    m_pathTableSectorBE = currentSector;
    currentSector += ptSectors;
    m_pathTableSectorBEOpt = currentSector;
    currentSector += ptSectors;

    // Directory extents in BFS order.
    for (auto* dir : m_dirsInBFSOrder) {
        dir->m_assignedLBA = currentSector;
        dir->m_computedSize = dir->m_dirSectorCount * 2048;
        currentSector += dir->m_dirSectorCount;
    }

    // File data.
    for (auto* file : m_filesInOrder) {
        file->m_assignedLBA = currentSector;
        uint32_t fileSize = 0;
        if (file->m_content && !file->m_content->failed()) {
            fileSize = file->m_content->size();
        }
        file->m_computedSize = fileSize;

        // Compute sectors based on mode.
        uint32_t bytesPerSector;
        switch (file->m_sectorMode) {
            case IEC60908b::SectorMode::M2_FORM2:
                bytesPerSector = 2324;
                break;
            case IEC60908b::SectorMode::M2_RAW:
                bytesPerSector = 2336;
                break;
            case IEC60908b::SectorMode::RAW:
                bytesPerSector = 2352;
                break;
            case IEC60908b::SectorMode::M1:
            case IEC60908b::SectorMode::M2_FORM1:
            default:
                bytesPerSector = 2048;
                break;
        }
        uint32_t fileSectors = fileSize > 0 ? ceilDiv(fileSize, bytesPerSector) : 0;
        currentSector += fileSectors;
    }

    m_totalSectors = currentSector;
}

// Serialize a directory entry record into a buffer. Returns number of bytes written.
void PCSX::ISO9660::IsoBuilder::serializeDirEntry(uint8_t* buf, const DirTree* node,
                                                    const std::string& filenameOverride) const {
    const std::string& fname = filenameOverride.empty() ? node->m_name : filenameOverride;
    uint32_t nameLen = fname.size();

    uint32_t length = 33 + nameLen;
    if (nameLen % 2 == 0) length++;
    if (node->m_hasXA) length += 14;

    memset(buf, 0, length);

    buf[0] = length;          // Length
    buf[1] = 0;               // Extended Attribute Record Length
    writeLE32(buf + 2, node->m_assignedLBA);   // LBA (LE)
    writeBE32(buf + 6, node->m_assignedLBA);   // LBA (BE)
    writeLE32(buf + 10, node->m_computedSize); // Size (LE)
    writeBE32(buf + 14, node->m_computedSize); // Size (BE)

    // Date (ShortDate: 7 bytes at offset 18)
    const auto& date = node->m_date;
    buf[18] = date.get<ISO9660LowLevel::ShortDate_Year>().value;
    buf[19] = date.get<ISO9660LowLevel::ShortDate_Month>().value;
    buf[20] = date.get<ISO9660LowLevel::ShortDate_Day>().value;
    buf[21] = date.get<ISO9660LowLevel::ShortDate_Hour>().value;
    buf[22] = date.get<ISO9660LowLevel::ShortDate_Minute>().value;
    buf[23] = date.get<ISO9660LowLevel::ShortDate_Second>().value;
    buf[24] = date.get<ISO9660LowLevel::ShortDate_Offset>().value;

    // Flags
    uint8_t flags = 0;
    if (node->m_hidden) flags |= 0x01;
    if (node->m_isDir) flags |= 0x02;
    buf[25] = flags;

    buf[26] = 0;  // Unit Size
    buf[27] = 0;  // Interleave Gap

    // Volume Sequence Number (both endian)
    writeBothEndian16(buf + 28, 1);

    // Filename
    buf[32] = nameLen;
    memcpy(buf + 33, fname.data(), nameLen);

    // XA extension (after filename + padding)
    if (node->m_hasXA) {
        uint32_t xaOffset = 33 + nameLen;
        if (nameLen % 2 == 0) xaOffset++;  // padding byte

        // XA system use: GroupID(2), UserID(2), Attribs(2), Signature "XA"(2), FileNum(1), Reserved(5)
        const auto& xa = node->m_xa;
        uint16_t groupId = xa.get<ISO9660LowLevel::DirEntry_XA_GroupID>().value;
        uint16_t userId = xa.get<ISO9660LowLevel::DirEntry_XA_UserID>().value;
        uint16_t attribs = xa.get<ISO9660LowLevel::DirEntry_XA_Attribs>().value;
        uint8_t fileNum = xa.get<ISO9660LowLevel::DirEntry_XA_FileNum>().value;

        writeBE16(buf + xaOffset, groupId);
        writeBE16(buf + xaOffset + 2, userId);
        writeBE16(buf + xaOffset + 4, attribs);
        buf[xaOffset + 6] = 'X';
        buf[xaOffset + 7] = 'A';
        buf[xaOffset + 8] = fileNum;
        memset(buf + xaOffset + 9, 0, 5);  // Reserved
    }
}

void PCSX::ISO9660::IsoBuilder::serializeDirectory(const DirTree* dir, uint8_t* buf, uint32_t bufSize) const {
    memset(buf, 0, bufSize);
    uint32_t offset = 0;

    // Helper: check sector boundary and pad if needed.
    auto checkBoundary = [&](uint32_t entrySize) {
        uint32_t posInSector = offset % 2048;
        if (posInSector + entrySize > 2048) {
            offset += 2048 - posInSector;  // pad to next sector
        }
    };

    // "." entry - points to this directory
    {
        DirTree dotEntry;
        dotEntry.m_name = std::string(1, '\x00');
        dotEntry.m_isDir = true;
        dotEntry.m_assignedLBA = dir->m_assignedLBA;
        dotEntry.m_computedSize = dir->m_computedSize;
        dotEntry.m_date = dir->m_date;
        dotEntry.m_hasXA = dir->m_hasXA;
        dotEntry.m_xa = dir->m_xa;

        uint32_t entrySize = 33 + 1;  // name len 1 (odd, no padding)
        if (dir->m_hasXA) entrySize += 14;

        checkBoundary(entrySize);
        serializeDirEntry(buf + offset, &dotEntry);
        offset += entrySize;
    }

    // ".." entry - points to parent (or self for root)
    {
        const DirTree* parentDir = dir->m_parent ? dir->m_parent : dir;
        DirTree dotdotEntry;
        dotdotEntry.m_name = std::string(1, '\x01');
        dotdotEntry.m_isDir = true;
        dotdotEntry.m_assignedLBA = parentDir->m_assignedLBA;
        dotdotEntry.m_computedSize = parentDir->m_computedSize;
        dotdotEntry.m_date = parentDir->m_date;
        dotdotEntry.m_hasXA = dir->m_hasXA;
        dotdotEntry.m_xa = dir->m_xa;

        uint32_t entrySize = 33 + 1;
        if (dir->m_hasXA) entrySize += 14;

        checkBoundary(entrySize);
        serializeDirEntry(buf + offset, &dotdotEntry);
        offset += entrySize;
    }

    // Child entries
    for (DirTree* child = dir->m_firstChild; child; child = child->m_nextSibling) {
        // ISO9660 filename: directories use plain name, files add ";1" suffix
        std::string isoName = child->m_name;
        if (!child->m_isDir) isoName += ";1";

        uint32_t entrySize = computeDirEntrySize(child);
        checkBoundary(entrySize);
        serializeDirEntry(buf + offset, child, isoName);
        offset += entrySize;
    }
}

void PCSX::ISO9660::IsoBuilder::serializePathTable(uint8_t* buf, uint32_t bufSize, bool bigEndian) const {
    memset(buf, 0, bufSize);
    uint32_t offset = 0;

    for (auto* dir : m_dirsInBFSOrder) {
        uint8_t nameLen;
        const char* name;
        if (dir == m_root) {
            nameLen = 1;
            name = "\x01";
        } else {
            nameLen = dir->m_name.size();
            name = dir->m_name.c_str();
        }

        uint32_t recordSize = 8 + nameLen;
        if (nameLen % 2 == 1) recordSize++;

        buf[offset] = nameLen;
        buf[offset + 1] = 0;  // extended attribute record length

        uint32_t lba = dir->m_assignedLBA;
        uint16_t parentIdx = dir->m_parent ? dir->m_parent->m_pathTableIndex : 1;

        if (bigEndian) {
            writeBE32(buf + offset + 2, lba);
            writeBE16(buf + offset + 6, parentIdx);
        } else {
            writeLE32(buf + offset + 2, lba);
            writeLE16(buf + offset + 6, parentIdx);
        }

        memcpy(buf + offset + 8, name, nameLen);
        // Padding byte (if odd nameLen) is already zeroed from memset.

        offset += recordSize;
    }
}

void PCSX::ISO9660::IsoBuilder::serializePVD(uint8_t* buf) const {
    memset(buf, 0, 2048);

    buf[0] = 1;    // Type Code: Primary Volume Descriptor
    buf[1] = 'C';  // Standard Identifier
    buf[2] = 'D';
    buf[3] = '0';
    buf[4] = '0';
    buf[5] = '1';
    buf[6] = 1;  // Version
    // buf[7] = 0; // Unused

    // Copy PVD string fields from the user-settable PVD struct.
    auto copyField = [&](uint32_t offset, const char* src, size_t maxLen) {
        size_t len = strnlen(src, maxLen);
        memcpy(buf + offset, src, len);
        // Pad with spaces.
        for (size_t i = len; i < maxLen; i++) buf[offset + i] = ' ';
    };

    copyField(8, m_pvd.get<ISO9660LowLevel::PVD_SystemIdent>().value, 32);
    copyField(40, m_pvd.get<ISO9660LowLevel::PVD_VolumeIdent>().value, 32);

    // Volume Space Size (both endian)
    writeBothEndian32(buf + 80, m_totalSectors);

    // Volume Set Size (both endian) = 1
    writeBothEndian16(buf + 120, 1);

    // Volume Sequence Number (both endian) = 1
    writeBothEndian16(buf + 124, 1);

    // Logical Block Size (both endian) = 2048
    writeBothEndian16(buf + 128, 2048);

    // Path Table Size (both endian)
    writeBothEndian32(buf + 132, m_pathTableSize);

    // Path table locations
    writeLE32(buf + 140, m_pathTableSectorLE);
    writeLE32(buf + 144, m_pathTableSectorLEOpt);
    writeBE32(buf + 148, m_pathTableSectorBE);
    writeBE32(buf + 152, m_pathTableSectorBEOpt);

    // Root directory record (34 bytes at offset 156)
    if (m_root) {
        // Serialize root as a DirEntry at PVD offset 156.
        // Root directory record in PVD uses name = \x00 (1 byte), length = 34.
        DirTree rootEntry;
        rootEntry.m_name = std::string(1, '\x00');
        rootEntry.m_isDir = true;
        rootEntry.m_assignedLBA = m_root->m_assignedLBA;
        rootEntry.m_computedSize = m_root->m_computedSize;
        rootEntry.m_date = m_root->m_date;
        rootEntry.m_hasXA = false;  // PVD root entry doesn't include XA
        serializeDirEntry(buf + 156, &rootEntry);
    }

    // String fields
    copyField(190, m_pvd.get<ISO9660LowLevel::PVD_VolSetIdent>().value, 128);
    copyField(318, m_pvd.get<ISO9660LowLevel::PVD_PublisherIdent>().value, 128);
    copyField(446, m_pvd.get<ISO9660LowLevel::PVD_DataPreparerIdent>().value, 128);
    copyField(574, m_pvd.get<ISO9660LowLevel::PVD_ApplicationIdent>().value, 128);
    copyField(702, m_pvd.get<ISO9660LowLevel::PVD_CopyrightFileIdent>().value, 37);
    copyField(739, m_pvd.get<ISO9660LowLevel::PVD_AbstractFileIdent>().value, 37);
    copyField(776, m_pvd.get<ISO9660LowLevel::PVD_BibliographicFileIdent>().value, 37);

    // Dates (LongDate: 17 bytes each)
    auto serializeLongDate = [&](uint32_t offset, const auto& dateField) {
        const auto& date = dateField;
        memcpy(buf + offset, date.template get<ISO9660LowLevel::LongDate_Year>().value, 4);
        memcpy(buf + offset + 4, date.template get<ISO9660LowLevel::LongDate_Month>().value, 2);
        memcpy(buf + offset + 6, date.template get<ISO9660LowLevel::LongDate_Day>().value, 2);
        memcpy(buf + offset + 8, date.template get<ISO9660LowLevel::LongDate_Hour>().value, 2);
        memcpy(buf + offset + 10, date.template get<ISO9660LowLevel::LongDate_Minute>().value, 2);
        memcpy(buf + offset + 12, date.template get<ISO9660LowLevel::LongDate_Second>().value, 2);
        memcpy(buf + offset + 14, date.template get<ISO9660LowLevel::LongDate_Hundredths>().value, 2);
        buf[offset + 16] = date.template get<ISO9660LowLevel::LongDate_TZ>().value;
    };

    serializeLongDate(813, m_pvd.get<ISO9660LowLevel::PVD_VolumeCreationDate>());
    serializeLongDate(830, m_pvd.get<ISO9660LowLevel::PVD_VolumeModificationDate>());
    serializeLongDate(847, m_pvd.get<ISO9660LowLevel::PVD_VolumeExpirationDate>());
    serializeLongDate(864, m_pvd.get<ISO9660LowLevel::PVD_VolumeEffectiveDate>());

    buf[881] = 1;  // File Structure Version

    // Application Use (512 bytes at offset 883)
    memcpy(buf + 883, m_pvd.get<ISO9660LowLevel::PVD_ApplicationUse>().value, 512);
}

void PCSX::ISO9660::IsoBuilder::writeSystemArea() {
    m_sectorWriter.writeLicense(m_licenseFile);
    m_licenseWritten = true;
}

void PCSX::ISO9660::IsoBuilder::writePVDSector() {
    uint8_t pvdData[2048];
    serializePVD(pvdData);
    m_sectorWriter.writeSectorAt(pvdData, IEC60908b::MSF(16 + 150), IEC60908b::SectorMode::M2_FORM1);
}

void PCSX::ISO9660::IsoBuilder::writeVDSetTerminator() {
    uint8_t data[2048];
    memset(data, 0, 2048);
    data[0] = 255;  // Type Code: Terminator
    data[1] = 'C';
    data[2] = 'D';
    data[3] = '0';
    data[4] = '0';
    data[5] = '1';
    data[6] = 1;  // Version
    m_sectorWriter.writeSectorAt(data, IEC60908b::MSF(17 + 150), IEC60908b::SectorMode::M2_FORM1);
}

void PCSX::ISO9660::IsoBuilder::writePathTables() {
    uint32_t ptSectors = ceilDiv(m_pathTableSize, 2048);
    uint32_t ptBufSize = ptSectors * 2048;
    std::vector<uint8_t> ptBuf(ptBufSize, 0);

    // LE path table
    serializePathTable(ptBuf.data(), ptBufSize, false);
    for (uint32_t i = 0; i < ptSectors; i++) {
        m_sectorWriter.writeSectorAt(ptBuf.data() + i * 2048, IEC60908b::MSF(m_pathTableSectorLE + i + 150),
                                     IEC60908b::SectorMode::M2_FORM1);
    }
    // LE optional copy
    for (uint32_t i = 0; i < ptSectors; i++) {
        m_sectorWriter.writeSectorAt(ptBuf.data() + i * 2048, IEC60908b::MSF(m_pathTableSectorLEOpt + i + 150),
                                     IEC60908b::SectorMode::M2_FORM1);
    }

    // BE path table
    memset(ptBuf.data(), 0, ptBufSize);
    serializePathTable(ptBuf.data(), ptBufSize, true);
    for (uint32_t i = 0; i < ptSectors; i++) {
        m_sectorWriter.writeSectorAt(ptBuf.data() + i * 2048, IEC60908b::MSF(m_pathTableSectorBE + i + 150),
                                     IEC60908b::SectorMode::M2_FORM1);
    }
    // BE optional copy
    for (uint32_t i = 0; i < ptSectors; i++) {
        m_sectorWriter.writeSectorAt(ptBuf.data() + i * 2048, IEC60908b::MSF(m_pathTableSectorBEOpt + i + 150),
                                     IEC60908b::SectorMode::M2_FORM1);
    }
}

void PCSX::ISO9660::IsoBuilder::writeDirectories() {
    for (auto* dir : m_dirsInBFSOrder) {
        uint32_t extentSize = dir->m_dirSectorCount * 2048;
        std::vector<uint8_t> dirBuf(extentSize, 0);
        serializeDirectory(dir, dirBuf.data(), extentSize);

        uint32_t sectors = dir->m_dirSectorCount;
        for (uint32_t i = 0; i < sectors; i++) {
            m_sectorWriter.writeSectorAt(dirBuf.data() + i * 2048,
                                         IEC60908b::MSF(dir->m_assignedLBA + i + 150),
                                         IEC60908b::SectorMode::M2_FORM1);
        }
    }
}

void PCSX::ISO9660::IsoBuilder::writeFiles(unsigned threadCount) {
    if (threadCount == 0) threadCount = std::thread::hardware_concurrency();
    if (threadCount == 0) threadCount = 1;

    if (threadCount == 1) {
        // Single-threaded: use the existing sector writer directly.
        for (auto* file : m_filesInOrder) {
            if (!file->m_content || file->m_content->failed() || file->m_computedSize == 0) continue;

            file->m_content->rSeek(0, SEEK_SET);
            uint32_t remaining = file->m_computedSize;
            uint32_t lba = file->m_assignedLBA;

            uint32_t bytesPerSector;
            switch (file->m_sectorMode) {
                case IEC60908b::SectorMode::M2_FORM2:
                    bytesPerSector = 2324;
                    break;
                case IEC60908b::SectorMode::M2_RAW:
                    bytesPerSector = 2336;
                    break;
                case IEC60908b::SectorMode::RAW:
                    bytesPerSector = 2352;
                    break;
                default:
                    bytesPerSector = 2048;
                    break;
            }

            while (remaining > 0) {
                uint8_t sectorData[2352];
                memset(sectorData, 0, sizeof(sectorData));
                uint32_t toRead = std::min(remaining, bytesPerSector);
                file->m_content->read(sectorData, toRead);
                m_sectorWriter.writeSectorAt(sectorData, IEC60908b::MSF(lba + 150), file->m_sectorMode);
                lba++;
                remaining -= toRead;
            }
        }
        return;
    }

    // Multi-threaded: parallel EDC/ECC computation.
    // Strategy: main thread prepares all frames first, then workers process them in parallel,
    // then write sequentially.
    struct SectorWork {
        uint8_t frame[2352];
        uint32_t lba;
        bool needsECC;
        std::binary_semaphore done{0};
    };

    // Count total file sectors.
    uint32_t totalFileSectors = 0;
    for (auto* file : m_filesInOrder) {
        if (!file->m_content || file->m_content->failed() || file->m_computedSize == 0) continue;
        uint32_t bytesPerSector;
        switch (file->m_sectorMode) {
            case IEC60908b::SectorMode::M2_FORM2: bytesPerSector = 2324; break;
            case IEC60908b::SectorMode::M2_RAW: bytesPerSector = 2336; break;
            case IEC60908b::SectorMode::RAW: bytesPerSector = 2352; break;
            default: bytesPerSector = 2048; break;
        }
        totalFileSectors += ceilDiv(file->m_computedSize, bytesPerSector);
    }

    if (totalFileSectors == 0) return;

    // Phase 1: Prepare all frames (main thread only - reads file content).
    std::vector<SectorWork> workItems(totalFileSectors);
    uint32_t workIdx = 0;
    for (auto* file : m_filesInOrder) {
        if (!file->m_content || file->m_content->failed() || file->m_computedSize == 0) continue;

        file->m_content->rSeek(0, SEEK_SET);
        uint32_t remaining = file->m_computedSize;
        uint32_t lba = file->m_assignedLBA;

        uint32_t bytesPerSector;
        switch (file->m_sectorMode) {
            case IEC60908b::SectorMode::M2_FORM2: bytesPerSector = 2324; break;
            case IEC60908b::SectorMode::M2_RAW: bytesPerSector = 2336; break;
            case IEC60908b::SectorMode::RAW: bytesPerSector = 2352; break;
            default: bytesPerSector = 2048; break;
        }

        while (remaining > 0) {
            uint8_t data[2352];
            memset(data, 0, sizeof(data));
            uint32_t toRead = std::min(remaining, bytesPerSector);
            file->m_content->read(data, toRead);

            auto& work = workItems[workIdx];
            work.lba = lba;

            switch (file->m_sectorMode) {
                case IEC60908b::SectorMode::M2_FORM1:
                    prepareM2F1FrameNoECC(work.frame, lba, data);
                    work.needsECC = true;
                    break;
                case IEC60908b::SectorMode::M2_FORM2:
                    prepareM2F2FrameNoECC(work.frame, lba, data);
                    work.needsECC = true;
                    break;
                case IEC60908b::SectorMode::RAW:
                    memcpy(work.frame, data, 2352);
                    work.needsECC = false;
                    break;
                default:
                    prepareM2F1FrameNoECC(work.frame, lba, data);
                    work.needsECC = true;
                    break;
            }

            workIdx++;
            lba++;
            remaining -= toRead;
        }
    }

    // Phase 2: Parallel EDC/ECC computation.
    std::atomic<uint32_t> nextWork{0};
    std::vector<std::thread> workers;
    for (unsigned t = 0; t < threadCount; t++) {
        workers.emplace_back([&]() {
            while (true) {
                uint32_t idx = nextWork.fetch_add(1, std::memory_order_relaxed);
                if (idx >= totalFileSectors) break;
                if (workItems[idx].needsECC) {
                    compute_edcecc(workItems[idx].frame);
                }
                workItems[idx].done.release();
            }
        });
    }

    // Phase 3: Write frames sequentially as they complete.
    for (uint32_t i = 0; i < totalFileSectors; i++) {
        workItems[i].done.acquire();
        m_sectorWriter.writeRawFrame(workItems[i].frame, workItems[i].lba);
    }

    for (auto& w : workers) w.join();
}

void PCSX::ISO9660::IsoBuilder::close(unsigned threadCount) {
    if (m_closed) return;
    m_closed = true;

    computeLayout();
    writeSystemArea();
    writePVDSector();
    writeVDSetTerminator();
    writePathTables();
    writeDirectories();
    writeFiles(threadCount);
    // Don't close the output file - the caller manages its lifetime.
    // This allows the buffer to be read back after building (e.g. for verification).
}
