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

#pragma once

#include <utility>
#include <vector>

#include "support/file.h"
#include "supportpsx/iec-60908b.h"
#include "supportpsx/iso9660-dirtree.h"
#include "supportpsx/iso9660-lowlevel.h"

namespace PCSX {

class ISO9660Builder {
  public:
    ISO9660Builder(IO<File> out) : m_out(out) { m_pvd.reset(); }
    bool failed() { return !m_out || m_out->failed(); }
    IEC60908b::MSF getCurrentLocation() { return m_location; }
    void writeLicense(IO<File> licenseFile = nullptr);
    IEC60908b::MSF writeSector(const uint8_t* sectorData, IEC60908b::SectorMode mode) {
        return writeSectorAt(sectorData, m_location++, mode);
    }
    IEC60908b::MSF writeSectorAt(const uint8_t* sectorData, IEC60908b::MSF msf, IEC60908b::SectorMode mode);

    // Access the PVD for setting volume descriptor fields.
    // User-settable: SystemIdent, VolumeIdent, VolSetIdent, PublisherIdent,
    // DataPreparerIdent, ApplicationIdent, CopyrightFileIdent, AbstractFileIdent,
    // BibliographicFileIdent, dates, ApplicationUse.
    // Computed at close(): VolumeSpaceSize, PathTableSize, path table locations,
    // RootDir entry, TypeCode, StdIdent, Version, FileStructureVersion.
    ISO9660LowLevel::PVD& getPVD() { return m_pvd; }
    const ISO9660LowLevel::PVD& getPVD() const { return m_pvd; }

    // Build the filesystem tree. All allocation is deferred to close().
    ISO9660::DirTree* createRoot(unsigned sectorCount = 1);
    ISO9660::DirTree* createDir(ISO9660::DirTree* parent, const std::string& name, unsigned sectorCount = 1);
    ISO9660::DirTree* createFile(ISO9660::DirTree* parent, const std::string& name, IO<File> content);

    // Compute layout and write the entire disc image.
    // threadCount: number of worker threads for parallel EDC/ECC (0 = hardware_concurrency).
    void close(unsigned threadCount = 0);

  private:
    // Add a child node to a parent's child list (maintains insertion order).
    void appendChild(ISO9660::DirTree* parent, ISO9660::DirTree* child);

    // Layout computation
    void computeLayout();
    uint32_t computeDirEntrySize(const ISO9660::DirTree* node) const;
    uint32_t computeDirExtentSize(const ISO9660::DirTree* dir) const;
    uint32_t computePathTableSize() const;

    // Serialization helpers
    void serializeDirEntry(uint8_t* buf, const ISO9660::DirTree* node, const std::string& filenameOverride = "") const;
    void serializeDirectory(const ISO9660::DirTree* dir, uint8_t* buf, uint32_t bufSize) const;
    void serializePathTable(uint8_t* buf, uint32_t bufSize, bool bigEndian) const;
    void serializePVD(uint8_t* buf) const;

    // Write pass
    void writePVDSector();
    void writeVDSetTerminator();
    void writePathTables();
    void writeDirectories();
    void writeFiles(unsigned threadCount);
    void writeFileSectors(ISO9660::DirTree* file, unsigned threadCount);
    void writeAnchorPadding();

    ISO9660LowLevel::PVD m_pvd;
    ISO9660::DirTree* m_root = nullptr;
    std::vector<std::unique_ptr<ISO9660::DirTree>> m_nodes;

    // License data
    IO<File> m_licenseFile;
    bool m_licenseWritten = false;

    // BFS-ordered directory list (computed during layout)
    std::vector<ISO9660::DirTree*> m_dirsInBFSOrder;

    // Files in tree order (computed during layout)
    std::vector<ISO9660::DirTree*> m_filesInOrder;

    // Layout state
    uint32_t m_pathTableSize = 0;
    uint32_t m_pathTableSectorLE = 0;
    uint32_t m_pathTableSectorLEOpt = 0;
    uint32_t m_pathTableSectorBE = 0;
    uint32_t m_pathTableSectorBEOpt = 0;
    uint32_t m_totalSectors = 0;

    // Padding spans introduced by setAnchorLBA. Each pair is [start, end) in LBA terms,
    // filled with empty Mode 2 Form 1 zero sectors by writeAnchorPadding().
    std::vector<std::pair<uint32_t, uint32_t>> m_anchorPaddingRanges;

    IO<File> m_out;
    IEC60908b::MSF m_location = {0, 2, 0};
};

}  // namespace PCSX
