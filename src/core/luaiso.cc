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

#include "core/luaiso.h"

#include <memory>

#include "cdrom/cdriso.h"
#include "cdrom/file.h"
#include "cdrom/iso9660-reader.h"
#include "core/cdrom.h"
#include "lua/luafile.h"
#include "lua/luawrapper.h"
#include "support/strings-helpers.h"
#include "supportpsx/iso9660-builder.h"

namespace {

struct LuaIso {
    LuaIso(std::shared_ptr<PCSX::CDRIso> iso) : iso(iso) {}
    std::shared_ptr<PCSX::CDRIso> iso;
};

void deleteIso(LuaIso* wrapper) { delete wrapper; }
bool isIsoFailed(LuaIso* wrapper) { return wrapper->iso->failed(); }
void isoClearPPF(LuaIso* wrapper) { wrapper->iso->getPPF()->clear(); }
void isoSavePPF(LuaIso* wrapper) { wrapper->iso->getPPF()->save(wrapper->iso->getIsoPath()); }
LuaIso* getCurrentIso() { return new LuaIso(PCSX::g_emulator->m_cdrom->getIso()); }
LuaIso* openIso(const char* path) { return new LuaIso(std::make_shared<PCSX::CDRIso>(path)); }
LuaIso* openIsoFromFile(PCSX::LuaFFI::LuaFile* wrapper) {
    return new LuaIso(std::make_shared<PCSX::CDRIso>(wrapper->file));
}

PCSX::ISO9660Reader* createIsoReader(LuaIso* wrapper) { return new PCSX::ISO9660Reader(wrapper->iso); }
void deleteIsoReader(PCSX::ISO9660Reader* isoReader) { delete isoReader; }

bool isReaderFailed(PCSX::ISO9660Reader* reader) { return reader->failed(); }
PCSX::LuaFFI::LuaFile* readerOpen(PCSX::ISO9660Reader* reader, const char* path) {
    return new PCSX::LuaFFI::LuaFile(reader->open(path));
}
PCSX::LuaFFI::LuaFile* fileisoOpen(LuaIso* wrapper, uint32_t lba, uint32_t size, PCSX::IEC60908b::SectorMode mode) {
    return new PCSX::LuaFFI::LuaFile(new PCSX::CDRIsoFile(wrapper->iso, lba, size, mode));
}

struct DirEntries {
    std::vector<PCSX::ISO9660Reader::FullDirEntry> entries;
};

DirEntries* readerListDir(PCSX::ISO9660Reader* reader, const char* path) {
    auto root = reader->getRootDirEntry();
    if (path == nullptr || path[0] == '\0') {
        return new DirEntries{reader->listAllEntriesFrom(root)};
    }
    // Walk the path using listAllEntriesFrom. ISO9660 directory entries
    // don't carry version suffixes (only files do), so exact match on each
    // path component is correct for directory listing.
    auto parts = PCSX::StringsHelpers::split(std::string_view(path), "/");
    PCSX::ISO9660LowLevel::DirEntry current = root;
    for (auto& part : parts) {
        auto entries = reader->listAllEntriesFrom(current);
        bool found = false;
        for (auto& [entry, xa] : entries) {
            if (entry.get<PCSX::ISO9660LowLevel::DirEntry_Filename>().value == part) {
                current = entry;
                found = true;
                break;
            }
        }
        if (!found) return new DirEntries{};
    }
    // Only return children if the target is actually a directory.
    if ((current.get<PCSX::ISO9660LowLevel::DirEntry_Flags>().value & 2) == 0) {
        return new DirEntries{};
    }
    return new DirEntries{reader->listAllEntriesFrom(current)};
}

void deleteDirEntries(DirEntries* entries) { delete entries; }
uint32_t dirEntriesCount(DirEntries* entries) { return entries->entries.size(); }
const char* dirEntryName(DirEntries* entries, uint32_t index) {
    if (index >= entries->entries.size()) return "";
    return entries->entries[index].first.get<PCSX::ISO9660LowLevel::DirEntry_Filename>().value.c_str();
}
uint32_t dirEntryLBA(DirEntries* entries, uint32_t index) {
    if (index >= entries->entries.size()) return 0;
    return entries->entries[index].first.get<PCSX::ISO9660LowLevel::DirEntry_LBA>();
}
uint32_t dirEntrySize(DirEntries* entries, uint32_t index) {
    if (index >= entries->entries.size()) return 0;
    return entries->entries[index].first.get<PCSX::ISO9660LowLevel::DirEntry_Size>();
}
bool dirEntryIsDir(DirEntries* entries, uint32_t index) {
    if (index >= entries->entries.size()) return false;
    return (entries->entries[index].first.get<PCSX::ISO9660LowLevel::DirEntry_Flags>().value & 2) != 0;
}

struct GapEntry {
    uint32_t lba;
    uint32_t sectors;
};

struct GapList {
    std::vector<GapEntry> gaps;
};

// XA attribute bits (CD-XA spec, stored big-endian in directory record).
// Bit 11 (0x0800): Mode 2 Form 1 data file
// Bit 12 (0x1000): Mode 2 Form 2 interleaved audio/video
static constexpr uint16_t XA_ATTR_FORM2 = 0x1000;

static void collectAllEntries(PCSX::ISO9660Reader* reader, const PCSX::ISO9660LowLevel::DirEntry& dir,
                              std::vector<std::pair<uint32_t, uint32_t>>& out) {
    auto entries = reader->listAllEntriesFrom(dir);
    for (auto& [entry, xa] : entries) {
        const auto& name = entry.get<PCSX::ISO9660LowLevel::DirEntry_Filename>().value;
        if (name.size() == 1 && (name[0] == '\0' || name[0] == '\1')) continue;
        uint32_t lba = entry.get<PCSX::ISO9660LowLevel::DirEntry_LBA>();
        uint32_t size = entry.get<PCSX::ISO9660LowLevel::DirEntry_Size>();
        uint16_t attribs = xa.get<PCSX::ISO9660LowLevel::DirEntry_XA_Attribs>();
        uint32_t sectorSize = (attribs & XA_ATTR_FORM2) ? 2324 : 2048;
        uint32_t sectors = (size + sectorSize - 1) / sectorSize;
        out.push_back({lba, sectors});
        bool isDir = (entry.get<PCSX::ISO9660LowLevel::DirEntry_Flags>().value & 2) != 0;
        if (isDir) collectAllEntries(reader, entry, out);
    }
}

GapList* readerFindGaps(PCSX::ISO9660Reader* reader) {
    if (reader->failed()) return new GapList{};
    std::vector<std::pair<uint32_t, uint32_t>> allFiles;

    // Account for ISO9660 system structures
    allFiles.push_back({0, 16});  // License/system area
    auto& pvd = reader->getPVD();
    uint32_t vdEnd = reader->getVDEnd();
    allFiles.push_back({16, vdEnd > 16 ? vdEnd - 16 : 1});  // Volume descriptors including terminator
    uint32_t lPathLoc = pvd.get<PCSX::ISO9660LowLevel::PVD_LPathTableLocation>();
    uint32_t pathTableSize = pvd.get<PCSX::ISO9660LowLevel::PVD_PathTableSize>();
    uint32_t pathTableSectors = (pathTableSize + 2047) / 2048;
    allFiles.push_back({lPathLoc, pathTableSectors});
    uint32_t lPathOptLoc = pvd.get<PCSX::ISO9660LowLevel::PVD_LPathTableOptLocation>();
    if (lPathOptLoc != 0) allFiles.push_back({lPathOptLoc, pathTableSectors});
    uint32_t mPathLoc = pvd.get<PCSX::ISO9660LowLevel::PVD_MPathTableLocation>();
    allFiles.push_back({mPathLoc, pathTableSectors});
    uint32_t mPathOptLoc = pvd.get<PCSX::ISO9660LowLevel::PVD_MPathTableOptLocation>();
    if (mPathOptLoc != 0) allFiles.push_back({mPathOptLoc, pathTableSectors});
    auto& rootDir = reader->getRootDirEntry();
    uint32_t rootLBA = rootDir.get<PCSX::ISO9660LowLevel::DirEntry_LBA>();
    uint32_t rootSize = rootDir.get<PCSX::ISO9660LowLevel::DirEntry_Size>();
    allFiles.push_back({rootLBA, (rootSize + 2047) / 2048});

    collectAllEntries(reader, reader->getRootDirEntry(), allFiles);
    std::sort(allFiles.begin(), allFiles.end());

    auto* result = new GapList{};
    uint32_t nextExpected = 0;
    for (auto& [lba, sectors] : allFiles) {
        if (lba > nextExpected) {
            result->gaps.push_back({nextExpected, lba - nextExpected});
        }
        uint32_t end = lba + sectors;
        if (end > nextExpected) nextExpected = end;
    }
    return result;
}

void deleteGapList(GapList* list) { delete list; }
uint32_t gapListCount(GapList* list) { return list->gaps.size(); }
uint32_t gapEntryLBA(GapList* list, uint32_t index) {
    if (index >= list->gaps.size()) return 0;
    return list->gaps[index].lba;
}
uint32_t gapEntrySectors(GapList* list, uint32_t index) {
    if (index >= list->gaps.size()) return 0;
    return list->gaps[index].sectors;
}

PCSX::ISO9660Builder* createIsoBuilder(PCSX::LuaFFI::LuaFile* wrapper) {
    return new PCSX::ISO9660Builder(wrapper->file);
}
void deleteIsoBuilder(PCSX::ISO9660Builder* builder) { delete builder; }
void isoBuilderWriteLicense(PCSX::ISO9660Builder* builder, PCSX::LuaFFI::LuaFile* licenseWrapper) {
    builder->writeLicense(licenseWrapper->file);
}
void isoBuilderWriteSector(PCSX::ISO9660Builder* builder, const uint8_t* sectorData, PCSX::IEC60908b::SectorMode mode) {
    builder->writeSector(sectorData, mode);
}
void isoBuilderClose(PCSX::ISO9660Builder* builder) { builder->close(); }

}  // namespace

template <typename T, size_t S>
static void registerSymbol(PCSX::Lua L, const char (&name)[S], const T ptr) {
    L.push<S>(name);
    L.push((void*)ptr);
    L.settable();
}

#define REGISTER(L, s) registerSymbol(L, #s, s)

static void registerAllSymbols(PCSX::Lua L) {
    L.getfieldtable("_CLIBS", LUA_REGISTRYINDEX);
    L.push("CORE_ISO");
    L.newtable();

    REGISTER(L, deleteIso);
    REGISTER(L, isIsoFailed);
    REGISTER(L, isoClearPPF);
    REGISTER(L, isoSavePPF);
    REGISTER(L, getCurrentIso);
    REGISTER(L, openIso);
    REGISTER(L, openIsoFromFile);
    REGISTER(L, createIsoReader);
    REGISTER(L, deleteIsoReader);
    REGISTER(L, isReaderFailed);
    REGISTER(L, readerOpen);
    REGISTER(L, fileisoOpen);

    REGISTER(L, readerListDir);
    REGISTER(L, deleteDirEntries);
    REGISTER(L, dirEntriesCount);
    REGISTER(L, dirEntryName);
    REGISTER(L, dirEntryLBA);
    REGISTER(L, dirEntrySize);
    REGISTER(L, dirEntryIsDir);

    REGISTER(L, readerFindGaps);
    REGISTER(L, deleteGapList);
    REGISTER(L, gapListCount);
    REGISTER(L, gapEntryLBA);
    REGISTER(L, gapEntrySectors);

    REGISTER(L, createIsoBuilder);
    REGISTER(L, deleteIsoBuilder);
    REGISTER(L, isoBuilderWriteLicense);
    REGISTER(L, isoBuilderWriteSector);
    REGISTER(L, isoBuilderClose);

    L.settable();
    L.pop();
}

void PCSX::LuaFFI::open_iso(Lua L) {
    static int lualoader = 1;
    static const char* isoFFI = (
#include "core/isoffi.lua"
    );
    registerAllSymbols(L);
    L.load(isoFFI, "src:core/isoffi.lua");
}
