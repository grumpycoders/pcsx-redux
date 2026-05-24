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
#include "supportpsx/iso9660-builder.h"
#include "supportpsx/iso9660-isobuilder.h"

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

// --- High-level IsoBuilder (filesystem-aware) ---

PCSX::ISO9660::IsoBuilder* createHLIsoBuilder(PCSX::LuaFFI::LuaFile* wrapper) {
    return new PCSX::ISO9660::IsoBuilder(wrapper->file);
}
void deleteHLIsoBuilder(PCSX::ISO9660::IsoBuilder* builder) { delete builder; }
bool hlIsoBuilderFailed(PCSX::ISO9660::IsoBuilder* builder) { return builder->failed(); }
void hlIsoBuilderWriteLicense(PCSX::ISO9660::IsoBuilder* builder, PCSX::LuaFFI::LuaFile* license) {
    builder->writeLicense(license ? license->file : nullptr);
}
void hlIsoBuilderClose(PCSX::ISO9660::IsoBuilder* builder, uint32_t threadCount) {
    builder->close(threadCount);
}

// PVD string field helpers
static void trimCStringTo(const char* src, size_t maxLen, char* dst, uint32_t dstSize) {
    size_t len = strnlen(src, maxLen);
    // Trim trailing spaces and nulls.
    while (len > 0 && (src[len - 1] == ' ' || src[len - 1] == '\0')) len--;
    size_t toCopy = len < dstSize - 1 ? len : dstSize - 1;
    memcpy(dst, src, toCopy);
    dst[toCopy] = '\0';
}

// PVD getters
void hlPvdGetSystemIdent(PCSX::ISO9660::IsoBuilder* b, char* buf, uint32_t bufSize) {
    trimCStringTo(b->getPVD().get<PCSX::ISO9660LowLevel::PVD_SystemIdent>().value, 32, buf, bufSize);
}
void hlPvdGetVolumeIdent(PCSX::ISO9660::IsoBuilder* b, char* buf, uint32_t bufSize) {
    trimCStringTo(b->getPVD().get<PCSX::ISO9660LowLevel::PVD_VolumeIdent>().value, 32, buf, bufSize);
}
void hlPvdGetVolSetIdent(PCSX::ISO9660::IsoBuilder* b, char* buf, uint32_t bufSize) {
    trimCStringTo(b->getPVD().get<PCSX::ISO9660LowLevel::PVD_VolSetIdent>().value, 128, buf, bufSize);
}
void hlPvdGetPublisherIdent(PCSX::ISO9660::IsoBuilder* b, char* buf, uint32_t bufSize) {
    trimCStringTo(b->getPVD().get<PCSX::ISO9660LowLevel::PVD_PublisherIdent>().value, 128, buf, bufSize);
}
void hlPvdGetDataPreparerIdent(PCSX::ISO9660::IsoBuilder* b, char* buf, uint32_t bufSize) {
    trimCStringTo(b->getPVD().get<PCSX::ISO9660LowLevel::PVD_DataPreparerIdent>().value, 128, buf, bufSize);
}
void hlPvdGetApplicationIdent(PCSX::ISO9660::IsoBuilder* b, char* buf, uint32_t bufSize) {
    trimCStringTo(b->getPVD().get<PCSX::ISO9660LowLevel::PVD_ApplicationIdent>().value, 128, buf, bufSize);
}
void hlPvdGetCopyrightFileIdent(PCSX::ISO9660::IsoBuilder* b, char* buf, uint32_t bufSize) {
    trimCStringTo(b->getPVD().get<PCSX::ISO9660LowLevel::PVD_CopyrightFileIdent>().value, 37, buf, bufSize);
}
void hlPvdGetAbstractFileIdent(PCSX::ISO9660::IsoBuilder* b, char* buf, uint32_t bufSize) {
    trimCStringTo(b->getPVD().get<PCSX::ISO9660LowLevel::PVD_AbstractFileIdent>().value, 37, buf, bufSize);
}
void hlPvdGetBibliographicFileIdent(PCSX::ISO9660::IsoBuilder* b, char* buf, uint32_t bufSize) {
    trimCStringTo(b->getPVD().get<PCSX::ISO9660LowLevel::PVD_BibliographicFileIdent>().value, 37, buf, bufSize);
}

// PVD setters
void hlPvdSetSystemIdent(PCSX::ISO9660::IsoBuilder* b, const char* val) {
    b->getPVD().get<PCSX::ISO9660LowLevel::PVD_SystemIdent>().set(val, ' ');
}
void hlPvdSetVolumeIdent(PCSX::ISO9660::IsoBuilder* b, const char* val) {
    b->getPVD().get<PCSX::ISO9660LowLevel::PVD_VolumeIdent>().set(val, ' ');
}
void hlPvdSetVolSetIdent(PCSX::ISO9660::IsoBuilder* b, const char* val) {
    b->getPVD().get<PCSX::ISO9660LowLevel::PVD_VolSetIdent>().set(val, ' ');
}
void hlPvdSetPublisherIdent(PCSX::ISO9660::IsoBuilder* b, const char* val) {
    b->getPVD().get<PCSX::ISO9660LowLevel::PVD_PublisherIdent>().set(val, ' ');
}
void hlPvdSetDataPreparerIdent(PCSX::ISO9660::IsoBuilder* b, const char* val) {
    b->getPVD().get<PCSX::ISO9660LowLevel::PVD_DataPreparerIdent>().set(val, ' ');
}
void hlPvdSetApplicationIdent(PCSX::ISO9660::IsoBuilder* b, const char* val) {
    b->getPVD().get<PCSX::ISO9660LowLevel::PVD_ApplicationIdent>().set(val, ' ');
}
void hlPvdSetCopyrightFileIdent(PCSX::ISO9660::IsoBuilder* b, const char* val) {
    b->getPVD().get<PCSX::ISO9660LowLevel::PVD_CopyrightFileIdent>().set(val, ' ');
}
void hlPvdSetAbstractFileIdent(PCSX::ISO9660::IsoBuilder* b, const char* val) {
    b->getPVD().get<PCSX::ISO9660LowLevel::PVD_AbstractFileIdent>().set(val, ' ');
}
void hlPvdSetBibliographicFileIdent(PCSX::ISO9660::IsoBuilder* b, const char* val) {
    b->getPVD().get<PCSX::ISO9660LowLevel::PVD_BibliographicFileIdent>().set(val, ' ');
}

// DirTree wrappers
PCSX::ISO9660::DirTree* hlCreateRoot(PCSX::ISO9660::IsoBuilder* b, uint32_t sectorCount) {
    return b->createRoot(sectorCount);
}
PCSX::ISO9660::DirTree* hlCreateDir(PCSX::ISO9660::IsoBuilder* b, PCSX::ISO9660::DirTree* parent,
                                     const char* name, uint32_t sectorCount) {
    return b->createDir(parent, name, sectorCount);
}
PCSX::ISO9660::DirTree* hlCreateFile(PCSX::ISO9660::IsoBuilder* b, PCSX::ISO9660::DirTree* parent,
                                      const char* name, PCSX::LuaFFI::LuaFile* content) {
    return b->createFile(parent, name, content->file);
}

const char* dirTreeGetName(PCSX::ISO9660::DirTree* node) { return node->getName().data(); }
uint32_t dirTreeGetSize(PCSX::ISO9660::DirTree* node) { return node->getSize(); }
uint32_t dirTreeGetLBA(PCSX::ISO9660::DirTree* node) { return node->getLBA(); }
bool dirTreeIsDir(PCSX::ISO9660::DirTree* node) { return node->isDir(); }
bool dirTreeIsHidden(PCSX::ISO9660::DirTree* node) { return node->isHidden(); }
void dirTreeSetHidden(PCSX::ISO9660::DirTree* node, bool val) { node->setHidden(val); }
bool dirTreeHasXA(PCSX::ISO9660::DirTree* node) { return node->hasXA(); }
void dirTreeSetHasXA(PCSX::ISO9660::DirTree* node, bool val) { node->setHasXA(val); }
void dirTreeSetSectorMode(PCSX::ISO9660::DirTree* node, PCSX::IEC60908b::SectorMode mode) {
    node->setSectorMode(mode);
}
uint16_t dirTreeGetXAAttribs(PCSX::ISO9660::DirTree* node) {
    return node->getXA().get<PCSX::ISO9660LowLevel::DirEntry_XA_Attribs>().value;
}
void dirTreeSetXAAttribs(PCSX::ISO9660::DirTree* node, uint16_t val) {
    node->getXA().get<PCSX::ISO9660LowLevel::DirEntry_XA_Attribs>().value = val;
}
uint8_t dirTreeGetXAFileNum(PCSX::ISO9660::DirTree* node) {
    return node->getXA().get<PCSX::ISO9660LowLevel::DirEntry_XA_FileNum>().value;
}
void dirTreeSetXAFileNum(PCSX::ISO9660::DirTree* node, uint8_t val) {
    node->getXA().get<PCSX::ISO9660LowLevel::DirEntry_XA_FileNum>().value = val;
}

// DirTree navigation
PCSX::ISO9660::DirTree* dirTreeParent(PCSX::ISO9660::DirTree* node) { return node->parent(); }
PCSX::ISO9660::DirTree* dirTreeFirstChild(PCSX::ISO9660::DirTree* node) { return node->firstChild(); }
PCSX::ISO9660::DirTree* dirTreeNextSibling(PCSX::ISO9660::DirTree* node) { return node->nextSibling(); }

// DirTree date access
void dirTreeSetDate(PCSX::ISO9660::DirTree* node, uint8_t year, uint8_t month, uint8_t day, uint8_t hour,
                    uint8_t minute, uint8_t second, uint8_t offset) {
    auto& date = node->getDate();
    date.get<PCSX::ISO9660LowLevel::ShortDate_Year>().value = year;
    date.get<PCSX::ISO9660LowLevel::ShortDate_Month>().value = month;
    date.get<PCSX::ISO9660LowLevel::ShortDate_Day>().value = day;
    date.get<PCSX::ISO9660LowLevel::ShortDate_Hour>().value = hour;
    date.get<PCSX::ISO9660LowLevel::ShortDate_Minute>().value = minute;
    date.get<PCSX::ISO9660LowLevel::ShortDate_Second>().value = second;
    date.get<PCSX::ISO9660LowLevel::ShortDate_Offset>().value = offset;
}
uint8_t dirTreeGetDateYear(PCSX::ISO9660::DirTree* node) {
    return node->getDate().get<PCSX::ISO9660LowLevel::ShortDate_Year>().value;
}
uint8_t dirTreeGetDateMonth(PCSX::ISO9660::DirTree* node) {
    return node->getDate().get<PCSX::ISO9660LowLevel::ShortDate_Month>().value;
}
uint8_t dirTreeGetDateDay(PCSX::ISO9660::DirTree* node) {
    return node->getDate().get<PCSX::ISO9660LowLevel::ShortDate_Day>().value;
}

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

    REGISTER(L, createIsoBuilder);
    REGISTER(L, deleteIsoBuilder);
    REGISTER(L, isoBuilderWriteLicense);
    REGISTER(L, isoBuilderWriteSector);
    REGISTER(L, isoBuilderClose);

    // High-level IsoBuilder
    REGISTER(L, createHLIsoBuilder);
    REGISTER(L, deleteHLIsoBuilder);
    REGISTER(L, hlIsoBuilderFailed);
    REGISTER(L, hlIsoBuilderWriteLicense);
    REGISTER(L, hlIsoBuilderClose);

    // PVD getters
    REGISTER(L, hlPvdGetSystemIdent);
    REGISTER(L, hlPvdGetVolumeIdent);
    REGISTER(L, hlPvdGetVolSetIdent);
    REGISTER(L, hlPvdGetPublisherIdent);
    REGISTER(L, hlPvdGetDataPreparerIdent);
    REGISTER(L, hlPvdGetApplicationIdent);
    REGISTER(L, hlPvdGetCopyrightFileIdent);
    REGISTER(L, hlPvdGetAbstractFileIdent);
    REGISTER(L, hlPvdGetBibliographicFileIdent);

    // PVD setters
    REGISTER(L, hlPvdSetSystemIdent);
    REGISTER(L, hlPvdSetVolumeIdent);
    REGISTER(L, hlPvdSetVolSetIdent);
    REGISTER(L, hlPvdSetPublisherIdent);
    REGISTER(L, hlPvdSetDataPreparerIdent);
    REGISTER(L, hlPvdSetApplicationIdent);
    REGISTER(L, hlPvdSetCopyrightFileIdent);
    REGISTER(L, hlPvdSetAbstractFileIdent);
    REGISTER(L, hlPvdSetBibliographicFileIdent);

    // DirTree
    REGISTER(L, hlCreateRoot);
    REGISTER(L, hlCreateDir);
    REGISTER(L, hlCreateFile);
    REGISTER(L, dirTreeGetName);
    REGISTER(L, dirTreeGetSize);
    REGISTER(L, dirTreeGetLBA);
    REGISTER(L, dirTreeIsDir);
    REGISTER(L, dirTreeIsHidden);
    REGISTER(L, dirTreeSetHidden);
    REGISTER(L, dirTreeHasXA);
    REGISTER(L, dirTreeSetHasXA);
    REGISTER(L, dirTreeSetSectorMode);
    REGISTER(L, dirTreeGetXAAttribs);
    REGISTER(L, dirTreeSetXAAttribs);
    REGISTER(L, dirTreeGetXAFileNum);
    REGISTER(L, dirTreeSetXAFileNum);
    REGISTER(L, dirTreeParent);
    REGISTER(L, dirTreeFirstChild);
    REGISTER(L, dirTreeNextSibling);
    REGISTER(L, dirTreeSetDate);
    REGISTER(L, dirTreeGetDateYear);
    REGISTER(L, dirTreeGetDateMonth);
    REGISTER(L, dirTreeGetDateDay);

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
