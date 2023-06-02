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
#include "cdrom/iec-60908b.h"
#include "cdrom/iso9660-builder.h"
#include "cdrom/iso9660-reader.h"
#include "core/cdrom.h"
#include "lua/luafile.h"
#include "lua/luawrapper.h"

namespace {

struct LuaIso {
    LuaIso(std::shared_ptr<PCSX::CDRIso> iso) : iso(iso) {}
    std::shared_ptr<PCSX::CDRIso> iso;
};

struct MSF {
    uint8_t m, s, f;
};

void deleteIso(LuaIso* wrapper) { delete wrapper; }
bool isIsoFailed(LuaIso* wrapper) { return wrapper->iso->failed(); }
void isoClearPPF(LuaIso* wrapper) { wrapper->iso->getPPF()->clear(); }
void isoSavePPF(LuaIso* wrapper) { wrapper->iso->getPPF()->save(wrapper->iso->getIsoPath()); }
LuaIso* getCurrentIso() { return new LuaIso(PCSX::g_emulator->m_cdrom->getIso()); }

PCSX::ISO9660Reader* createIsoReader(LuaIso* wrapper) { return new PCSX::ISO9660Reader(wrapper->iso); }
void deleteIsoReader(PCSX::ISO9660Reader* isoReader) { delete isoReader; }

bool isReaderFailed(PCSX::ISO9660Reader* reader) { return reader->failed(); }
PCSX::LuaFFI::LuaFile* readerOpen(PCSX::ISO9660Reader* reader, const char* path) {
    return new PCSX::LuaFFI::LuaFile(reader->open(path));
}
PCSX::LuaFFI::LuaFile* fileisoOpen(LuaIso* wrapper, uint32_t lba, uint32_t size, PCSX::SectorMode mode) {
    return new PCSX::LuaFFI::LuaFile(new PCSX::CDRIsoFile(wrapper->iso, lba, size, mode));
}
uint32_t getIsoTN(LuaIso* wrapper) { return wrapper->iso->getTN(); }
MSF getIsoTD(LuaIso* wrapper, uint32_t tn) {
    auto ret = wrapper->iso->getTD(tn);
    return {ret.m, ret.s, ret.f};
}

PCSX::ISO9660Builder* createIsoBuilder(PCSX::LuaFFI::LuaFile* wrapper) {
    return new PCSX::ISO9660Builder(wrapper->file);
}
void deleteIsoBuilder(PCSX::ISO9660Builder* builder) { delete builder; }
void isoBuilderWriteLicense(PCSX::ISO9660Builder* builder, PCSX::LuaFFI::LuaFile* licenseWrapper) {
    builder->writeLicense(licenseWrapper->file);
}
void isoBuilderWriteSector(PCSX::ISO9660Builder* builder, const uint8_t* sectorData, PCSX::SectorMode mode) {
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
    REGISTER(L, getIsoTD);
    REGISTER(L, getIsoTN);
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

    L.settable();
    L.pop();
}

void PCSX::LuaFFI::open_iso(Lua L) {
    static int lualoader = 1;
    static const char* isoFFI = (
#include "core/isoffi.lua"
    );
    registerAllSymbols(L);
    L.load(isoFFI, "internal:core/isoffi.lua");
}
