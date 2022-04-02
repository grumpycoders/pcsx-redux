-- lualoader, R"EOF(--
--   Copyright (C) 2022 PCSX-Redux authors
--
--   This program is free software; you can redistribute it and/or modify
--   it under the terms of the GNU General Public License as published by
--   the Free Software Foundation; either version 2 of the License, or
--   (at your option) any later version.
--
--   This program is distributed in the hope that it will be useful,
--   but WITHOUT ANY WARRANTY; without even the implied warranty of
--   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--   GNU General Public License for more details.
--
--   You should have received a copy of the GNU General Public License
--   along with this program; if not, write to the
--   Free Software Foundation, Inc.,
--   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

ffi.cdef [[

enum SectorMode {
    GUESS,     // will try and guess the sector mode based on flags found in the first sector
    RAW,       // 2352 bytes per sector
    M1,        // 2048 bytes per sector
    M2_RAW,    // 2336 bytes per sector, includes subheader; can't be guessed
    M2_FORM1,  // 2048 bytes per sector
    M2_FORM2,  // 2324 bytes per sector
};

typedef struct { char opaque[?]; } LuaIso;
typedef struct { char opaque[?]; } IsoReader;

void deleteIso(LuaIso* wrapper);

bool isIsoFailed(LuaIso* wrapper);

LuaIso* getCurrentIso();

IsoReader* createIsoReader(LuaIso* wrapper);
void deleteIsoReader(IsoReader* isoReader);
bool isReaderFailed(IsoReader* reader);
LuaFile* readerOpen(IsoReader* reader, const char* path);
LuaFile* fileisoOpen(LuaIso* wrapper, uint32_t lba, uint32_t size, enum SectorMode mode);

]]

local C = ffi.load 'CORE_ISO'

local function readerGarbageCollect(reader) C.deleteIsoReader(reader._wrapper) end
local readerMeta = { __gc = readerGarbageCollect }

local function isoGarbageCollect(iso) C.deleteIso(iso._wrapper) end
local isoMeta = { __gc = isoGarbageCollect }

local function createIsoReaderWrapper(isoReader)
    local reader = {
        _wrapper = isoReader,
        open = function(self, fname)
            return Support.File._createFileWrapper(C.readerOpen(self._wrapper, fname))
        end,
    }
    setmetatable(reader, readerMeta)
    return reader
end

local function createFileWrapper(wrapper)
    local iso = {
        _wrapper = wrapper,
        failed = function(self) return C.isIsoFailed(self._wrapper) end,
        createReader = function(self) return createIsoReaderWrapper(C.createIsoReader(self._wrapper)) end,
        open = function(self, lba, size, mode)
            if size == nil then size = -1 end
            if mode == nil then mode = 'GUESS' end
            return Support.File._createFileWrapper(C.fileisoOpen(self._wrapper, lba, size, mode))
        end,
    }
    setmetatable(iso, isoMeta)
    return iso
end

PCSX.getCurrentIso = function() return createFileWrapper(C.getCurrentIso()) end

-- )EOF"
