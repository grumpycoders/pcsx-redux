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

typedef struct { char opaque[?]; } LuaIso;
typedef struct { char opaque[?]; } IsoReader;

void deleteIso(LuaIso* wrapper);

bool isIsoFailed(LuaIso* wrapper);

LuaIso* getCurrentIso();

IsoReader* createIsoReader(LuaIso* wrapper);
void deleteIsoReader(IsoReader* isoReader);
bool isReaderFailed(IsoReader* reader);
LuaFile* readerOpen(IsoReader* reader, const char* path);

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
    }
    setmetatable(iso, isoMeta)
    return iso
end

PCSX.getCurrentIso = function() return createFileWrapper(C.getCurrentIso()) end

-- )EOF"
