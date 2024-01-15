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
    M2_RAW,    // 2336 bytes per sector, includes subheader; cannot be guessed
    M2_FORM1,  // 2048 bytes per sector
    M2_FORM2,  // 2324 bytes per sector
};

typedef struct { char opaque[?]; } LuaIso;
typedef struct { char opaque[?]; } IsoReader;

void deleteIso(LuaIso* wrapper);
bool isIsoFailed(LuaIso* wrapper);
void isoClearPPF(LuaIso* wrapper);
void isoSavePPF(LuaIso* wrapper);
LuaIso* getCurrentIso();
LuaIso* openIso(const char* path);
LuaIso* openIsoFromFile(LuaFile* wrapper);

IsoReader* createIsoReader(LuaIso* wrapper);
void deleteIsoReader(IsoReader* isoReader);
bool isReaderFailed(IsoReader* reader);
LuaFile* readerOpen(IsoReader* reader, const char* path);
LuaFile* fileisoOpen(LuaIso* wrapper, uint32_t lba, uint32_t size, enum SectorMode mode);

typedef struct { char opaque[?]; } ISO9660Builder;
ISO9660Builder* createIsoBuilder(LuaFile* out);
void deleteIsoBuilder(ISO9660Builder* builder);
void isoBuilderWriteLicense(ISO9660Builder* builder, LuaFile*);
void isoBuilderWriteSector(ISO9660Builder* builder, const uint8_t* sectorData, enum SectorMode mode);
void isoBuilderClose(ISO9660Builder* builder);

]]

local C = ffi.load 'CORE_ISO'

local function createIsoReaderWrapper(isoReader)
    local reader = {
        _wrapper = ffi.gc(isoReader, C.deleteIsoReader),
        open = function(self, fname) return Support.File._createFileWrapper(C.readerOpen(self._wrapper, fname)) end,
    }
    return reader
end

local function createIsoWrapper(wrapper)
    local iso = {
        _wrapper = ffi.gc(wrapper, C.deleteIso),
        failed = function(self) return C.isIsoFailed(self._wrapper) end,
        createReader = function(self) return createIsoReaderWrapper(C.createIsoReader(self._wrapper)) end,
        clearPPF = function(self) C.isoClearPPF(self._wrapper) end,
        savePPF = function(self) C.isoSavePPF(self._wrapper) end,
        open = function(self, lba, size, mode)
            if type(size) == 'string' and mode == nil then
                mode = size
                size = -1
            end
            if size == nil then size = -1 end
            if mode == nil then mode = 'GUESS' end
            return Support.File._createFileWrapper(C.fileisoOpen(self._wrapper, lba, size, mode))
        end,
    }
    return iso
end

local function createIsoBuilderWrapper(wrapper)
    local iso = {
        _wrapper = ffi.gc(wrapper, function(self)
            C.isoBuilderClose(self)
            C.deleteIsoBuilder(self)
        end),
        writeLicense = function(self, file)
            if not file then file = Support.File.failedFile() end
            C.isoBuilderWriteLicense(self._wrapper, file._wrapper)
        end,
        writeSector = function(self, sectorData, mode)
            if not mode then mode = 'M2_FORM1' end
            if Support.isLuaBuffer(sectorData) then sectorData = sectorData.data end
            C.isoBuilderWriteSector(self._wrapper, sectorData, mode)
        end,
        close = function(self) C.isoBuilderClose(self._wrapper) end,
    }
    return iso
end

PCSX.getCurrentIso = function() return createIsoWrapper(C.getCurrentIso()) end
PCSX.openIso = function(arg)
    if type(arg) == 'string' then
        return createIsoWrapper(C.openIso(arg))
    else
        return createIsoWrapper(C.openIsoFromFile(arg._wrapper))
    end
end
PCSX.isoBuilder = function(file) return createIsoBuilderWrapper(C.createIsoBuilder(file._wrapper)) end
PCSX.isoTools = {
    fromBCD = function(bcd)
        local dec = 0
        local mul = 1
        while bcd ~= 0 do
            local digit = bcd % 16
            if digit >= 10 then error('Invalid BCD digit: ' .. digit) end
            dec = dec + mul * digit
            mul = mul * 10
            bcd = math.floor(bcd / 16)
        end
        return dec
    end,
    toBCD = function(dec)
        local bcd = 0
        local mul = 1
        while dec ~= 0 do
            local digit = dec % 10
            bcd = bcd + mul * digit
            mul = mul * 16
            dec = math.floor(dec / 10)
        end
        return bcd
    end,
    fromMSF = function(m, s, f)
        m = PCSX.isoTools.fromBCD(m)
        s = PCSX.isoTools.fromBCD(s)
        f = PCSX.isoTools.fromBCD(f)
        if s >= 60 then error('Invalid MSF seconds: ' .. s) end
        if f >= 75 then error('Invalid MSF frames: ' .. f) end
        return (m * 60 + s) * 75 + f - 150
    end,
    toMSF = function(lba)
        lba = lba + 150
        local f = lba % 75
        lba = lba - f
        lba = lba / 75
        local s = lba % 60
        lba = lba - s
        local m = lba / 60
        return m, s, f
    end,
}

-- )EOF"
