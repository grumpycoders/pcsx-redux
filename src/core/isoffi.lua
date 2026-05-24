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

// High-level filesystem-aware ISO builder
typedef struct { char opaque[?]; } HLIsoBuilder;
typedef struct { char opaque[?]; } IsoDirTree;

HLIsoBuilder* createHLIsoBuilder(LuaFile* out);
void deleteHLIsoBuilder(HLIsoBuilder* builder);
bool hlIsoBuilderFailed(HLIsoBuilder* builder);
void hlIsoBuilderWriteLicense(HLIsoBuilder* builder, LuaFile* license);
void hlIsoBuilderClose(HLIsoBuilder* builder, uint32_t threadCount);

// PVD field getters (copy trimmed string to caller buffer)
void hlPvdGetSystemIdent(HLIsoBuilder* b, char* buf, uint32_t bufSize);
void hlPvdGetVolumeIdent(HLIsoBuilder* b, char* buf, uint32_t bufSize);
void hlPvdGetVolSetIdent(HLIsoBuilder* b, char* buf, uint32_t bufSize);
void hlPvdGetPublisherIdent(HLIsoBuilder* b, char* buf, uint32_t bufSize);
void hlPvdGetDataPreparerIdent(HLIsoBuilder* b, char* buf, uint32_t bufSize);
void hlPvdGetApplicationIdent(HLIsoBuilder* b, char* buf, uint32_t bufSize);
void hlPvdGetCopyrightFileIdent(HLIsoBuilder* b, char* buf, uint32_t bufSize);
void hlPvdGetAbstractFileIdent(HLIsoBuilder* b, char* buf, uint32_t bufSize);
void hlPvdGetBibliographicFileIdent(HLIsoBuilder* b, char* buf, uint32_t bufSize);

// PVD field setters (pad with spaces)
void hlPvdSetSystemIdent(HLIsoBuilder* b, const char* val);
void hlPvdSetVolumeIdent(HLIsoBuilder* b, const char* val);
void hlPvdSetVolSetIdent(HLIsoBuilder* b, const char* val);
void hlPvdSetPublisherIdent(HLIsoBuilder* b, const char* val);
void hlPvdSetDataPreparerIdent(HLIsoBuilder* b, const char* val);
void hlPvdSetApplicationIdent(HLIsoBuilder* b, const char* val);
void hlPvdSetCopyrightFileIdent(HLIsoBuilder* b, const char* val);
void hlPvdSetAbstractFileIdent(HLIsoBuilder* b, const char* val);
void hlPvdSetBibliographicFileIdent(HLIsoBuilder* b, const char* val);

// DirTree creation
IsoDirTree* hlCreateRoot(HLIsoBuilder* b, uint32_t sectorCount);
IsoDirTree* hlCreateDir(HLIsoBuilder* b, IsoDirTree* parent, const char* name, uint32_t sectorCount);
IsoDirTree* hlCreateFile(HLIsoBuilder* b, IsoDirTree* parent, const char* name, LuaFile* content);

// DirTree property access
const char* dirTreeGetName(IsoDirTree* node);
uint32_t dirTreeGetSize(IsoDirTree* node);
uint32_t dirTreeGetLBA(IsoDirTree* node);
bool dirTreeIsDir(IsoDirTree* node);
bool dirTreeIsHidden(IsoDirTree* node);
void dirTreeSetHidden(IsoDirTree* node, bool val);
bool dirTreeHasXA(IsoDirTree* node);
void dirTreeSetHasXA(IsoDirTree* node, bool val);
void dirTreeSetSectorMode(IsoDirTree* node, enum SectorMode mode);
uint16_t dirTreeGetXAAttribs(IsoDirTree* node);
void dirTreeSetXAAttribs(IsoDirTree* node, uint16_t val);
uint8_t dirTreeGetXAFileNum(IsoDirTree* node);
void dirTreeSetXAFileNum(IsoDirTree* node, uint8_t val);

// DirTree navigation
IsoDirTree* dirTreeParent(IsoDirTree* node);
IsoDirTree* dirTreeFirstChild(IsoDirTree* node);
IsoDirTree* dirTreeNextSibling(IsoDirTree* node);

// DirTree date access
void dirTreeSetDate(IsoDirTree* node, uint8_t year, uint8_t month, uint8_t day,
                    uint8_t hour, uint8_t minute, uint8_t second, uint8_t offset);
uint8_t dirTreeGetDateYear(IsoDirTree* node);
uint8_t dirTreeGetDateMonth(IsoDirTree* node);
uint8_t dirTreeGetDateDay(IsoDirTree* node);

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

-- High-level ISO builder (filesystem-aware)
local pvdBuf = ffi.new('char[?]', 513)  -- max CString size (512 for ApplicationUse) + 1

local function createDirTreeWrapper(node)
    if node == nil then return nil end
    local wrapper = {
        _node = node,
        getName = function(self) return ffi.string(C.dirTreeGetName(self._node)) end,
        getSize = function(self) return C.dirTreeGetSize(self._node) end,
        getLBA = function(self) return C.dirTreeGetLBA(self._node) end,
        isDir = function(self) return C.dirTreeIsDir(self._node) end,
        isHidden = function(self) return C.dirTreeIsHidden(self._node) end,
        setHidden = function(self, val) C.dirTreeSetHidden(self._node, val) end,
        hasXA = function(self) return C.dirTreeHasXA(self._node) end,
        setXA = function(self, val) C.dirTreeSetHasXA(self._node, val) end,
        setSectorMode = function(self, mode) C.dirTreeSetSectorMode(self._node, mode) end,
        getXAAttribs = function(self) return C.dirTreeGetXAAttribs(self._node) end,
        setXAAttribs = function(self, val) C.dirTreeSetXAAttribs(self._node, val) end,
        getXAFileNum = function(self) return C.dirTreeGetXAFileNum(self._node) end,
        setXAFileNum = function(self, val) C.dirTreeSetXAFileNum(self._node, val) end,
        parent = function(self) return createDirTreeWrapper(C.dirTreeParent(self._node)) end,
        firstChild = function(self) return createDirTreeWrapper(C.dirTreeFirstChild(self._node)) end,
        nextSibling = function(self) return createDirTreeWrapper(C.dirTreeNextSibling(self._node)) end,
        setDate = function(self, year, month, day, hour, minute, second, offset)
            C.dirTreeSetDate(self._node, year or 0, month or 0, day or 0,
                           hour or 0, minute or 0, second or 0, offset or 0)
        end,
    }
    return wrapper
end

local function createHLIsoBuilderWrapper(wrapper)
    local function pvdGetter(getter)
        return function(self)
            getter(self._wrapper, pvdBuf, 513)
            return ffi.string(pvdBuf)
        end
    end
    local builder = {
        _wrapper = ffi.gc(wrapper, C.deleteHLIsoBuilder),
        failed = function(self) return C.hlIsoBuilderFailed(self._wrapper) end,
        writeLicense = function(self, file)
            if file then
                C.hlIsoBuilderWriteLicense(self._wrapper, file._wrapper)
            else
                C.hlIsoBuilderWriteLicense(self._wrapper, nil)
            end
        end,
        -- PVD getters
        getSystemIdent = pvdGetter(C.hlPvdGetSystemIdent),
        getVolumeIdent = pvdGetter(C.hlPvdGetVolumeIdent),
        getVolSetIdent = pvdGetter(C.hlPvdGetVolSetIdent),
        getPublisherIdent = pvdGetter(C.hlPvdGetPublisherIdent),
        getDataPreparerIdent = pvdGetter(C.hlPvdGetDataPreparerIdent),
        getApplicationIdent = pvdGetter(C.hlPvdGetApplicationIdent),
        getCopyrightFileIdent = pvdGetter(C.hlPvdGetCopyrightFileIdent),
        getAbstractFileIdent = pvdGetter(C.hlPvdGetAbstractFileIdent),
        getBibliographicFileIdent = pvdGetter(C.hlPvdGetBibliographicFileIdent),
        -- PVD setters
        setSystemIdent = function(self, val) C.hlPvdSetSystemIdent(self._wrapper, val) end,
        setVolumeIdent = function(self, val) C.hlPvdSetVolumeIdent(self._wrapper, val) end,
        setVolSetIdent = function(self, val) C.hlPvdSetVolSetIdent(self._wrapper, val) end,
        setPublisherIdent = function(self, val) C.hlPvdSetPublisherIdent(self._wrapper, val) end,
        setDataPreparerIdent = function(self, val) C.hlPvdSetDataPreparerIdent(self._wrapper, val) end,
        setApplicationIdent = function(self, val) C.hlPvdSetApplicationIdent(self._wrapper, val) end,
        setCopyrightFileIdent = function(self, val) C.hlPvdSetCopyrightFileIdent(self._wrapper, val) end,
        setAbstractFileIdent = function(self, val) C.hlPvdSetAbstractFileIdent(self._wrapper, val) end,
        setBibliographicFileIdent = function(self, val) C.hlPvdSetBibliographicFileIdent(self._wrapper, val) end,
        -- Tree building
        createRoot = function(self, sectorCount)
            return createDirTreeWrapper(C.hlCreateRoot(self._wrapper, sectorCount or 1))
        end,
        createDir = function(self, parent, name, sectorCount)
            return createDirTreeWrapper(C.hlCreateDir(self._wrapper, parent._node, name, sectorCount or 1))
        end,
        createFile = function(self, parent, name, fileHandle)
            return createDirTreeWrapper(C.hlCreateFile(self._wrapper, parent._node, name, fileHandle._wrapper))
        end,
        close = function(self, threadCount)
            C.hlIsoBuilderClose(self._wrapper, threadCount or 0)
        end,
    }
    return builder
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
PCSX.createIsoBuilder = function(file) return createHLIsoBuilderWrapper(C.createHLIsoBuilder(file._wrapper)) end
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
