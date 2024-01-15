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
local C = ffi.load 'SUPPORT_FILE'

local sliceMeta = {
    __tostring = function(slice) return ffi.string(C.getSliceData(slice._wrapper), C.getSliceSize(slice._wrapper)) end,
    __len = function(slice) return tonumber(C.getSliceSize(slice._wrapper)) end,
    __index = function(slice, index)
        if type(index) == 'number' and index >= 0 and index < C.getSliceSize(slice._wrapper) then
            local data = C.getSliceData(slice._wrapper)
            local buffer = ffi.cast('const uint8_t*', data)
            return buffer[index]
        elseif index == 'data' then
            return C.getSliceData(slice._wrapper)
        elseif index == 'size' then
            return tonumber(C.getSliceSize(slice._wrapper))
        end
        error('Unknown index `' .. index .. '` for LuaSlice')
    end,
    __newindex = function(slice, index, value) end,
}

local function createSliceWrapper(wrapper)
    local slice = { _wrapper = ffi.gc(wrapper, C.destroySlice), _type = 'Slice' }
    return setmetatable(slice, sliceMeta)
end

local bufferMeta = {
    __tostring = function(buffer) return ffi.string(buffer.data, buffer.size) end,
    __len = function(buffer) return buffer.size end,
    __index = function(buffer, index)
        if type(index) == 'number' and index >= 0 and index < buffer.size then
            return buffer.data[index]
        elseif index == 'maxsize' then
            return function(buffer) return ffi.sizeof(buffer) - 4 end
        elseif index == 'resize' then
            return function(buffer, size)
                if size > buffer:maxsize() then error('buffer size too large') end
                buffer.size = size
            end
        elseif index == 'pbSlice' then
            return Support._internal.createPBSliceFromBuffer(buffer)
        end
        error('Unknown index `' .. index .. '` for LuaBuffer')
    end,
    __newindex = function(buffer, index, value)
        if type(index) == 'number' and index >= 0 and index < buffer.size then
            buffer.data[index] = value
        else
            error('Unknown or immutable index `' .. index .. '` for LuaBuffer')
        end
    end,
}

local function validateBuffer(buffer)
    if buffer:maxsize() < buffer.size then
        error('Invalid or corrupted LuaBuffer: claims size of ' .. buffer.size .. ' but actual size is ' ..
                  buffer:maxsize())
    end
    return buffer
end
local LuaBuffer = ffi.metatype('LuaBuffer', bufferMeta)

local function read(self, ptr, size)
    if type(ptr) == 'number' and size == nil then
        size = ptr
        local buf = Support.NewLuaBuffer(size)
        size = C.readFileBuffer(self._wrapper, buf)
        buf.size = size
        return validateBuffer(buf)
    elseif type(ptr) == 'cdata' and size == nil and ffi.typeof(ptr) == LuaBuffer then
        return C.readFileBuffer(self._wrapper, validateBuffer(ptr))
    elseif type(ptr) == 'userdata' and size == nil then
        return Support._internal.readFileUserData(self._wrapper, ptr)
    end
    return C.readFileRawPtr(self._wrapper, ptr, size)
end

local function readAt(self, ptr, size, pos)
    if type(ptr) == 'number' and type(size) == 'number' and pos == nil then
        pos = size
        size = ptr
        local buf = Support.NewLuaBuffer(size)
        size = C.readFileAtBuffer(self._wrapper, buf, pos)
        buf.size = size
        return validateBuffer(buf)
    elseif type(ptr) == 'cdata' and type(size) == 'number' and pos == nil and ffi.typeof(ptr) == LuaBuffer then
        return C.readFileAtBuffer(self._wrapper, validateBuffer(ptr), size)
    elseif type(ptr) == 'userdata' and type(size) == 'number' and pos == nil then
        return Support._internal.readFileAtUserData(self._wrapper, ptr, size)
    end
    return C.readFileAtRawPtr(self._wrapper, ptr, size, pos)
end

local function write(self, data, size)
    if type(data) == 'cdata' and size == nil and ffi.typeof(data) == LuaBuffer then
        return C.writeFileBuffer(self._wrapper, validateBuffer(data))
    elseif type(data) == 'userdata' and size == nil then
        return Support._internal.writeFileUserData(self._wrapper, data)
    elseif type(size) == 'number' then
        return C.writeFileRawPtr(self._wrapper, data, size)
    end
    if type(data) ~= 'string' then data = tostring(data) end
    return C.writeFileRawPtr(self._wrapper, data, string.len(data))
end

local function writeAt(self, data, size, pos)
    if type(data) == 'cdata' and type(size) == 'number' and pos == nil and ffi.typeof(data) == LuaBuffer then
        return C.writeFileAtBuffer(self._wrapper, validateBuffer(data), size)
    elseif type(data) == 'userdata' and type(size) == 'number' and pos == nil then
        return Support._internal.writeFileAtUserData(self._wrapper, data, size)
    elseif type(size) == 'number' and type(pos) == 'number' then
        return C.writeFileAtRawPtr(self._wrapper, data, size, pos)
    end
    if type(data) ~= 'string' then data = tostring(data) end
    return C.writeFileAtRawPtr(self._wrapper, data, string.len(data), size)
end

local function writeMoveSlice(self, slice) C.writeFileMoveSlice(self._wrapper, slice._wrapper) end

local function writeAtMoveSlice(self, slice, pos) C.writeFileAtMoveSlice(self._wrapper, slice._wrapper, pos) end

local function rSeek(self, pos, wheel)
    if wheel == nil then wheel = 'SEEK_SET' end
    return C.rSeek(self._wrapper, pos, wheel)
end

local function wSeek(self, pos, wheel)
    if wheel == nil then wheel = 'SEEK_SET' end
    return C.wSeek(self._wrapper, pos, wheel)
end

local function readNum(self, ctype, pos)
    local size = ffi.sizeof(ctype)
    local buf = ctype()
    if pos == nil then
        C.readFileRawPtr(self._wrapper, ffi.cast('void*', buf), size)
    else
        C.readFileAtRawPtr(self._wrapper, ffi.cast('void*', buf), size, pos)
    end
    if (ffi.abi('be')) and size ~= 1 then
        local n = ctype()
        local s = ffi.cast('uint8_t*', buf)
        local d = ffi.cast('uint8_t*', n)
        for i = 0, size - 1, 1 do d[i] = s[size - i - 1] end
        buf = n
    end
    return buf[0]
end

local function writeNum(self, num, ctype, pos)
    local size = ffi.sizeof(ctype)
    local buf = ctype()
    buf[0] = num
    if (ffi.abi('be')) and size ~= 1 then
        local n = ctype()
        local s = ffi.cast('uint8_t*', buf)
        local d = ffi.cast('uint8_t*', n)
        for i = 0, size - 1, 1 do d[i] = s[size - i - 1] end
        buf = n
    end
    if pos == nil then
        C.writeFileRawPtr(self._wrapper, ffi.cast('void*', buf), size)
    else
        C.writeFileAtRawPtr(self._wrapper, ffi.cast('void*', buf), size, pos)
    end
end

local function startCachingAndWait(self)
    local captures = {}
    captures.current = coroutine.running()
    if not captures.current then error(':startCachingAndWait() needs to be called from a coroutine') end
    captures.callback = function()
        PCSX.nextTick(function()
            captures.callback:free()
            coroutine.resume(captures.current)
        end)
    end
    captures.callback = ffi.cast('void (*)()', captures.callback)
    if C.startFileCachingWithCallback(self._wrapper, captures.callback) then
        coroutine.yield()
    else
        captures.callback:free()
    end
end

local uint8_t = ffi.typeof('uint8_t[1]');
local uint16_t = ffi.typeof('uint16_t[1]');
local uint32_t = ffi.typeof('uint32_t[1]');
local uint64_t = ffi.typeof('uint64_t[1]');
local int8_t = ffi.typeof('int8_t[1]');
local int16_t = ffi.typeof('int16_t[1]');
local int32_t = ffi.typeof('int32_t[1]');
local int64_t = ffi.typeof('int64_t[1]');

local function createFileWrapper(wrapper)
    local file = {
        _wrapper = ffi.gc(wrapper, C.deleteFile),
        _type = 'File',
        close = function(self) C.closeFile(self._wrapper) end,
        read = read,
        readAt = readAt,
        write = write,
        writeAt = writeAt,
        writeMoveSlice = writeMoveSlice,
        writeAtMoveSlice = writeAtMoveSlice,
        rSeek = rSeek,
        rTell = function(self) return C.rTell(self._wrapper) end,
        wSeek = wSeek,
        wTell = function(self) return C.wTell(self._wrapper) end,
        size = function(self) return tonumber(C.getFileSize(self._wrapper)) end,
        seekable = function(self) return C.isFileSeekable(self._wrapper) end,
        writable = function(self) return C.isFileWritable(self._wrapper) end,
        eof = function(self) return C.isFileEOF(self._wrapper) end,
        failed = function(self) return C.isFileFailed(self._wrapper) end,
        cacheable = function(self) return C.isFileCacheable(self._wrapper) end,
        caching = function(self) return C.isFileCaching(self._wrapper) end,
        cacheProgress = function(self) return C.fileCacheProgress(self._wrapper) end,
        startCaching = function(self) return C.startFileCaching(self._wrapper) end,
        startCachingAndWait = startCachingAndWait,
        dup = function(self) return createFileWrapper(C.dupFile(self._wrapper)) end,
        subFile = function(self, start, size)
            return createFileWrapper(C.subFile(self._wrapper, start or 0, size or -1))
        end,
        readU8 = function(self) return readNum(self, uint8_t) end,
        readU16 = function(self) return readNum(self, uint16_t) end,
        readU32 = function(self) return readNum(self, uint32_t) end,
        readU64 = function(self) return readNum(self, uint64_t) end,
        readI8 = function(self) return readNum(self, int8_t) end,
        readI16 = function(self) return readNum(self, int16_t) end,
        readI32 = function(self) return readNum(self, int32_t) end,
        readI64 = function(self) return readNum(self, int64_t) end,
        readU8At = function(self, pos) return readNum(self, uint8_t, pos) end,
        readU16At = function(self, pos) return readNum(self, uint16_t, pos) end,
        readU32At = function(self, pos) return readNum(self, uint32_t, pos) end,
        readU64At = function(self, pos) return readNum(self, uint64_t, pos) end,
        readI8At = function(self, pos) return readNum(self, int8_t, pos) end,
        readI16At = function(self, pos) return readNum(self, int16_t, pos) end,
        readI32At = function(self, pos) return readNum(self, int32_t, pos) end,
        readI64At = function(self, pos) return readNum(self, int64_t, pos) end,
        writeU8 = function(self, num) writeNum(self, num, uint8_t) end,
        writeU16 = function(self, num) writeNum(self, num, uint16_t) end,
        writeU32 = function(self, num) writeNum(self, num, uint32_t) end,
        writeU64 = function(self, num) writeNum(self, num, uint64_t) end,
        writeI8 = function(self, num) writeNum(self, num, int8_t) end,
        writeI16 = function(self, num) writeNum(self, num, int16_t) end,
        writeI32 = function(self, num) writeNum(self, num, int32_t) end,
        writeI64 = function(self, num) writeNum(self, num, int64_t) end,
        writeU8At = function(self, num, pos) writeNum(self, num, uint8_t, pos) end,
        writeU16At = function(self, num, pos) writeNum(self, num, uint16_t, pos) end,
        writeU32At = function(self, num, pos) writeNum(self, num, uint32_t, pos) end,
        writeU64At = function(self, num, pos) writeNum(self, num, uint64_t, pos) end,
        writeI8At = function(self, num, pos) writeNum(self, num, int8_t, pos) end,
        writeI16At = function(self, num, pos) writeNum(self, num, int16_t, pos) end,
        writeI32At = function(self, num, pos) writeNum(self, num, int32_t, pos) end,
        writeI64At = function(self, num, pos) writeNum(self, num, int64_t, pos) end,
    }
    return file
end

local function open(filename, t)
    if (t == nil) then t = 'READ' end
    if (t == 'DOWNLOAD_URL_AND_WAIT') then
        local captures = {}
        captures.current = coroutine.running()
        if not captures.current then
            error(':open() with DOWNLOAD_URL_AND_WAIT needs to be called from a coroutine')
        end
        captures.callback = function()
            PCSX.nextTick(function()
                captures.callback:free()
                coroutine.resume(captures.current)
            end)
        end
        captures.callback = ffi.cast('void (*)()', captures.callback)
        local ret = createFileWrapper(C.openFileAndWait(filename, captures.callback))
        coroutine.yield()
        return ret
    else
        return createFileWrapper(C.openFile(filename, t))
    end
end

local function buffer(ptr, size, type)
    local f
    if ptr == nil and size == nil and type == nil then
        f = C.bufferFileEmpty()
    elseif type == nil or type == 'READWRITE' then
        f = C.bufferFile(ptr, size)
    elseif type == 'READ' then
        f = C.bufferFileReadOnly(ptr, size)
    elseif type == 'ACQUIRE' then
        f = C.bufferFileAcquire(ptr, size)
    end

    if f == nil then error('Invalid parameters to Support.File.buffer') end

    return createFileWrapper(f)
end

local function zReader(file, size, raw)
    if type(size) == 'string' then
        raw = size
        size = nil
    end
    raw = raw == 'RAW'
    if size == nil then size = -1 end
    return createFileWrapper(C.zReader(file._wrapper, size, raw))
end

local function uvFifo(address, port)
    if type(address) ~= 'string' then error('address must be a string') end
    if type(port) ~= 'number' then error('port must be a number') end
    local ret = createFileWrapper(C.uvFifo(address, port))
    ret.isConnecting = function(file) return C.uvFifoIsConnecting(file._wrapper) end
    return ret
end

local function mem4g()
    local ret = createFileWrapper(C.mem4g())
    ret.lowestAddress = function(file) return C.mem4gLowestAddress(file._wrapper) end
    ret.highestAddress = function(file) return C.mem4gHighestAddress(file._wrapper) end
    ret.actualSize = function(file) return C.mem4gActualSize(file._wrapper) end
    return ret
end

local function ffmpegAudioFile(file, options)
    if type(options) ~= 'table' then options = {} end
    local channels, endianness, sampleFormat, frequency = options.channels, options.endianness, options.sampleFormat,
                                                          options.frequency
    return createFileWrapper(C.ffmpegAudioFile(file._wrapper, channels or 'Stereo', endianness or 'Little',
                                               sampleFormat or 'S16', frequency or 44100))
end

if (type(Support) ~= 'table') then Support = {} end

Support.NewLuaBuffer = function(size)
    local buf = LuaBuffer(size)
    buf.size = size
    return buf
end

Support.isLuaBuffer = function(obj) return ffi.istype('LuaBuffer', obj) end

Support.File = {
    open = open,
    buffer = buffer,
    zReader = zReader,
    uvFifo = uvFifo,
    mem4g = mem4g,
    failedFile = function() return createFileWrapper(C.failedFile()) end,
    ffmpegAudioFile = ffmpegAudioFile,
    _createFileWrapper = createFileWrapper,
    _createSliceWrapper = createSliceWrapper,
}

-- )EOF"
