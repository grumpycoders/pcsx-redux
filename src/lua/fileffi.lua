--lualoader, R"EOF(--

ffi.cdef [[

typedef struct { char opaque[?]; } LuaFile;
typedef struct { uint32_t size; uint8_t data[?]; } LuaBuffer;

enum FileOps {
    READ,
    TRUNCATE,
    CREATE,
    READWRITE,
};

enum SeekWheel {
    SEEK_SET,
    SEEK_CUR,
    SEEK_END,
};

void deleteFile(LuaFile* wrapper);

LuaFile* openFile(const char* filename, enum FileOps t);
void closeFile(LuaFile* wrapper);

uint32_t readFileRawPtr(LuaFile* wrapper, void* dst, uint32_t size);
uint32_t readFileBuffer(LuaFile* wrapper, LuaBuffer* buffer);

uint32_t writeFileRawPtr(LuaFile* wrapper, const const uint8_t* data, uint32_t size);
uint32_t writeFileBuffer(LuaFile* wrapper, const LuaBuffer* buffer);

int32_t rSeek(LuaFile* wrapper, int32_t pos, enum SeekWheel wheel);
int32_t rTell(LuaFile* wrapper);
int32_t wSeek(LuaFile* wrapper, int32_t pos, enum SeekWheel wheel);
int32_t wTell(LuaFile* wrapper);

uint32_t getFileSize(LuaFile*);

uint32_t readFileAtRawPtr(LuaFile* wrapper, void* dst, uint32_t size, uint32_t pos);
uint32_t readFileAtBuffer(LuaFile* wrapper, LuaBuffer* buffer, uint32_t pos);

uint32_t writeFileAtRawPtr(LuaFile* wrapper, const const uint8_t* data, uint32_t size, uint32_t pos);
uint32_t writeFileAtBuffer(LuaFile* wrapper, const LuaBuffer* buffer, uint32_t pos);

bool isFileSeekable(LuaFile*);
bool isFileWritable(LuaFile*);
bool isFileEOF(LuaFile*);
bool isFileFailed(LuaFile*);

LuaFile* dupFile(LuaFile*);

]]

local C = ffi.load 'SUPPORT_FILE'

local function fileGarbageCollect(file)
    C.deleteFile(file._wrapper)
end

local fileMeta = { __gc = fileGarbageCollect }
local bufferMeta = {
    __tostring = function(buffer)
        return ffi.string(buffer.data, buffer.size)
    end,
    __index = function(buffer, index)
        if type(index) == 'number' and index >= 0 and index < buffer.size then
            return buffer.data[index]
        end
        error('Unknown index `' .. index .. '` for LuaBuffer')
    end,
    __newindex = function(buffer, index, value)
        if type(index) == 'number' and index >= 0 and index < buffer.size then
            buffer.data[index] = value
        end
        error('Unknown or immutable index `' .. index .. '` for LuaBuffer')
    end,
}
local function validateBuffer(buffer)
    local actualSize = ffi.sizeof(buffer) - 4
    if actualSize < buffer.size then error('Invalid or corrupted LuaBuffer: claims size of ' .. buffer.size .. ' but actual size is ' .. actualSize) end
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
    else
        return C.readFileRawPtr(self._wrapper, ptr, size)
    end
end

local function readAt(self, ptr, size, pos)
    if type(ptr) == 'number' and type(size) == 'number' and pos == nil then
        ptr = size
        size = ptr
        local buf = Support.NewLuaBuffer(size)
        size = C.readFileAtBuffer(self._wrapper, buf, pos)
        buf.size = size
        return validateBuffer(buf)
    elseif type(ptr) == 'cdata' and type(size) == 'number' and pos == nil and ffi.typeof(ptr) == LuaBuffer then
        return C.readFileAtBuffer(self._wrapper, validateBuffer(ptr), size)
    else
        return C.readFileAtRawPtr(self._wrapper, ptr, size, pos)
    end
end

local function write(self, data, size)
    if type(data) == 'string' and size == nil then
        return C.writeRawPtr(self._wrapper, data, string.len(data))
    elseif type(data) == 'cdata' and size == nil and ffi.typeof(data) == LuaBuffer then
        return C.writeBuffer(self._wrapper, validateBuffer(data))
    else
        return C.writeRawPtr(self._wrapper, data, size)
    end
end

local function writeAt(self, data, size, pos)
    if type(data) == 'string' and type(size) == 'number' and pos == nil then
        return C.writeAtRawPtr(self._wrapper, data, string.len(data), size)
    elseif type(data) == 'cdata' and type(size) == 'number' and pos == nil and ffi.typeof(data) == LuaBuffer then
        return C.writeAtBuffer(self._wrapper, validateBuffer(data), pos)
    else
        return C.writeAtRawPtr(self._wrapper, data, size, pos)
    end
end

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
        for i = 0, size - 1, 1 do
            d[i] = s[size - i - 1]
        end
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
        for i = 0, size - 1, 1 do
            d[i] = s[size - i - 1]
        end
        buf = n
    end
    if pos == nil then
        C.writeRawPtr(self._wrapper, ffi.cast('void*', buf), size)
    else
        C.writeAtRawPtr(self._wrapper, ffi.cast('void*', buf), size, pos)
    end
end

local uint8_t = ffi.typeof('uint8_t[1]');
local uint16_t = ffi.typeof('uint16_t[1]');
local uint32_t = ffi.typeof('uint32_t[1]');
local int8_t = ffi.typeof('int8_t[1]');
local int16_t = ffi.typeof('int16_t[1]');
local int32_t = ffi.typeof('int32_t[1]');

local function createFileWrapper(wrapper)
    local file = {
        _wrapper = wrapper,
        close = function(self) C.close(self._wrapper) end,
        read = read,
        readAt = readAt,
        write = write,
        writeAt = writeAt,
        rSeek = rSeek,
        rTell = function(self) return C.rTell(self._wrapper) end,
        wSeek = wSeek,
        wTell = function(self) return C.wTell(self._wrapper) end,
        size = function(self) return C.getFileSize(self._wrapper) end,
        seekable = function(self) return C.isFileSeekable(self._wrapper) end,
        writable = function(self) return C.isFileWritable(self._wrapper) end,
        eof = function(self) return C.isFileEOF(self._wrapper) end,
        failed = function(self) return C.isFileFailed(self._wrapper) end,
        dup = function(self) return createFileWrapper(C.dupFile(self._wrapper)) end,
        readU8 = function(self) return readNum(self, uint8_t) end,
        readU16 = function(self) return readNum(self, uint16_t) end,
        readU32 = function(self) return readNum(self, uint32_t) end,
        readI8 = function(self) return readNum(self, int8_t) end,
        readI16 = function(self) return readNum(self, int16_t) end,
        readI32 = function(self) return readNum(self, int32_t) end,
        readU8At = function(self, pos) return readNum(self, uint8_t, pos) end,
        readU16At = function(self, pos) return readNum(self, uint16_t, pos) end,
        readU32At = function(self, pos) return readNum(self, uint32_t, pos) end,
        readI8At = function(self, pos) return readNum(self, int8_t, pos) end,
        readI16At = function(self, pos) return readNum(self, int16_t, pos) end,
        readI32At = function(self, pos) return readNum(self, int32_t, pos) end,
        writeU8 = function(self, num) writeNum(self, num, uint8_t) end,
        writeU16 = function(self, num) writeNum(self, num, uint16_t) end,
        writeU32 = function(self, num) writeNum(self, num, uint32_t) end,
        writeI8 = function(self, num) writeNum(self, num, int8_t) end,
        writeI16 = function(self, num) writeNum(self, num, int16_t) end,
        writeI32 = function(self, num) writeNum(self, num, int32_t) end,
        writeU8At = function(self, num, pos) writeNum(self, num, uint8_t, pos) end,
        writeU16At = function(self, num, pos) writeNum(self, num, uint16_t, pos) end,
        writeU32At = function(self, num, pos) writeNum(self, num, uint32_t, pos) end,
        writeI8At = function(self, num, pos) writeNum(self, num, int8_t, pos) end,
        writeI16At = function(self, num, pos) writeNum(self, num, int16_t, pos) end,
        writeI32At = function(self, num, pos) writeNum(self, num, int32_t, pos) end,
    }
    setmetatable(file, fileMeta)
    return file
end

local function open(filename, t)
    if (t == nil) then t = 'READ' end
    return createFileWrapper(C.openFile(filename, t))
end

if (type(Support) ~= 'table') then Support = {} end

Support.NewLuaBuffer = function(size)
    local buf = LuaBuffer(size)
    buf.size = size
    return buf
end

Support.File = {
    open = open,
    _createFileWrapper = createFileWrapper,
}

-- )EOF"
