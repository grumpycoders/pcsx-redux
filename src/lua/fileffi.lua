--lualoader, R"EOF(--

ffi.cdef [[

typedef struct { char opaque[?]; } LuaFile;
typedef struct { uint32_t size; uint8_t data[?]; } LuaBuffer;

enum FileOps {
    READ,
    TRUNCATE,
    CREATE,
    READWRITE,
    DOWNLOAD_URL,
};

enum SeekWheel {
    SEEK_SET,
    SEEK_CUR,
    SEEK_END,
};

void deleteFile(LuaFile* wrapper);

LuaFile* openFile(const char* filename, enum FileOps t);
LuaFile* openFileWithCallback(const char* url, void (*callback)());

LuaFile* bufferFileReadOnly(void* data, uint64_t size);
LuaFile* bufferFile(void* data, uint64_t size);
LuaFile* bufferFileAcquire(void* data, uint64_t size);
LuaFile* bufferFileEmpty();

LuaFile* subFile(LuaFile*, uint64_t start, int64_t size);

void closeFile(LuaFile* wrapper);

uint64_t readFileRawPtr(LuaFile* wrapper, void* dst, uint64_t size);
uint64_t readFileBuffer(LuaFile* wrapper, LuaBuffer* buffer);

uint64_t writeFileRawPtr(LuaFile* wrapper, const const uint8_t* data, uint64_t size);
uint64_t writeFileBuffer(LuaFile* wrapper, const LuaBuffer* buffer);

int64_t rSeek(LuaFile* wrapper, int64_t pos, enum SeekWheel wheel);
int64_t rTell(LuaFile* wrapper);
int64_t wSeek(LuaFile* wrapper, int64_t pos, enum SeekWheel wheel);
int64_t wTell(LuaFile* wrapper);

uint64_t getFileSize(LuaFile*);

uint64_t readFileAtRawPtr(LuaFile* wrapper, void* dst, uint64_t size, uint64_t pos);
uint64_t readFileAtBuffer(LuaFile* wrapper, LuaBuffer* buffer, uint64_t pos);

uint64_t writeFileAtRawPtr(LuaFile* wrapper, const const uint8_t* data, uint64_t size, uint64_t pos);
uint64_t writeFileAtBuffer(LuaFile* wrapper, const LuaBuffer* buffer, uint64_t pos);

bool isFileSeekable(LuaFile*);
bool isFileWritable(LuaFile*);
bool isFileEOF(LuaFile*);
bool isFileFailed(LuaFile*);
bool isFileCacheable(LuaFile*);
bool isFileCaching(LuaFile*);
float fileCacheProgress(LuaFile*);
void startFileCaching(LuaFile*);
bool startFileCachingWithCallback(LuaFile* wrapper, void (*callback)());

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
    __len = function(buffer)
        return buffer.size
    end,
    __index = function(buffer, index)
        if type(index) == 'number' and index >= 0 and index < buffer.size then
            return buffer.data[index]
        elseif index == 'maxsize' then
            return function(buffer) return ffi.sizeof(buffer) - 4 end
        elseif index == 'expand' then
            return function(buffer, size)
                if size > buffer.maxsize() then
                    error('buffer size too large')
                end
                buffer.size = size
            end
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
    if buffer:maxsize() < buffer.size then error('Invalid or corrupted LuaBuffer: claims size of ' .. buffer.size .. ' but actual size is ' .. buffer:maxsize()) end
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
    if type(data) == 'cdata' and size == nil and ffi.typeof(data) == LuaBuffer then
        return C.writeFileBuffer(self._wrapper, validateBuffer(data))
    elseif type(size) == 'number' then
        return C.writeFileRawPtr(self._wrapper, data, size)
    end
    if type(data) ~= 'string' then data = tostring(data) end
    return C.writeFileRawPtr(self._wrapper, data, string.len(data))
end

local function writeAt(self, data, size, pos)
    if type(data) == 'cdata' and type(size) == 'number' and pos == nil and ffi.typeof(data) == LuaBuffer then
        return C.writeFileAtBuffer(self._wrapper, validateBuffer(data), size)
    elseif type(size) == 'number' and type(pos) == 'number' then
        return C.writeFileAtRawPtr(self._wrapper, data, size, pos)
    end
    if type(data) ~= 'string' then data = tostring(data) end
    return C.writeFileAtRawPtr(self._wrapper, data, string.len(data), size)
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

local function startCachingAndWait(self)
    local captures = {}
    captures.current = coroutine.running()
    if not captures.current then error(':startCachingAndWait() needs to be called from a coroutine') end
    captures.callback = function()
        local oldCleanup = AfterPollingCleanup
        AfterPollingCleanup = function()
            if oldCleanup then oldCleanup() end
            captures.callback:free()
            coroutine.resume(captures.current)
        end
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
        _wrapper = wrapper,
        close = function(self) C.closeFile(self._wrapper) end,
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
        cacheable = function(self) return C.isFileCacheable(self._wrapper) end,
        caching = function(self) return C.isFileCaching(self._wrapper) end,
        cacheProgress = function(self) return C.fileCacheProgress(self._wrapper) end,
        startCaching = function(self) return C.startFileCaching(self._wrapper) end,
        startCachingAndWait = startCachingAndWait,
        dup = function(self) return createFileWrapper(C.dupFile(self._wrapper)) end,
        subFile = function(self, start, size) return createFileWrapper(C.subFile(self._wrapper, start or 0, size or -1)) end,
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
    setmetatable(file, fileMeta)
    return file
end

local function open(filename, t)
    if (t == nil) then t = 'READ' end
    if (t == 'DOWNLOAD_URL_AND_WAIT') then
        local captures = {}
        captures.current = coroutine.running()
        if not captures.current then error(':startCachingAndWait() needs to be called from a coroutine') end
        captures.callback = function()
            local oldCleanup = AfterPollingCleanup
            AfterPollingCleanup = function()
                if oldCleanup then oldCleanup() end
                captures.callback:free()
                coroutine.resume(captures.current)
            end
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

if (type(Support) ~= 'table') then Support = {} end

Support.NewLuaBuffer = function(size)
    local buf = LuaBuffer(size)
    buf.size = size
    return buf
end

Support.File = {
    open = open,
    buffer = buffer,
    _createFileWrapper = createFileWrapper,
}

-- )EOF"
