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

void deleteFile(LuaFile* wrapper);

LuaFile* openFile(const char* filename, enum FileOps t);
void closeFile(LuaFile* wrapper);

uint32_t readFileRawPtr(LuaFile* wrapper, void* dst, uint32_t size);
uint32_t readFileBuffer(LuaFile* wrapper, LuaBuffer* buffer);

uint32_t writeFileRawPtr(LuaFile* wrapper, const const uint8_t* data, uint32_t size);
uint32_t writeFileBuffer(LuaFile* wrapper, const LuaBuffer* buffer);

]]

local C = ffi.load 'SUPPORT_FILE'
local LuaBuffer = ffi.typeof('LuaBuffer')

if (type(Support) ~= 'table') then Support = {} end

local function fileGarbageCollect(file)
    C.deleteFile(file._wrapper)
end

local fileMeta = { __gc = fileGarbageCollect }

local function Read(self, ptr, size)
    if type(ptr) == 'number' and size == nil then
        size = ptr
        local buf = LuaBuffer(size)
        buf.size = size
        size = C.readFileBuffer(self._wrapper, buf)
        return ffi.string(buf.data, size)
    elseif type(ptr) == 'cdata' and size == nil and ffi.typeof(ptr) == LuaBuffer then
        return C.readFileBuffer(self._wrapper, ptr)
    else
        return C.readFileRawPtr(self._wrapper, ptr, size)
    end
end

local function Write(self, data, size)
    if type(data) == 'string' and size == nil then
        return C.writeRawPtr(self._wrapper, data, string.len(data))
    elseif type(data) == 'cdata' and size == nil and ffi.typeof(data) == LuaBuffer then
        return C.writeBuffer(self._wrapper, data)
    else
        return C.writeRawPtr(self._wrapper, data, size)
    end
end

local function FileWrapper(wrapper)
    local file = {
        _wrapper = wrapper,
        close = function(self) C.close(self._wrapper) end,
        read = Read,
        write = Write,
    }
    setmetatable(file, fileMeta)
    return file
end

local function Open(filename, t)
    if (t == nil) then t = 'READ' end
    return FileWrapper(C.openFile(filename, t))
end

Support.File = {
    Open = Open,
    _FileWrapper = FileWrapper,
}

-- )EOF"
