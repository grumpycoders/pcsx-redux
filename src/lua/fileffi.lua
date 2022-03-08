--lualoader, R"EOF(--

ffi.cdef [[

typedef struct { char opaque[?]; };

enum FileOps {
    READ,
    TRUNCATE,
    CREATE,
    READWRITE,
};

]]

local C = ffi.load 'SUPPORTFILE'

if (type(Support) ~= "table") then Support = {} end

Support.File = {
}

-- )EOF"
