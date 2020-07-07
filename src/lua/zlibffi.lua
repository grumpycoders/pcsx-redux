--lualoader, R"EOF(--
--zlib binding, taken and modified from https://github.com/luapower/zlib
--Written by Cosmin Apreutesei. Public Domain.

ffi.cdef [[
enum {
/* flush values*/
     Z_NO_FLUSH           = 0,
     Z_PARTIAL_FLUSH      = 1,
     Z_SYNC_FLUSH         = 2,
     Z_FULL_FLUSH         = 3,
     Z_FINISH             = 4,
     Z_BLOCK              = 5,
     Z_TREES              = 6,
/* return codes */
     Z_OK                 = 0,
     Z_STREAM_END         = 1,
     Z_NEED_DICT          = 2,
     Z_ERRNO              = -1,
     Z_STREAM_ERROR       = -2,
     Z_DATA_ERROR         = -3,
     Z_MEM_ERROR          = -4,
     Z_BUF_ERROR          = -5,
     Z_VERSION_ERROR      = -6,
/* compression values */
     Z_NO_COMPRESSION      =  0,
     Z_BEST_SPEED          =  1,
     Z_BEST_COMPRESSION    =  9,
     Z_DEFAULT_COMPRESSION = -1,
/* compression levels */
     Z_FILTERED            =  1,
     Z_HUFFMAN_ONLY        =  2,
     Z_RLE                 =  3,
     Z_FIXED               =  4,
     Z_DEFAULT_STRATEGY    =  0,
/* compression strategies */
     Z_BINARY              =  0,
     Z_TEXT                =  1,
     Z_ASCII               =  Z_TEXT,   /* for compatibility with 1.2.2 and earlier */
     Z_UNKNOWN             =  2,
/* Possible values of the data_type field (though see inflate()) */
     Z_DEFLATED            =  8,
/* The deflate compression method (the only one supported in this version) */
     Z_NULL                =  0,  /* for initializing zalloc, zfree, opaque */
     Z_MAX_WBITS           =  15 /* 32K LZ77 window */
};

typedef struct {
    int unused;
} gzFile_s;
typedef gzFile_s* gzFile;

typedef void* (*z_alloc_func)(void* opaque, unsigned items, unsigned size);
typedef void (*z_free_func)(void* opaque, void* address);
typedef unsigned (*z_in_func)(void*, unsigned char**);
typedef int (*z_out_func)(void*, unsigned char*, unsigned);

typedef struct z_stream_s {
    const char* next_in;
    unsigned avail_in;
    unsigned long total_in;
    char* next_out;
    unsigned avail_out;
    unsigned long total_out;
    char* msg;
    void* state;
    z_alloc_func zalloc;
    z_free_func zfree;
    void* opaque;
    int data_type;
    unsigned long adler;
    unsigned long reserved;
} z_stream;

typedef struct gz_header_s {
    int text;
    unsigned long time;
    int xflags;
    int os;
    char* extra;
    unsigned extra_len;
    unsigned extra_max;
    char* name;
    unsigned name_max;
    char* comment;
    unsigned comm_max;
    int hcrc;
    int done;
} gz_header;

const char* zlibVersion();
unsigned long zlibCompileFlags();
const char* zError(int);

int inflate(z_stream*, int flush);
int inflateEnd(z_stream*);

int inflateSetDictionary(z_stream*, const char* dictionary, unsigned dictLength);
int inflateSync(z_stream*);
int inflateCopy(z_stream*, z_stream* source);
int inflateReset(z_stream*);
int inflateReset2(z_stream*, int windowBits);
int inflatePrime(z_stream*, int bits, int value);
long inflateMark(z_stream*);
int inflateGetHeader(z_stream*, gz_header* head);
int inflateBack(z_stream*, z_in_func in, void* in_desc, z_out_func out, void* out_desc);
int inflateBackEnd(z_stream*);
int inflateInit_(z_stream*, const char* version, int stream_size);
int inflateInit2_(z_stream*, int windowBits, const char* version, int stream_size);
int inflateBackInit_(z_stream*, int windowBits, unsigned char* window, const char* version, int stream_size);
int inflateSyncPoint(z_stream*);
int inflateUndermine(z_stream*, int);

int deflate(z_stream*, int flush);
int deflateEnd(z_stream*);

int deflateSetDictionary(z_stream*, const char* dictionary, unsigned dictLength);
int deflateCopy(z_stream*, z_stream* source);
int deflateReset(z_stream*);
int deflateParams(z_stream*, int level, int strategy);
int deflateTune(z_stream*, int good_length, int max_lazy, int nice_length, int max_chain);
unsigned long deflateBound(z_stream*, unsigned long sourceLen);
int deflatePrime(z_stream*, int bits, int value);
int deflateSetHeader(z_stream*, gz_header* head);
int deflateInit_(z_stream*, int level, const char* version, int stream_size);
int deflateInit2_(z_stream*, int level, int method, int windowBits, int memLevel, int strategy, const char* version,
                  int stream_size);

int compress(char* dest, unsigned long* destLen, const char* source, unsigned long sourceLen);
int compress2(char* dest, unsigned long* destLen, const char* source, unsigned long sourceLen, int level);
unsigned long compressBound(unsigned long sourceLen);
int uncompress(char* dest, unsigned long* destLen, const char* source, unsigned long sourceLen);

gzFile gzdopen(int fd, const char* mode);
int gzbuffer(gzFile, unsigned size);
int gzsetparams(gzFile, int level, int strategy);
int gzread(gzFile, void* buf, unsigned len);
int gzwrite(gzFile, void const* buf, unsigned len);
int gzprintf(gzFile, const char* format, ...);
int gzputs(gzFile, const char* s);
char* gzgets(gzFile, char* buf, int len);
int gzputc(gzFile, int c);
int gzgetc(gzFile);
int gzungetc(int c, gzFile);
int gzflush(gzFile, int flush);
int gzrewind(gzFile);
int gzeof(gzFile);
int gzdirect(gzFile);
int gzclose(gzFile);
int gzclose_r(gzFile);
int gzclose_w(gzFile);
const char* gzerror(gzFile, int* errnum);
void gzclearerr(gzFile);
gzFile gzopen(const char*, const char*);
long gzseek(gzFile, long, int);
long gztell(gzFile);
long gzoffset(gzFile);

unsigned long adler32(unsigned long adler, const char* buf, unsigned len);
unsigned long crc32(unsigned long crc, const char* buf, unsigned len);
unsigned long adler32_combine(unsigned long, unsigned long, long);
unsigned long crc32_combine(unsigned long, unsigned long, long);

const unsigned long* get_crc_table(void);
]]

local C = ffi.C

local function version()
    return ffi.string(C.zlibVersion())
end

local function checkz(ret)
    if ret == 0 then return end
    error(ffi.string(C.zError(ret)))
end

local function flate(api)
    return function(...)
        local ret = api(...)
        if ret == 0 then return true end
        if ret == C.Z_STREAM_END then return false end
        checkz(ret)
    end
end

local deflate = flate(C.deflate)
local inflate = flate(C.inflate)

--FUN TIME: windowBits is range 8..15 (default = 15) but can also be -8..15
--for raw deflate with no zlib header or trailer and can also be greater than
--15 which reads/writes a gzip header and trailer instead of a zlib wrapper.
--so I added a format parameter which can be 'deflate', 'zlib', 'gzip'
--(default = 'zlib') to cover all the cases so that windowBits can express
--only the window bits in the initial 8..15 range. additionally for inflate,
--windowBits can be 0 which means use the value in the zlib header of the
--compressed stream.

local function format_windowBits(format, windowBits)
    if format == 'gzip' then windowBits = windowBits + 16 end
    if format == 'deflate' then windowBits = -windowBits end
    return windowBits
end

local function init_deflate(format, level, method, windowBits, memLevel, strategy)
    level = level or C.Z_DEFAULT_COMPRESSION
    method = method or C.Z_DEFLATED
    windowBits = format_windowBits(format, windowBits or C.Z_MAX_WBITS)
    memLevel = memLevel or 8
    strategy = strategy or C.Z_DEFAULT_STRATEGY

    local strm = ffi.new'z_stream'
    checkz(C.deflateInit2_(strm, level, method, windowBits, memLevel, strategy, version(), ffi.sizeof(strm)))
    ffi.gc(strm, C.deflateEnd)
    return strm, deflate
end

local function init_inflate(format, windowBits)
    windowBits = format_windowBits(format, windowBits or C.Z_MAX_WBITS)

    local strm = ffi.new'z_stream'
    checkz(C.inflateInit2_(strm, windowBits, version(), ffi.sizeof(strm)))
    ffi.gc(strm, C.inflateEnd)
    return strm, inflate
end

local function inflate_deflate(init)
    return function(read, write, bufsize, ...)
        bufsize = bufsize or 16384

        local strm, flate = init(...)

        local buf = ffi.new('uint8_t[?]', bufsize)
        strm.next_out, strm.avail_out = buf, bufsize
        strm.next_in, strm.avail_in = nil, 0

        if type(read) == 'string' then
            local s = read
            local done
            read = function()
                if done then return end
                done = true
                return s
            end
        elseif type(read) == 'table' then
            local t = read
            local i = 0
            read = function()
                i = i + 1
                return t[i]
            end
        end

        local t
        local asstring = write == ''
        if type(write) == 'table' or asstring then
            t = asstring and {} or write
            write = function(data, sz)
                t[#t+1] = ffi.string(data, sz)
            end
        end

        local function flush()
            local sz = bufsize - strm.avail_out
            if sz == 0 then return end
            write(buf, sz)
            strm.next_out, strm.avail_out = buf, bufsize
        end

        local data, size --data must be anchored as an upvalue!
        while true do
            if strm.avail_in == 0 then --input buffer empty: refill
                data, size = read()
                if not data then --eof: finish up
                    local ret
                    repeat
                        flush()
                    until not flate(strm, C.Z_FINISH)
                    flush()
                    break
                end
                strm.next_in, strm.avail_in = data, size or #data
            end
            flush()
            if not flate(strm, C.Z_NO_FLUSH) then
                flush()
                break
            end
        end

        if asstring then
            return table.concat(t)
        else
            return t
        end
    end
end

--inflate(read, write[, bufsize][, format][, windowBits])
local inflate = inflate_deflate(init_inflate)
--deflate(read, write[, bufsize][, format][, level][, windowBits][, memLevel][, strategy])
local deflate = inflate_deflate(init_deflate)

--utility functions

local function compress_tobuffer(data, size, level, buf, sz)
    level = level or -1
    sz = ffi.new('unsigned long[1]', sz)
    checkz(C.compress2(buf, sz, data, size, level))
    return sz[0]
end

local function compress(data, size, level)
    size = size or #data
    local sz = C.compressBound(size)
    local buf = ffi.new('uint8_t[?]', sz)
    sz = compress_tobuffer(data, size, level, buf, sz)
    return ffi.string(buf, sz)
end

local function uncompress_tobuffer(data, size, buf, sz)
    sz = ffi.new('unsigned long[1]', sz)
    checkz(C.uncompress(buf, sz, data, size))
    return sz[0]
end

local function uncompress(data, size, sz)
    local buf = ffi.new('uint8_t[?]', sz)
    sz = uncompress_tobuffer(data, size or #data, buf, sz)
    return ffi.string(buf, sz)
end

--gzip file access functions

local function checkz(ret) assert(ret == 0) end
local function checkminus1(ret) assert(ret ~= -1); return ret end
local function ptr(o) return o ~= nil and o or nil end

local function gzclose(gzfile)
    checkz(C.gzclose(gzfile))
    ffi.gc(gzfile, nil)
end

local function gzopen(filename, mode, bufsize)
    local gzfile = ptr(C.gzopen(filename, mode or 'r'))
    if not gzfile then
        return nil, string.format('errno %d', ffi.errno())
    end
    ffi.gc(gzfile, gzclose)
    if bufsize then C.gzbuffer(gzfile, bufsize) end
    return gzfile
end

local flush_enum = {
    none    = C.Z_NO_FLUSH,
    partial = C.Z_PARTIAL_FLUSH,
    sync    = C.Z_SYNC_FLUSH,
    full    = C.Z_FULL_FLUSH,
    finish  = C.Z_FINISH,
    block   = C.Z_BLOCK,
    trees   = C.Z_TREES,
}

local function gzflush(gzfile, flush)
    checkz(C.gzflush(gzfile, flush_enum[flush]))
end

local function gzread_tobuffer(gzfile, buf, sz)
    return checkminus1(C.gzread(gzfile, buf, sz))
end

local function gzread(gzfile, sz)
    local buf = ffi.new('uint8_t[?]', sz)
    return ffi.string(buf, gzread_tobuffer(gzfile, buf, sz))
end

local function gzwrite(gzfile, data, sz)
    sz = C.gzwrite(gzfile, data, sz or #data)
    if sz == 0 then return nil,'error' end
    return sz
end

local function gzeof(gzfile)
    return C.gzeof(gzfile) == 1
end

local function gzseek(gzfile, ...)
    local narg = select('#',...)
    local whence, offset
    if narg == 0 then
        whence, offset = 'cur', 0
    elseif narg == 1 then
        if type(...) == 'string' then
            whence, offset = ..., 0
        else
            whence, offset = 'cur',...
        end
    else
        whence, offset = ...
    end
    whence = assert(whence == 'set' and 0 or whence == 'cur' and 1)
    return checkminus1(C.gzseek(gzfile, offset, whence))
end

local function gzoffset(gzfile)
    return checkminus1(C.gzoffset(gzfile))
end

ffi.metatype('gzFile_s', {__index = {
    close = gzclose,
    read = gzread,
    write = gzwrite,
    flush = gzflush,
    eof = gzeof,
    seek = gzseek,
    offset = gzoffset,
}})

--checksum functions

local function adler32(data, sz, adler)
    adler = adler or C.adler32(0, nil, 0)
    return tonumber(C.adler32(adler, data, sz or #data))
end

local function crc32(data, sz, crc)
    crc = crc or C.crc32(0, nil, 0)
    return tonumber(C.crc32(crc, data, sz or #data))
end

zlib = {
    version = version,
    inflate = inflate,
    deflate = deflate,
    uncompress_tobuffer = uncompress_tobuffer,
    uncompress = uncompress,
    compress_tobuffer = compress_tobuffer,
    compress = compress,
    open = gzopen,
    adler32 = adler32,
    crc32 = crc32,
}

-- )EOF"
