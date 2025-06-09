-- MIT License
--
-- Copyright (c) 2025 PCSX-Redux authors
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the 'Software'), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in all
-- copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE.
--[[

This script creates a PSX archive file from a JSON index file. The JSON file needs
to be formatted as follows:
{
    "files": [
        {
            "path": "path/to/file1"
        },
        {
            "path": "path/to/file2"
        }
    ]
}
The 'files' array can contain any number of file objects, each with a 'path'
property pointing to the file to be included in the archive. The script will
compress the files using the UCL-NRV2E algorithm and write the resulting archive
to a specified output file.

Using PCSX-Redux as a CLI tool, one can run the script as follows:

./PCSX-Redux -cli -dofile mkarchive.lua -exec "mkarchive('index.json', 'output.arc') PCSX.Quit()"

The archive format is designed to be really efficient for the PSX. Using the
format for other platforms is definitely possible, but the specification
will heavily limit the user's options. All numbers are stored in little-endian
format, as this is the native format for the PSX.

The design philosophy is to speed things up as much as possible. Saving space
is not a priority. As a result, most everything in the archive is padded to
2048 bytes, to ensure there is no overhead when reading the archive.

The archive is split into two big sections: the index, and the data.
The index is a header, and a list of files.

The archive header format is as follows:
- 8 bytes: "PSX-ARC1" (ASCII) - This is the magic number for the archive
- 4 bytes: number of files in the archive (32-bit unsigned integer)
- 4 bytes: total size of the archive (in sectors, 32-bit unsigned integer)

Then, there are the file entries, one for each file in the archive. Each entry is
formatted as follows:
- 8 bytes: hash of the file path - defaults to the DJB2 hash of the file path
- 8 bytes, packed in a bitfield, from the least significant bit:
    - 21 bits: decompressed size in bytes
    - 11 bits: padding size in bytes
    - 19 bits: sector offset to the start of the file data from the start of the archive
    - 10 bits: compressed size in sectors
    - 3 bits: compression method:
        - 0: no compression
        - 1: UCL-NRV2E compression
        - 2: LZ4 compression

Importantly, the entries are sorted by hash, not by file path. This is to ensure that
the index can be loaded straight in memory, and the files can be accessed randomly
using only a binary search. The hash is a 64-bit unsigned integer, and is calculated
using the DJB2 hash algorithm, but the actual algorithm is not important. The archive
manager will allow the user to specify a custom hash function, but the default is DJB2.
The index order isn't affecting the order of the files in the archive, as the files are stored
in the order they are added to the archive. It is in fact probably important that the user
stores the files in the order in which they are supposed to be accessed, to limit seeking
times into the archive.

This tool only supports the UCL-NRV2E compression, but the archive manager code in
psyqo-paths can handle both UCL-NRV2E and LZ4 compression.

Rationales, design decisions, and other notes
=============================================

Why not use a standard archive format?

The PSX is a very limited platform, and the archive format is designed to be as
fast as possible. The typical formats (ZIP, RAR, etc.) are not designed for the PSX, and
would be very slow to read or have a lot of memory overhead.


Why padding to 2048 bytes?

The PSX uses 2048 byte sectors, and the CD ROM drive is designed to read data in
2048 byte chunks. This means that if we want to read data from the archive, we need
to read it in 2048 byte chunks. If we don't pad the data to 2048 bytes, we would
need an additional buffer to read a whole sector, and then copy the relevant data
to the correct location in memory. This would add a lot of overhead, and would
slow down the archive manager. By padding the data to 2048 bytes, we can just read
the data straight into the correct location in memory. Additionally, space isn't a
concern, as the PSX has a lot of space on the CD ROM. The archive format is designed
to be as fast as possible, and the extra space used for padding is negligible
compared to the size of the files in the archive. In fact, the compression used here
isn't meant to save space, but to speed up the reading of the files. The maximum
reading speed of the PSX is 300kB/s, so for instance, reading a 1MB file would take
about 3.5 seconds. If we can compress the file to 512kB, then we can read it in
1.7 seconds instead. This is a significant speedup, which has a big impact on the
usability of the software.


Why 64-bit hashes?

The birthday problem (https://en.wikipedia.org/wiki/Birthday_problem) says that the
probability of a collision is very high for 32-bit hashes. Only a few thousand files
are already almost guaranteed to generate a collision. Using only 32 bits would mean
that we'd need a way to handle collisions, which would add a lot of complexity to the
archive format. Using 64 bits means that the probability of a collision is very low,
and we can just ignore it. The DJB2 hash algorithm is very fast, and it can function
at compile time, meaning that the compiled code can simply contain the hash of the
file paths. Additionally, this field can be completely bypassed by the user, if the
index is stored using sequential numbers. For instance, the access code can just
use numbers from 0 to n-1 to identify their files, and then get the proper index
pointer using a simple array access. In this case, the hash is not needed at all,
and the hash field can be repurposed for something else.


Why padding the compressed files BEFORE their data instead of after?

The two compression algorithms used in this archive format (UCL-NRV2E and LZ4) are
able to handle in-place decompression. This means that the decompressor can read the compressed
data and write the decompressed data to the same location. This is very useful when memory
is limited, as it means that we don't need to allocate a separate buffer for the decompressed
data. The downside is that the compressed data needs to be placed at the end of the
single buffer used for both the compressed and decompressed data. If the compressed
data was placed at the beginning of the sector, then the archive manager would need to
move the data after reading it from disc to the correct location in memory. Doing the
padding before means the archive manager can just read the data from disc straight
into the correct location in memory. Note this is only relevant for compressed files.
Files stored uncompressed are naturally padded after their data.


Why a 64 bits bitfield?

First, the attentive reader will notice that the first two fields in the bitfield
are 21 and 11 bits long, meaning they form a single 32-bit integer, so the bitfield
can also be seen as two 32-bit integers. Then, for each field:
    - 21 bits for the decompressed data size is enough to store the size of a 2MB
        file, which is the size of the RAM of the PSX. Additionally, this field is
        technically optional, if the file isn't compressed. In this case, the
        archive manager will just use the size of the file in sectors.
    - 11 bits for the padding size is enough to store the padding size up to 2048
        bytes, which is the size of a sector. No need for more.
    - 19 bits for the offset in sectors means we can store up to 524288 sectors,
        which is 1GB. This is more than enough for the PSX, where CD ROMs are
        limited to 650MB. Additionally, this field may be used by the user
        to simply locate where a file is in the archive, bypassing the rest of
        the archive manager. This can be useful for STR or XA files, which are
        streamed from the disc.
    - 10 bits for the compressed size in sectors means we can store up to 1024
        sectors, which is 2MB. Again, this is the size of the RAM of the PSX.
    - 3 bits for the compression method means we can store up to 8 different
        compression methods. We are currently only defining the values 0, 1, and 2,
        but we are leaving the rest for future use. This also completes the 64-bit
        bitfield, meaning we can store the whole thing in a single 64-bit integer.


Why two compressing methods?

First, the LZ4 and UCL-NRV2E methods are extremely similar in terms of speed,
compression levels, and features. The UCL-NRV2E method is a bit slower, but it has a better
compression ratio. The LZ4 method is a bit faster, but it has a worse compression ratio.
The difference however boils down to licensing. While both decompressors have been
written from scratch and are free to use with an MIT license, the UCL-NRV2E
compressor is licensed under the GPLv2 license. This means that users who are writing
a closed source application cannot use the compressor, as it would force them to
release their source code. The LZ4 compressor is licensed under the BSD license.
Ideally, one archive should only contain files compressed with a single method, in order
to avoid the binary overhead of having both decompression code in the executable. The
choice between the two methods is left to the user, according to their needs.


Anything else?

The format of the index means that the files stored in the archive do not need
to be contiguous. This allows the user to generate an archive with "hidden" files,
which are not stored in the index, but are still present in the archive. This can
be useful in the context of the PSX where the the archive may be stored at the
beginning of the disc, and gets interlaced with the iso9660 filesystem, in order
to allow the disc to boot, while the software does not need to rely on the filesystem
to access the files. This is a common practice in the PSX, and is used by many games.
The archive manager may simply be given a hardcoded LBA for the beginning of the
archive, and the authoring software would always write the archive at that location,
while reserving space inside the archive for the iso9660 filesystem.

]] --
-- Taken and adapted from https://gist.github.com/hmenke/4536dda27095634b4563a1a9d854a040
local bit = require 'bit'
local ffi = require 'ffi'
local lpeg = require 'lpeg'
local C = lpeg.C
local Cf = lpeg.Cf
local Cg = lpeg.Cg
local Ct = lpeg.Ct
local P = lpeg.P
local R = lpeg.R
local S = lpeg.S
local V = lpeg.V

-- number parsing
local digit = R '09'
local dot = P '.'
local eE = S 'eE'
local sign = S '+-' ^ -1
local mantissa = digit ^ 1 * dot * digit ^ 0 + dot * digit ^ 1 + digit ^ 1
local exponent = (eE * sign * digit ^ 1) ^ -1
local real = sign * mantissa * exponent / tonumber

-- optional whitespace
local ws = S ' \t\n\r' ^ 0

-- match a literal string surrounded by whitespace
local lit = function(str) return ws * P(str) * ws end

-- match a literal string and synthesize an attribute
local attr = function(str, attr) return ws * P(str) / function() return attr end * ws end

-- JSON grammar
local json = P {
    'value',

    value = V 'null_value' + V 'bool_value' + V 'string_value' + V 'real_value' + V 'array' + V 'object',

    null_value = attr('null', nil),
    bool_value = attr('true', true) + attr('false', false),
    string_value = ws * P '"' * C((P '\\"' + 1 - P '"') ^ 0) * P '"' * ws,
    real_value = ws * real * ws,
    array = lit '[' * Ct((V 'value' * lit ',' ^ -1) ^ 0) * lit ']',
    member_pair = Cg(V 'string_value' * lit ':' * V 'value') * lit ',' ^ -1,
    object = lit '{' * Cf(Ct '' * V 'member_pair' ^ 0, rawset) * lit '}',
}

function mkarchive(index, out)
    if type(index) == 'string' then index = Support.File.open(index) end
    if type(index) == 'table' and index._type == 'File' then index = tostring(index:read(index:size())) end
    if type(index) == 'string' then index = json:match(index) end
    if type(index) ~= 'table' then error('mkarchive: invalid index type') end
    index = index.files or {}

    local needsToClose = false

    if type(out) == 'string' then
        needsToClose = true
        out = Support.File.open(out, 'TRUNCATE')
    end

    for k, v in ipairs(index) do
        if type(v) ~= 'table' then error('mkarchive: invalid index entry type') end
        if not v.path then error('mkarchive: missing file path in index entry') end

        index[k].hash = v.hash or Support.extra.djbHash(v.path)
    end

    local zeroBuffer = ffi.new('uint8_t[?]', 2048, 0)

    local fileCount = #index
    local indexSize = fileCount * 16 + 16
    local indexSectors = math.ceil(indexSize / 2048)

    out:wSeek(indexSectors * 2048)

    for k, v in ipairs(index) do
        print('Packing', v.path)
        local path = v.path
        local file = Support.File.open(path)

        index[k].decompressedSize = file:size()
        index[k].offset = out:wTell() / 2048
        local srcData = file:readToSlice(file:size())
        local compressedData = PCSX.Misc.uclPack(srcData)
        local compressedSize = #compressedData
        local compressedSectors = math.ceil((compressedSize + 2047) / 2048)
        local decompressedSectors = math.ceil((index[k].decompressedSize + 2047) / 2048)
        if compressedSectors >= decompressedSectors then
            compressedSize = index[k].decompressedSize
            local padding = compressedSize % 2048
            out:writeMoveSlice(srcData)
            if padding > 0 then out:write(zeroBuffer, 2048 - padding) end
            index[k].compressionMethod = 0
            index[k].padding = 0
        else
            local padding = compressedSize % 2048
            if padding > 0 then
                padding = 2048 - padding
                out:write(zeroBuffer, padding)
            end
            out:writeMoveSlice(compressedData)
            index[k].compressionMethod = 1
            index[k].padding = padding
        end
        print('', index[k].decompressedSize, '->', compressedSize)

        compressedSize = math.floor((compressedSize + 2047) / 2048)
        index[k].compressedSize = compressedSize

        file:close()
    end

    local totalSize = out:wTell() / 2048

    out:wSeek(0)
    out:write('PSX-ARC1')
    out:writeU32(fileCount)
    out:writeU32(totalSize)

    table.sort(index, function(a, b) return a.hash < b.hash end)

    for _, v in ipairs(index) do
        out:writeU32(bit.band(v.hash, 0xffffffff))
        out:writeU32(bit.rshift(v.hash, 32))
        -- next 64 bits:
        -- - 21 bits for decompressed size
        -- - 11 bits for padding
        -- - 19 bits for offset
        -- - 10 bits for compressed size
        -- - 3 bits for compression method
        local decompressedSize = bit.band(v.decompressedSize, 0x1fffff)
        local padding = bit.band(v.padding, 0x7ff)
        local offset = bit.band(v.offset, 0x7ffff)
        local compressedSize = bit.band(v.compressedSize, 0x3ff)
        local compressionMethod = bit.band(v.compressionMethod, 0x7)
        local low = bit.bor(bit.lshift(decompressedSize, 0), bit.lshift(padding, 21))
        local high = bit.bor(bit.lshift(offset, 0), bit.lshift(compressedSize, 19), bit.lshift(compressionMethod, 29))
        out:writeU32(low)
        out:writeU32(high)
    end

    if needsToClose then out:close() end

    print('Packed', fileCount, 'files into', tonumber(totalSize), 'sectors, with', indexSectors, 'sectors of index data')
    pprint(index)
end
