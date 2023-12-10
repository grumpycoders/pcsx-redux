--   Copyright (C) 2023 PCSX-Redux authors
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
local ffi = require('ffi')

-- This file can be used as a library to compress assets using the UCL library.
-- The `compress` function takes two arguments, the first being the input file
-- and the second being the output file. Both arguments can be either a string
-- or a File object. If a string is passed, the corresponding file will be
-- opened and closed automatically. If a File object is passed, it will not be
-- closed automatically.

-- The code isn't exactly optimal, due to the fact that the zlib library
-- doesn't support reading from a File object. This means that we need to read
-- the data into a buffer before compressing it. If not for this limitation,
-- the code would be much simpler. Considering that the Adler32 checksum is
-- here only for the sake of the demo, it would be possible to simply not
-- include it in the compressed data, and accelerate this code quite a bit.
function compress(input, output)
    local ownInput = false
    local ownOutput = false
    if type(input) == 'string' then
        input = Support.File.open(input)
        ownInput = true
    end
    if type(output) == 'string' then
        output = Support.File.open(output, 'TRUNCATE')
        ownOutput = true
    end

    local originalSize = input:size()

    -- We need to read the data into a buffer because the zlib's adler32 code
    -- doesn't support reading from a File object.
    local data = ffi.new('uint8_t[?]', originalSize)
    input:read(data, originalSize)
    input:rSeek(-originalSize, 'SEEK_CUR')

    local adler = zlib.adler32(data, originalSize)

    local compressed = Support.File.buffer()
    PCSX.Misc.uclPack(input, compressed)
    local compressedSize = compressed:size()

    -- Write the 16-bytes header. The first 4 bytes are the magic number, the
    -- next 4 bytes are the original size, the next 4 bytes are the compressed
    -- size and the last 4 bytes are the adler32 checksum.
    output:writeU32(0x4e324501)
    output:writeU32(originalSize)
    output:writeU32(compressedSize)
    output:writeU32(adler)

    -- Write the compressed data.
    output:write(compressed:read(compressedSize))

    if ownInput then input:close() end

    if ownOutput then output:close() end
end
