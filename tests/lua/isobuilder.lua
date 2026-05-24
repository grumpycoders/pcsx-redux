--   Copyright (C) 2026 PCSX-Redux authors
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

local lu = require 'luaunit'
local ffi = require 'ffi'

TestIsoBuilder = {}

-- Generate a small DTMF tone as test file content.
local function generateTestContent(size)
    local buf = Support.File.buffer()
    local data = ffi.new('uint8_t[?]', size)
    for i = 0, size - 1 do
        -- Simple pattern: sine-ish bytes for verifiable content.
        data[i] = math.floor(128 + 127 * math.sin(2 * math.pi * i / 256))
    end
    buf:write(ffi.cast('const char*', data), size)
    buf:rSeek(0)
    return buf
end

function TestIsoBuilder:test_minimalIso()
    -- Create a minimal ISO with one file in the root directory.
    local out = Support.File.buffer()
    local builder = PCSX.createIsoBuilder(out)
    lu.assertNotNil(builder)
    lu.assertFalse(builder:failed())

    -- Write empty system area (no license).
    builder:writeLicense()

    -- Set PVD fields.
    builder:setSystemIdent('PLAYSTATION')
    builder:setVolumeIdent('TEST_DISC')

    -- Create root directory (1 sector).
    local root = builder:createRoot(1)
    lu.assertNotNil(root)
    lu.assertTrue(root:isDir())

    -- Create a small test file.
    local content = generateTestContent(4096)
    local file = builder:createFile(root, 'TEST.DAT', content)
    lu.assertNotNil(file)
    lu.assertFalse(file:isDir())
    lu.assertEquals(file:getName(), 'TEST.DAT')

    -- Close - computes layout and writes everything.
    builder:close()

    -- The output buffer should now contain a valid ISO image.
    lu.assertTrue(out:size() > 0)

    -- Verify: open the ISO and read it back.
    out:rSeek(0)
    local iso = PCSX.openIso(out)
    lu.assertNotNil(iso)
    lu.assertFalse(iso:failed())

    local reader = iso:createReader()
    lu.assertNotNil(reader)

    -- Open the file we created.
    local readBack = reader:open('TEST.DAT;1')
    lu.assertNotNil(readBack)
    lu.assertEquals(readBack:size(), 4096)

    -- Verify content matches.
    readBack:rSeek(0)
    local readData = readBack:read(4096)
    lu.assertNotNil(readData)

    content:rSeek(0)
    local origData = content:read(4096)
    lu.assertEquals(tostring(readData), tostring(origData))
end

function TestIsoBuilder:test_subdirectory()
    -- Create an ISO with a subdirectory containing a file.
    local out = Support.File.buffer()
    local builder = PCSX.createIsoBuilder(out)

    builder:writeLicense()
    builder:setVolumeIdent('SUBDIR_TEST')

    local root = builder:createRoot(1)
    local dataDir = builder:createDir(root, 'DATA', 1)
    lu.assertTrue(dataDir:isDir())
    lu.assertEquals(dataDir:getName(), 'DATA')

    local content = generateTestContent(2048)
    builder:createFile(dataDir, 'INFO.BIN', content)

    builder:close()

    -- Read it back.
    out:rSeek(0)
    local iso = PCSX.openIso(out)
    local reader = iso:createReader()

    -- Open file through subdirectory path.
    local readBack = reader:open('DATA/INFO.BIN;1')
    lu.assertNotNil(readBack)
    lu.assertEquals(readBack:size(), 2048)
end

function TestIsoBuilder:test_pvdFields()
    -- Verify PVD string fields round-trip correctly.
    local out = Support.File.buffer()
    local builder = PCSX.createIsoBuilder(out)

    builder:setSystemIdent('PLAYSTATION')
    builder:setVolumeIdent('MY_VOL')
    builder:setPublisherIdent('TEST_PUB')
    builder:setApplicationIdent('TEST_APP')

    lu.assertEquals(builder:getSystemIdent(), 'PLAYSTATION')
    lu.assertEquals(builder:getVolumeIdent(), 'MY_VOL')
    lu.assertEquals(builder:getPublisherIdent(), 'TEST_PUB')
    lu.assertEquals(builder:getApplicationIdent(), 'TEST_APP')
end

function TestIsoBuilder:test_multipleFiles()
    -- Create an ISO with multiple files.
    local out = Support.File.buffer()
    local builder = PCSX.createIsoBuilder(out)

    builder:writeLicense()
    builder:setVolumeIdent('MULTI_FILE')

    local root = builder:createRoot(1)

    local content1 = generateTestContent(512)
    local content2 = generateTestContent(1024)
    local content3 = generateTestContent(3000)

    builder:createFile(root, 'FILE1.DAT', content1)
    builder:createFile(root, 'FILE2.DAT', content2)
    builder:createFile(root, 'FILE3.DAT', content3)

    builder:close()

    -- Read back and verify sizes.
    out:rSeek(0)
    local iso = PCSX.openIso(out)
    local reader = iso:createReader()

    local f1 = reader:open('FILE1.DAT;1')
    lu.assertNotNil(f1)
    lu.assertEquals(f1:size(), 512)

    local f2 = reader:open('FILE2.DAT;1')
    lu.assertNotNil(f2)
    lu.assertEquals(f2:size(), 1024)

    local f3 = reader:open('FILE3.DAT;1')
    lu.assertNotNil(f3)
    lu.assertEquals(f3:size(), 3000)
end
