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
    local builder = PCSX.isoBuilder(out)
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
    local builder = PCSX.isoBuilder(out)

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
    lu.assertFalse(readBack:failed())
    lu.assertEquals(readBack:size(), 2048)
end

function TestIsoBuilder:test_pvdFields()
    -- Verify PVD string fields round-trip correctly.
    local out = Support.File.buffer()
    local builder = PCSX.isoBuilder(out)

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
    local builder = PCSX.isoBuilder(out)

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
    lu.assertFalse(f1:failed())
    lu.assertEquals(f1:size(), 512)

    local f2 = reader:open('FILE2.DAT;1')
    lu.assertNotNil(f2)
    lu.assertFalse(f2:failed())
    lu.assertEquals(f2:size(), 1024)

    local f3 = reader:open('FILE3.DAT;1')
    lu.assertNotNil(f3)
    lu.assertFalse(f3:failed())
    lu.assertEquals(f3:size(), 3000)
end

function TestIsoBuilder:test_anchorLBA()
    -- Anchor a file to a specific LBA. The layout pass must pad prior sectors with
    -- empty M2F1 zero sectors, and the file's actual LBA must match the anchor.
    local out = Support.File.buffer()
    local builder = PCSX.isoBuilder(out)
    builder:writeLicense()
    builder:setVolumeIdent('ANCHOR_TEST')

    local root = builder:createRoot(1)

    -- First file is unanchored.
    local first = builder:createFile(root, 'FIRST.DAT', generateTestContent(2048))

    -- Second file is anchored well past where it would naturally land.
    local anchored = builder:createFile(root, 'ANCHOR.DAT', generateTestContent(2048))
    anchored:setAnchorLBA(150)
    lu.assertTrue(anchored:hasAnchorLBA())
    lu.assertEquals(anchored:getAnchorLBA(), 150)

    builder:close()

    -- After build, the anchored file's assigned LBA must be exactly 150.
    lu.assertEquals(anchored:getLBA(), 150)
    -- And the first file must come earlier.
    lu.assertTrue(first:getLBA() < 150)

    -- Read back via ISO9660 and verify the dir entry agrees.
    out:rSeek(0)
    local iso = PCSX.openIso(out)
    local reader = iso:createReader()
    local entries = reader:listDir('')
    local foundAnchor = false
    for _, e in ipairs(entries) do
        if e.name == 'ANCHOR.DAT;1' then
            foundAnchor = true
            lu.assertEquals(e.lba, 150)
            lu.assertEquals(e.size, 2048)
        end
    end
    lu.assertTrue(foundAnchor)

    -- Read back the anchored file's actual content to confirm we can open it.
    local f = reader:open('ANCHOR.DAT;1')
    lu.assertNotNil(f)
    lu.assertFalse(f:failed())
    lu.assertEquals(f:size(), 2048)
end

function TestIsoBuilder:test_declaredSize()
    -- Declare a size in the dir entry that's larger than the actual content.
    local out = Support.File.buffer()
    local builder = PCSX.isoBuilder(out)
    builder:writeLicense()
    builder:setVolumeIdent('DECL_SIZE')

    local root = builder:createRoot(1)
    local shadow = builder:createFile(root, 'SHADOW.BIN', generateTestContent(2048))
    shadow:setDeclaredSize(50 * 2048)  -- claim 50 sectors regardless of content
    lu.assertTrue(shadow:hasDeclaredSize())
    lu.assertEquals(shadow:getDeclaredSize(), 50 * 2048)

    builder:close()

    out:rSeek(0)
    local iso = PCSX.openIso(out)
    local reader = iso:createReader()
    local entries = reader:listDir('')
    local found = false
    for _, e in ipairs(entries) do
        if e.name == 'SHADOW.BIN;1' then
            found = true
            -- Declared size must be reflected, not the 2048-byte actual content.
            lu.assertEquals(e.size, 50 * 2048)
        end
    end
    lu.assertTrue(found)
end

function TestIsoBuilder:test_vpStyleShadowFile()
    -- VP-style layout: a small leading file, then a shadow file anchored to LBA 150
    -- whose declared size covers a large extent beyond its actual content. This
    -- emulates the Valkyrie Profile VALKYRIE.BIN pattern.
    local out = Support.File.buffer()
    local builder = PCSX.isoBuilder(out)
    builder:writeLicense()
    builder:setVolumeIdent('VP_STYLE')

    local root = builder:createRoot(1)

    -- Small executable-like file.
    builder:createFile(root, 'EXEC.BIN', generateTestContent(4096))

    -- Shadow file anchored at LBA 150 with declared size 200 sectors.
    local shadow = builder:createFile(root, 'BIG.BIN', generateTestContent(2048))
    shadow:setAnchorLBA(150)
    shadow:setDeclaredSize(200 * 2048)

    builder:close()

    -- Verify shadow file at exactly LBA 150 with the declared extent.
    lu.assertEquals(shadow:getLBA(), 150)

    out:rSeek(0)
    local iso = PCSX.openIso(out)
    local reader = iso:createReader()
    local entries = reader:listDir('')
    local foundShadow = false
    for _, e in ipairs(entries) do
        if e.name == 'BIG.BIN;1' then
            foundShadow = true
            lu.assertEquals(e.lba, 150)
            lu.assertEquals(e.size, 200 * 2048)
        end
    end
    lu.assertTrue(foundShadow)
end

function TestIsoBuilder:test_m2RawRoundTrip()
    -- Write a multi-sector M2_RAW payload with a deterministic pattern and verify
    -- the rebuilt disc returns identical bytes when read back in M2_RAW. Regression
    -- guard for the multi-threaded writeFiles path treating M2_RAW as M2_FORM1.
    local payload = Support.File.buffer()
    local data = ffi.new('uint8_t[?]', 4672)
    for i = 0, 4671 do data[i] = i % 251 end  -- deterministic, non-zero pattern
    payload:write(ffi.cast('const char*', data), 4672)
    payload:rSeek(0)

    local out = Support.File.buffer()
    local builder = PCSX.isoBuilder(out)
    builder:writeLicense()
    builder:setVolumeIdent('M2RAW_RT')
    local root = builder:createRoot(1)
    local file = builder:createFile(root, 'PATTERN.BIN', payload)
    file:setSectorMode('M2_RAW')
    builder:close()

    out:rSeek(0)
    local iso = PCSX.openIso(out)
    local reader = iso:createReader()
    local lba
    for _, e in ipairs(reader:listDir('')) do
        if e.name == 'PATTERN.BIN;1' then lba = e.lba end
    end
    lu.assertNotNil(lba)

    local rb = iso:open(lba, 4672, 'M2_RAW')
    for i = 0, 4671 do
        lu.assertEquals(rb:readU8At(i), i % 251,
            string.format('M2_RAW round-trip mismatch at byte %d', i))
    end
end

function TestIsoBuilder:test_anchorErrorOnBackwardLBA()
    -- Anchoring to an LBA that's already passed must raise an error at close time.
    local out = Support.File.buffer()
    local builder = PCSX.isoBuilder(out)
    builder:writeLicense()
    builder:setVolumeIdent('ANCHOR_ERR')

    local root = builder:createRoot(1)
    -- A reasonably large first file so the cursor advances past LBA 25.
    builder:createFile(root, 'PADDING.DAT', generateTestContent(64 * 2048))

    -- Anchor a second file to an LBA that's been passed by the time we lay it out.
    local bad = builder:createFile(root, 'BAD.DAT', generateTestContent(2048))
    bad:setAnchorLBA(25)

    local ok = pcall(function() builder:close() end)
    lu.assertFalse(ok, 'expected close() to throw on backward anchor')
end
