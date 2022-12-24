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

-- This script creates a test ISO image for the CDROM unit tests.

local uniromDisc = PCSX.getCurrentIso()
local uniromDiscReader = uniromDisc:createReader()
local uniromFile = uniromDiscReader:open('UNIROM_B.EXE;1')
local licenseFile = uniromDisc:open(0, 2352 * 16, 'RAW')
local iso = PCSX.isoBuilder(Support.File.open('test.bin', 'TRUNCATE'))
iso:writeLicense(licenseFile)

local b = Support.NewLuaBuffer(2352)
ffi.fill(b.data, 2352)
b:resize(2048)

local pvd = Support.File.buffer()
pvd:writeAt(b, 0)
pvd:writeU8At(1, 0)
pvd:writeAt('CD001', 1)
pvd:writeU32At(1, 132)
pvd:writeU32At(17, 140)
pvd:writeU32At(18, 158)

local pt = Support.File.buffer()
pt:writeAt(b, 0)
pt:writeU8At(1, 0)
pt:writeU8At(18, 2)
pt:writeU8At(1, 6)

local root = Support.File.buffer()
root:writeAt(b, 0)
root:writeU8At(42, 0)
root:writeU32At(19, 2)
root:writeU32At(uniromFile:size(), 10)
root:writeU8At(9, 32)
root:writeAt('PSX.EXE;1', 33)

pvd:read(b)
iso:writeSector(b)
pt:read(b)
iso:writeSector(b)
root:read(b)
iso:writeSector(b)

local count = 19
while not uniromFile:eof() do
    uniromFile:read(b)
    iso:writeSector(b)
    count = count + 1
end

ffi.fill(b.data, 2048)
for i = count, 70 * 60 * 75 - 1 do
    b[0] = bit.band(i, 0xff)
    b[1] = bit.band(bit.rshift(i, 8), 0xff)
    b[2] = bit.band(bit.rshift(i, 16), 0xff)
    iso:writeSector(b)
end

b:resize(2352)
local audioTrack
audioTrack = Support.File.open('test-t2.bin', 'TRUNCATE')
for i = 1, 75 * 5 do
    audioTrack:write(b)
end
audioTrack = Support.File.open('test-t3.bin', 'TRUNCATE')
for i = 1, 75 * 5 + 15 do
    audioTrack:write(b)
end
audioTrack = Support.File.open('test-t4.bin', 'TRUNCATE')
for i = 1, 75 * 5 + 15 do
    audioTrack:write(b)
end
audioTrack = Support.File.open('test-t5.bin', 'TRUNCATE')
for i = 1, 75 * 5 + 15 do
    audioTrack:write(b)
end
audioTrack = Support.File.open('test-t6.bin', 'TRUNCATE')
for i = 1, 75 * 5 + 15 do
    audioTrack:write(b)
end

local cue = Support.File.open('test.cue', 'TRUNCATE')
cue:write([[
FILE "test.bin" BINARY
  TRACK 01 MODE2/2352
    INDEX 01 00:00:00
FILE "test-t2.bin" BINARY
  TRACK 02 AUDIO
    INDEX 01 00:00:00
FILE "test-t3.bin" BINARY
  TRACK 03 AUDIO
    INDEX 01 00:00:00
FILE "test-t4.bin" BINARY
  TRACK 04 AUDIO
    INDEX 00 00:00:00
    INDEX 01 00:02:00
FILE "test-t5.bin" BINARY
  TRACK 05 AUDIO
    INDEX 00 00:00:00
    INDEX 01 00:02:45
FILE "test-t6.bin" BINARY
  TRACK 06 AUDIO
    INDEX 00 00:00:00
    INDEX 01 00:02:00
]])

for i = 7, 25 do
    audioTrack = Support.File.open(string.format('test-t%d.bin', i), 'TRUNCATE')
    for j = 1, 75 * 5 + 15 do
        audioTrack:write(b)
    end
    cue:write(string.format('FILE "test-t%d.bin" BINARY\n', i))
    cue:write(string.format('  TRACK %02d AUDIO\n', i))
    cue:write('    INDEX 01 00:02:00\n')
end

PCSX.quit()
