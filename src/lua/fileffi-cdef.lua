-- lualoader, R"EOF(--
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
ffi.cdef [[

typedef struct { char opaque[?]; } LuaFile;
typedef struct { uint32_t size; uint8_t data[?]; } LuaBuffer;
typedef struct { char opaque[?]; } LuaSlice;

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

LuaFile* uvFifo(const char* address, int port);

void closeFile(LuaFile* wrapper);

uint64_t readFileRawPtr(LuaFile* wrapper, void* dst, uint64_t size);
uint64_t readFileBuffer(LuaFile* wrapper, LuaBuffer* buffer);

uint64_t writeFileRawPtr(LuaFile* wrapper, const const uint8_t* data, uint64_t size);
uint64_t writeFileBuffer(LuaFile* wrapper, const LuaBuffer* buffer);
void writeFileMoveSlice(LuaFile* wrapper, LuaSlice* slice);

int64_t rSeek(LuaFile* wrapper, int64_t pos, enum SeekWheel wheel);
int64_t rTell(LuaFile* wrapper);
int64_t wSeek(LuaFile* wrapper, int64_t pos, enum SeekWheel wheel);
int64_t wTell(LuaFile* wrapper);

uint64_t getFileSize(LuaFile*);

uint64_t readFileAtRawPtr(LuaFile* wrapper, void* dst, uint64_t size, uint64_t pos);
uint64_t readFileAtBuffer(LuaFile* wrapper, LuaBuffer* buffer, uint64_t pos);

uint64_t writeFileAtRawPtr(LuaFile* wrapper, const const uint8_t* data, uint64_t size, uint64_t pos);
uint64_t writeFileAtBuffer(LuaFile* wrapper, const LuaBuffer* buffer, uint64_t pos);
void writeFileAtMoveSlice(LuaFile* wrapper, LuaSlice* slice, uint64_t pos);

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

LuaFile* zReader(LuaFile*, int64_t size, bool raw);

uint64_t getSliceSize(LuaSlice*);
const void* getSliceData(LuaSlice*);
void destroySlice(LuaSlice*);
]]

-- )EOF"
