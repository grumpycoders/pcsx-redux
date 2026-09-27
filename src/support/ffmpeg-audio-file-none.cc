/*

MIT License

Copyright (c) 2024 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

// There is no FFmpeg on wasm. A compressed CD-audio track constructs and
// immediately reports failed(), which is the same path the caller already
// takes for an unreadable track.
#ifdef __EMSCRIPTEN__

#include "support/ffmpeg-audio-file.h"

PCSX::FFmpegAudioFile::FFmpegAudioFile(IO<File> file, Channels channels, Endianness endianess,
                                       SampleFormat sampleFormat, unsigned frequency)
    : File(RO_SEEKABLE), m_file(file), m_channels(channels), m_endianess(endianess), m_sampleFormat(sampleFormat) {
    m_failed = true;
}

PCSX::FFmpegAudioFile::~FFmpegAudioFile() {}

ssize_t PCSX::FFmpegAudioFile::rSeek(ssize_t pos, int wheel) { return -1; }

ssize_t PCSX::FFmpegAudioFile::read(void* dest, size_t size) { return -1; }

void PCSX::FFmpegAudioFile::closeInternal() {}

int PCSX::FFmpegAudioFile::getSampleFormat() const { return 0; }

unsigned PCSX::FFmpegAudioFile::getSampleSize() const { return 0; }

ssize_t PCSX::FFmpegAudioFile::decompSome(void* dest, ssize_t size) { return -1; }

#endif
