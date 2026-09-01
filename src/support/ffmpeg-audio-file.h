/*

MIT License

Copyright (c) 2022 PCSX-Redux authors

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

#pragma once

extern "C" {
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavutil/frame.h>
#include <libavutil/mem.h>
#include <libswresample/swresample.h>
}

#include "support/file.h"

namespace PCSX {

class FFmpegAudioFile : public File {
  public:
    enum class Channels { Stereo, Mono };
    enum class Endianness { Little, Big };
    enum class SampleFormat { U8, S16, S32, F32, D64 };
    FFmpegAudioFile(IO<File> file, Channels, Endianness, SampleFormat, unsigned frequency);
    virtual ~FFmpegAudioFile() {}
    virtual ssize_t rSeek(ssize_t pos, int wheel) final override;
    virtual ssize_t rTell() final override { return m_filePtr; }
    virtual ssize_t read(void* dest, size_t size) final override;
    virtual size_t size() final override {
        if (m_size >= 0) return m_size;
        throw std::runtime_error("Unable to determine file size");
    }
    virtual bool eof() final override { return m_hitEOF; }
    virtual File* dup() final override {
        return new FFmpegAudioFile(m_file, m_channels, m_endianess, m_sampleFormat, m_frequency);
    };
    virtual bool failed() final override { return m_failed || m_file->failed(); }

  private:
    virtual void closeInternal() final override;
    AVSampleFormat getSampleFormat() const;
    unsigned getSampleSize() const;
    ssize_t decompSome(void* dest, ssize_t size);
    IO<File> m_file;
    ssize_t m_filePtr = 0;
    ssize_t m_size = 0;
    bool m_hitEOF = false;
    bool m_failed = false;
    Channels m_channels;
    Endianness m_endianess;
    SampleFormat m_sampleFormat;
    unsigned m_frequency;
    AVFormatContext* m_formatContext = nullptr;
    AVIOContext* m_ioContext = nullptr;
    AVFrame* m_decodedFrame = nullptr;
    AVFrame* m_resampledFrame = nullptr;
    AVPacket* m_packet = nullptr;
    AVCodecContext* m_codecContext = nullptr;
    SwrContext* m_resamplerContext = nullptr;
    int m_audioStreamIndex = -1;
    ssize_t m_totalOut = 0;
    size_t m_packetPtr = 0;
};

}  // namespace PCSX
