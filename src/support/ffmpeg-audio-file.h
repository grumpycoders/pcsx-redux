/***************************************************************************
 *   Copyright (C) 2022 PCSX-Redux authors                                 *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

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
    enum Channels { CHANNELS_STEREO, CHANNELS_MONO };
    enum Endianness { ENDIANNESS_LITTLE, ENDIANNESS_BIG };
    FFmpegAudioFile(IO<File> file, Channels, Endianness, unsigned frequency);
    ~FFmpegAudioFile();
    virtual void close() final override {}
    virtual ssize_t rSeek(ssize_t pos, int wheel) final override;
    virtual ssize_t rTell() final override { return m_filePtr; }
    virtual ssize_t read(void* dest, size_t size) final override;
    virtual size_t size() final override {
        if (m_size >= 0) return m_size;
        throw std::runtime_error("Unable to determine file size");
    }
    virtual bool eof() final override { return m_hitEOF; }
    virtual File* dup() final override { return new FFmpegAudioFile(m_file, m_channels, m_endianess, m_frequency); };
    virtual bool failed() final override { return m_failed || m_file->failed(); }

  private:
    ssize_t decompSome(void* dest, ssize_t size);
    IO<File> m_file;
    ssize_t m_filePtr = 0;
    ssize_t m_size = 0;
    bool m_hitEOF = false;
    bool m_failed = false;
    Channels m_channels;
    Endianness m_endianess;
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
