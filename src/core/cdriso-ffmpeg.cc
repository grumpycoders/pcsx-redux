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

#include "core/cdriso.h"

extern "C" {
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavutil/mathematics.h>
#include <libavutil/opt.h>
#include <libavutil/timestamp.h>
#include <libswresample/swresample.h>
}

int PCSX::CDRiso::get_compressed_cdda_track_length(const char *filepath) {
    int seconds = -1;
    av_log_set_level(AV_LOG_QUIET);

    AVFormatContext *inAudioFormat = NULL;
    inAudioFormat = avformat_alloc_context();
    int errorCode = avformat_open_input(&inAudioFormat, filepath, NULL, NULL);
    avformat_find_stream_info(inAudioFormat, NULL);
    seconds = (int)ceil((double)inAudioFormat->duration / (double)AV_TIME_BASE);
    avformat_close_input(&inAudioFormat);
    return seconds;
}

static int decode_packet(int *got_frame, AVPacket pkt, int audio_stream_idx, AVFrame *frame,
                         AVCodecContext *audio_dec_ctx, void *buf, int *size, SwrContext *swr) {
    int ret = 0;
    int decoded = pkt.size;
    *got_frame = 0;

    if (pkt.stream_index == audio_stream_idx) {
        // ret = avcodec_decode_audio4(audio_dec_ctx, frame, got_frame, &pkt);
        ret = avcodec_receive_frame(audio_dec_ctx, frame);
        if (ret == 0) *got_frame = 1;
        if (ret == AVERROR(EAGAIN)) ret = 0;
        if (ret == 0) ret = avcodec_send_packet(audio_dec_ctx, &pkt);
        if (ret == AVERROR(EAGAIN)) {
            ret = 0;
        } else if (ret < 0) {
            PCSX::g_system->printf(_("Error decoding audio frame\n"));
            return ret;
        } else {
            ret = pkt.size;
        }

        /* Some audio decoders decode only part of the packet, and have to be
         * called again with the remainder of the packet data.
         * Sample: fate-suite/lossless-audio/luckynight-partial.shn
         * Also, some decoders might over-read the packet. */

        decoded = FFMIN(ret, pkt.size);

        if (*got_frame) {
            size_t unpadded_linesize = frame->nb_samples * av_get_bytes_per_sample(AVSampleFormat(frame->format));
            swr_convert(swr, (uint8_t **)&buf, frame->nb_samples, (const uint8_t **)frame->data, frame->nb_samples);
            (*size) += (unpadded_linesize * 2);
        }
    }
    return decoded;
}

static int open_codec_context(int *stream_idx, AVFormatContext *fmt_ctx, enum AVMediaType type) {
    int ret, stream_index;
    AVStream *st;
    AVDictionary *opts = NULL;

    ret = av_find_best_stream(fmt_ctx, type, -1, -1, NULL, 0);

    if (ret < 0) {
        PCSX::g_system->printf(_("Could not find %s stream in input file\n"), av_get_media_type_string(type));
        return ret;
    } else {
        stream_index = ret;
        st = fmt_ctx->streams[stream_index];

        const AVCodec *dec = avcodec_find_decoder(st->codecpar->codec_id);
        if (!dec) {
            PCSX::g_system->printf(_("Failed to find %s codec\n"), av_get_media_type_string(type));
            return AVERROR(EINVAL);
        }

        AVCodecContext *dec_ctx = avcodec_alloc_context3(dec);
        if (!dec_ctx) {
            PCSX::g_system->printf(_("Failed to find %s codec\n"), av_get_media_type_string(type));
            return AVERROR(EINVAL);
        }
        avcodec_parameters_to_context(dec_ctx, st->codecpar);

        /* Init the decoders, with or without reference counting */
        if ((ret = avcodec_open2(dec_ctx, dec, NULL)) < 0) {
            PCSX::g_system->printf(_("Failed to open %s codec\n"), av_get_media_type_string(type));
            avcodec_free_context(&dec_ctx);
            return ret;
        }
        avcodec_free_context(&dec_ctx);
        *stream_idx = stream_index;
    }
    return 0;
}

static int decode_compressed_cdda_track(char *buf, char *src_filename, int *size) {
    AVFormatContext *fmt_ctx = NULL;
    AVCodecContext *audio_dec_ctx = NULL;
    const AVCodec *audio_codec = NULL;
    AVStream *audio_stream = NULL;
    int audio_stream_idx = -1;
    AVFrame *frame = NULL;
    AVPacket pkt;
    SwrContext *resample_context;
    int ret = 0, got_frame;

    if (avformat_open_input(&fmt_ctx, src_filename, NULL, NULL) < 0) {
        PCSX::g_system->printf(_("Could not open source file %s\n"), src_filename);
        return -1;
    }

    if (avformat_find_stream_info(fmt_ctx, NULL) < 0) {
        PCSX::g_system->printf(_("Could not find stream information\n"));
        ret = -1;
        goto end;
    }

    if (open_codec_context(&audio_stream_idx, fmt_ctx, AVMEDIA_TYPE_AUDIO) >= 0) {
        audio_stream = fmt_ctx->streams[audio_stream_idx];
    }

    if (!audio_stream) {
        PCSX::g_system->printf(_("Could not find audio stream in the input, aborting\n"));
        ret = -1;
        goto end;
    }

    audio_codec = avcodec_find_decoder(audio_stream->codecpar->codec_id);

    if (!audio_codec) {
        PCSX::g_system->printf(_("Could not find audio codec for the input, aborting\n"));
        ret = -1;
        goto end;
    }

    audio_dec_ctx = avcodec_alloc_context3(audio_codec);

    if (!audio_dec_ctx) {
        PCSX::g_system->printf(_("Could not allocate audio codec for the input, aborting\n"));
        ret = -1;
        goto end;
    }

    // init and configure resampler
    resample_context = swr_alloc();
    if (!resample_context) {
        PCSX::g_system->printf(_("Could not allocate resample context"));
        ret = -1;
        goto end;
    }
    av_opt_set_int(resample_context, "in_channel_layout", audio_dec_ctx->channel_layout, 0);
    av_opt_set_int(resample_context, "out_channel_layout", AV_CH_LAYOUT_STEREO, 0);
    av_opt_set_int(resample_context, "in_sample_rate", audio_dec_ctx->sample_rate, 0);
    av_opt_set_int(resample_context, "out_sample_rate", 44100, 0);
    av_opt_set_sample_fmt(resample_context, "in_sample_fmt", audio_dec_ctx->sample_fmt, 0);
    av_opt_set_sample_fmt(resample_context, "out_sample_fmt", AV_SAMPLE_FMT_S16, 0);
    if (swr_init(resample_context) < 0) {
        PCSX::g_system->printf(_("Could not open resample context"));
        ret = -1;
        goto end;
    }

    frame = av_frame_alloc();
    if (!frame) {
        PCSX::g_system->printf(_("Could not allocate frame\n"));
        ret = AVERROR(ENOMEM);
        goto end;
    }

    /* initialize packet, set data to NULL, let the demuxer fill it */
    av_init_packet(&pkt);
    pkt.data = NULL;
    pkt.size = 0;

    /* read frames from the file */
    while (av_read_frame(fmt_ctx, &pkt) >= 0) {
        AVPacket orig_pkt = pkt;
        do {
            ret = decode_packet(&got_frame, pkt, audio_stream_idx, frame, audio_dec_ctx, buf + (*size), size,
                                resample_context);
            if (ret < 0) break;
            pkt.data += ret;
            pkt.size -= ret;
        } while (pkt.size > 0);
        av_packet_unref(&orig_pkt);
    }

    /* flush cached frames */
    pkt.data = NULL;
    pkt.size = 0;
    do {
        decode_packet(&got_frame, pkt, audio_stream_idx, frame, audio_dec_ctx, buf + (*size), size, resample_context);
    } while (got_frame);

end:
    swr_free(&resample_context);
    if (audio_dec_ctx) {
        avcodec_close(audio_dec_ctx);
        avcodec_free_context(&audio_dec_ctx);
    }
    avformat_close_input(&fmt_ctx);
    av_frame_free(&frame);
    return ret < 0;
}

/* end of ffmpeg-only code */

int PCSX::CDRiso::do_decode_cdda(struct trackinfo *tri, uint32_t tracknumber) {
    tri->decoded_buffer = (char *)malloc(tri->len_decoded_buffer);
    memset(tri->decoded_buffer, 0, tri->len_decoded_buffer - 1);

    if (tri->decoded_buffer == NULL) {
        PCSX::g_system->message(_("Could not allocate memory to decode CDDA TRACK: %s\n"), tri->filepath);
        tri->handle->close();                   // encoded file handle not needed anymore
        tri->handle.setFile(new BufferFile());  // change handle to decoded one
        tri->cddatype = trackinfo::BIN;
        return 0;
    }

    tri->handle->close();  // encoded file handle not needed anymore
    tri->handle.reset();

    int ret;
    PCSX::g_system->printf(_("Decoding audio tr#%u (%s)..."), tracknumber, tri->filepath);

    int len = 0;

    if ((ret = decode_compressed_cdda_track(tri->decoded_buffer, tri->filepath, &len)) == 0) {
        if (len > tri->len_decoded_buffer) {
            PCSX::g_system->printf(_("Buffer overflow..."));
            PCSX::g_system->printf(_("Actual %i vs. %i estimated\n"), len, tri->len_decoded_buffer);
            len = tri->len_decoded_buffer;  // we probably segfaulted already, oh well...
        }

        tri->handle.setFile(new BufferFile(tri->decoded_buffer, len));  // change handle to decoded one
        PCSX::g_system->printf(_("OK\n"), tri->filepath);
    }
    tri->cddatype = trackinfo::BIN;
    return len;
}
