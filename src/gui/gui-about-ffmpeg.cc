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

#ifndef __EMSCRIPTEN__

extern "C" {
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavutil/avutil.h>
}

#include <algorithm>
#include <cstring>
#include <vector>

#include "gui/gui.h"
#include "imgui.h"
#include "support/strings-helpers.h"

void PCSX::GUI::aboutFFmpegTab() {
    if (ImGui::BeginTabItem(_("FFmpeg information"))) {
        ImGui::Text(_("Version: %s"), av_version_info());
        ImGui::Text(_("License: %s"), avutil_license());
        ImGui::TextWrapped(_("Configuration: %s"), avutil_configuration());
        ImGui::Separator();

        ImGui::TextUnformatted(_("List of supported formats:"));
        const AVInputFormat* format = nullptr;
        void* opaque = nullptr;
        std::vector<const AVInputFormat*> formats;
        unsigned nb_formats = 0;
        while ((format = av_demuxer_iterate(&opaque))) nb_formats++;
        formats.reserve(nb_formats);
        opaque = nullptr;
        while ((format = av_demuxer_iterate(&opaque))) formats.push_back(format);
        std::sort(formats.begin(), formats.end(), [](auto& a, auto& b) { return strcmp(a->name, b->name) < 0; });
        useMonoFont();
        for (auto& format : formats) {
            ImGui::Text("  %-25s %s", format->name, format->long_name);
        }
        ImGui::PopFont();
        ImGui::Separator();

        ImGui::TextUnformatted(_("List of supported codecs: (D: Decoder, E: Encoder, L: Lossy, S: Lossless)"));
        const AVCodecDescriptor* codec = nullptr;
        std::vector<const AVCodecDescriptor*> codecs;
        unsigned nb_codecs = 0;
        while ((codec = avcodec_descriptor_next(codec))) nb_codecs++;
        codecs.reserve(nb_codecs);
        codec = nullptr;
        while ((codec = avcodec_descriptor_next(codec))) codecs.push_back(codec);
        std::sort(codecs.begin(), codecs.end(), [](auto& a, auto& b) {
            if (a->type == b->type) {
                return strcmp(a->name, b->name) < 0;
            }
            return a->type < b->type;
        });

        auto getMediaType = [](AVMediaType type) -> const char* {
            switch (type) {
                case AVMEDIA_TYPE_VIDEO:
                    return "Video";
                case AVMEDIA_TYPE_AUDIO:
                    return "Audio";
                case AVMEDIA_TYPE_DATA:
                    return "Data";
                case AVMEDIA_TYPE_SUBTITLE:
                    return "Subtitle";
                case AVMEDIA_TYPE_ATTACHMENT:
                    return "Attachment";
                default:
                    return "Unknown";
            }
        };

        auto previousType = AVMEDIA_TYPE_UNKNOWN;

        useMonoFont();
        for (auto& codec : codecs) {
            auto type = codec->type;
            if (type != previousType) {
                ImGui::Separator();
                useMainFont();
                ImGui::Text(_("%s codecs"), getMediaType(type));
                ImGui::PopFont();
                previousType = type;
            }
            std::string_view name = codec->name;
            if (StringsHelpers::endsWith(name, "_deprecated")) continue;
            ImGui::Text("  %c%c%c%c %-20s %s", avcodec_find_decoder(codec->id) ? 'D' : '.',
                        avcodec_find_encoder(codec->id) ? 'E' : '.', (codec->props & AV_CODEC_PROP_LOSSY) ? 'L' : '.',
                        (codec->props & AV_CODEC_PROP_LOSSLESS) ? 'S' : '.', codec->name, codec->long_name);
        }
        ImGui::PopFont();
        ImGui::EndTabItem();
    }
}

#endif  // __EMSCRIPTEN__
