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

#include "cdrom/cdriso.h"
#include "core/cdrom.h"
#include "cueparser/cueparser.h"
#include "cueparser/disc.h"
#include "cueparser/fileabstract.h"
#include "cueparser/scheduler.h"
#include "support/ffmpeg-audio-file.h"

// this function tries to get the .cue file of the given .bin
// the necessary data is put into the ti (trackinformation)-array
bool PCSX::CDRIso::parsecue(const char *isofileString) {
    std::filesystem::path isofile = MAKEU8(isofileString);
    std::filesystem::path cuename, filepath;
    IO<File> fi;

    m_numtracks = 0;

    // copy name of the iso and change extension from .bin to .cue
    cuename = isofile;
    cuename.replace_extension("cue");

    fi.setFile(new UvFile(cuename));
    if (g_emulator->settings.get<Emulator::SettingFullCaching>()) {
        fi.asA<UvFile>()->startCaching();
    }
    if (fi->failed()) return false;

    // Some stupid tutorials wrongly tell users to use cdrdao to rip a
    // "bin/cue" image, which is in fact a "bin/toc" image. So let's check
    // that...
    if (fi->gets() == "CD_ROM_XA") {
        // Don't proceed further, as this is actually a .toc file rather
        // than a .cue file.
        return parsetoc(isofileString);
    }
    fi->rSeek(0, SEEK_SET);

    // build a path for files referenced in .cue
    filepath = cuename.parent_path();

    CueScheduler scheduler;
    Scheduler_construct(&scheduler);
    struct Context {
        std::filesystem::path filepath;
        bool failed = false;
    } context;
    context.filepath = filepath;
    scheduler.opaque = &context;

    auto createFile = [](CueFile *file, CueScheduler *scheduler, const char *filename) -> CueFile * {
        Context *context = reinterpret_cast<Context *>(scheduler->opaque);
        UvFile *fi = new UvFile(filename);
        if (fi->failed()) {
            delete fi;
            fi = new UvFile(context->filepath / filename);
        }
        file->opaque = fi;
        file->destroy = [](CueFile *file) {
            UvFile *fi = reinterpret_cast<UvFile *>(file->opaque);
            delete fi;
            file->opaque = nullptr;
        };
        file->close = [](CueFile *file, CueScheduler *scheduler, void (*cb)(CueFile *, CueScheduler *)) {
            UvFile *fi = reinterpret_cast<UvFile *>(file->opaque);
            fi->close();
            File_schedule_close(file, scheduler, cb);
        };
        file->size = [](CueFile *file, CueScheduler *scheduler, int compressed,
                        void (*cb)(CueFile *, CueScheduler *, uint64_t)) {
            UvFile *fi = reinterpret_cast<UvFile *>(file->opaque);
            if (compressed) {
                FFmpegAudioFile *cfi = new FFmpegAudioFile(fi, FFmpegAudioFile::CHANNELS_STEREO,
                                                           FFmpegAudioFile::ENDIANNESS_LITTLE, 44100);
                file->opaque = cfi;
                File_schedule_size(file, scheduler, cfi->size(), cb);
            } else {
                File_schedule_size(file, scheduler, fi->size(), cb);
            }
        };
        file->read = [](CueFile *file, CueScheduler *scheduler, uint32_t amount, uint64_t cursor, uint8_t *buffer,
                        void (*cb)(CueFile *, CueScheduler *, int error, uint32_t amount, uint8_t *buffer)) {
            UvFile *fi = reinterpret_cast<UvFile *>(file->opaque);
            if (cursor >= fi->size()) {
                File_schedule_read(file, scheduler, 0, 0, nullptr, cb);
            } else {
                auto r = fi->readAt(buffer, amount, cursor);
                File_schedule_read(file, scheduler, r < 0 ? 1 : 0, r, buffer, cb);
            }
        };
        file->write = [](CueFile *file, CueScheduler *scheduler, uint32_t amount, uint64_t cursor,
                         const uint8_t *buffer, void (*cb)(CueFile *, CueScheduler *, int error, uint32_t amount)) {
            throw std::runtime_error("Writes not implemented");
        };
        file->cfilename = nullptr;
        file->filename = nullptr;
        file->references = 1;
        return !fi->failed() ? file : nullptr;
    };

    CueFile cue;
    CueParser parser;
    CueDisc disc;
    bool success = createFile(&cue, &scheduler, cuename.string().c_str());
    if (!success) {
        throw std::runtime_error("Couldn't open cue file twice...");
    }
    cue.cfilename = cuename.string().c_str();
    CueParser_construct(&parser, &disc);
    CueParser_parse(&parser, &cue, &scheduler, createFile,
                    [](CueParser *parser, CueScheduler *scheduler, const char *error) {
                        Context *context = reinterpret_cast<Context *>(scheduler->opaque);
                        if (error) {
                            context->failed = true;
                            g_system->log(LogClass::CDROM_IO, "Error parsing Cue File: %s", error);
                        }
                    });

    Scheduler_run(&scheduler);
    CueParser_destroy(&parser);

    File_schedule_close(&cue, &scheduler, [](CueFile *file, CueScheduler *scheduler) { file->destroy(file); });
    if (context.failed) {
        for (unsigned i = 1; i <= disc.trackCount; i++) {
            CueTrack *track = &disc.tracks[i];
            if (track->file) {
                if (track->file->references == 1) {
                    File_schedule_close(track->file, &scheduler,
                                        [](CueFile *file, CueScheduler *scheduler) { file->destroy(file); });
                } else {
                    track->file->references--;
                }
                track->file = nullptr;
            }
        }
        Scheduler_run(&scheduler);
        return false;
    }
    Scheduler_run(&scheduler);

    m_cdHandle.setFile(reinterpret_cast<UvFile *>(disc.tracks[1].file->opaque));

    for (unsigned i = 1; i <= disc.trackCount; i++) {
        CueTrack *track = &disc.tracks[i];
        File *fi = reinterpret_cast<File *>(track->file->opaque);
        m_ti[i].handle.setFile(new SubFile(fi, (track->indices[1] - track->fileOffset) * 2352, track->size * 2352));
        m_ti[i].type = track->trackType == TRACK_TYPE_AUDIO ? TrackType::CDDA : TrackType::DATA;
        m_ti[i].cddatype = track->compressed ? trackinfo::CCDDA : trackinfo::BIN;
        m_ti[i].start = IEC60908b::MSF(track->indices[1]);
        m_ti[i].pregap = IEC60908b::MSF(track->indices[1] - track->indices[0]);
        m_ti[i].length = IEC60908b::MSF(track->size);
    }

    m_numtracks = disc.trackCount;
    m_multifile = true;

    return true;
}
