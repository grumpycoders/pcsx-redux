/*

MIT License

Copyright (c) 2022 Nicolas "Pixel" Noble

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

#include "cueparser/cueparser.h"

#include <assert.h>
#include <ctype.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "cueparser/disc.h"
#include "cueparser/fileabstract.h"
#include "cueparser/scheduler.h"

#pragma GCC diagnostic ignored "-Wswitch"

enum Keyword {
    KW_EMPTY = 0x00001505,
    KW_4CH = 0x0b86667a,
    KW_AIFF = 0x7c7ea8ad,
    KW_AUDIO = 0x0c561a33,
    KW_BINARY = 0x9da252ca,
    KW_CATALOG = 0x2316d516,
    KW_CDG = 0x0b87cf65,
    KW_CDI_2336 = 0x2f162780,
    KW_CDI_2352 = 0x2f1626c2,
    KW_CDTEXTFILE = 0xbbd08639,
    KW_DCP = 0x0b87bad2,
    KW_FILE = 0x7c7e1383,
    KW_FLAGS = 0x0c434e1a,
    KW_INDEX = 0x0cda305b,
    KW_ISRC = 0x7c8344ae,
    KW_MODE1_2048 = 0x10a03916,
    KW_MODE1_2352 = 0x10a02cbe,
    KW_MODE2_2336 = 0x0e924c9f,
    KW_MODE2_2352 = 0x0e924d5d,
    KW_MOTOROLA = 0x7ba98cec,
    KW_MP3 = 0x0b87c98b,
    KW_PERFORMER = 0xcc7e14e3,
    KW_POSTGAP = 0xb61fc6ab,
    KW_PRE = 0x0b880de2,
    KW_PREGAP = 0xc625ff94,
    KW_REM = 0x0b88069f,
    KW_SCMS = 0x7c8a8e8b,
    KW_SONGWRITER = 0xb05cc69f,
    KW_TITLE = 0x0d83f885,
    KW_TRACK = 0x0d7ac5ca,
    KW_WAVE = 0x7c885360,
};

static void new_keyword(struct CueParser* parser) { parser->keyword = 5381; }

static void keyword_add_char(struct CueParser* parser, int c) {
    uint32_t hash = parser->keyword;
    hash = ((hash << 5) + hash) ^ c;
    parser->keyword = hash;
}

struct end_Closure {
    struct CueScheduler* scheduler;
    void (*destroy)(struct CueClosure*);
    void (*call)(struct CueClosure*);
    struct CueClosure* next;
    struct CueParser* parser;
    const char* error;
};

static void closure_generic_free(struct CueClosure* closure) { free(closure); }

static void end_closure_call(struct CueClosure* closure_) {
    struct end_Closure* closure = (struct end_Closure*)closure_;
    closure->parser->cb(closure->parser, closure->scheduler, closure->error);
}

static void reset_word(char* word) { *(uint8_t*)&word[255] = 255; }

static int append_to_word(char* word, int c) {
    uint8_t* b = (uint8_t*)word;
    int len = 255 - b[255];
    if (len == 255) return 0;
    word[len++] = c;
    b[255] = 255 - len;
    return 1;
}

static int word_len(char* word) {
    uint8_t* b = (uint8_t*)word;
    return 255 - b[255];
}

static void end_word(char* word) {
    int len = word_len(word);
    word[len] = 0;
    reset_word(word);
}

void CueParser_construct(struct CueParser* parser, struct CueDisc* disc) {
    parser->disc = disc;
    parser->cursor = 0;
    reset_word(parser->word);
    parser->amount = 0;
    parser->state = CUE_PARSER_START;
    parser->inQuotes = 0;
    parser->afterQuotes = 0;
    parser->inRem = 0;
    parser->gotSpace = 1;
    parser->currentFileSize = 0;
    parser->currentFile = NULL;
    parser->currentTrack = 0;
    parser->currentSectorNumber = 0;
    parser->isTrackANewFile = 0;
    disc->catalog[0] = 0;
    disc->isrc[0] = 0;
    disc->trackCount = 0;
    for (unsigned i = 0; i < MAXTRACK; i++) {
        disc->tracks[i].file = NULL;
    }
    new_keyword(parser);
}

static void close_cb(struct CueFile* file, struct CueScheduler* scheduler) {
    struct CueParser* parser = file->user;
    parser->cb(parser, scheduler, NULL);
}

void CueParser_close(struct CueParser* parser, struct CueScheduler* scheduler,
                     void (*cb)(struct CueParser*, struct CueScheduler*, const char*)) {
    if (parser->currentFile) {
        if (--parser->currentFile->references) {
            parser->cb = cb;
            parser->currentFile->user = parser;
            parser->currentFile->close(parser->currentFile, scheduler, close_cb);
        }
    } else {
        parser->currentFile = NULL;
    }
}

void CueParser_destroy(struct CueParser* parser) {}

static int needs_argument(struct CueParser* parser) {
    switch (parser->state) {
        case CUE_PARSER_CATALOG:
        case CUE_PARSER_CDTEXTFILE:
        case CUE_PARSER_FILE_FILENAME:
        case CUE_PARSER_INDEX_NUMBER:
        case CUE_PARSER_INDEX_TIMECODE:
        case CUE_PARSER_ISRC:
        case CUE_PARSER_PERFORMER:
        case CUE_PARSER_POSTGAP:
        case CUE_PARSER_PREGAP:
        case CUE_PARSER_SONGWRITER:
        case CUE_PARSER_TITLE:
        case CUE_PARSER_TRACK_NUMBER:
            return 1;
    }
    return 0;
}

static void schedule_read(struct CueParser* parser, struct CueFile* file, struct CueScheduler* scheduler);
static void size_cb(struct CueFile* file, struct CueScheduler* scheduler, uint64_t size);

static int32_t timecodeToSectorNumber(char* timecode) {
    char* endptr;
    int min = strtol(timecode, &endptr, 10);
    if (*endptr != ':' || (min < 0) || (min >= 100)) {
        return -1;
    }
    int sec = strtol(endptr + 1, &endptr, 10);
    if (*endptr != ':' || (sec < 0) || (sec >= 60)) {
        return -1;
    }
    int fra = strtol(endptr + 1, &endptr, 10);
    if (*endptr || (fra < 0) || (fra >= 75)) {
        return -1;
    }
    return fra + sec * 75 + min * 60 * 75;
}

void end_parse(struct CueParser* parser, struct CueScheduler* scheduler, const char* error) {
    struct end_Closure* closure = malloc(sizeof(struct end_Closure));
    assert(closure);
    closure->destroy = closure_generic_free;
    closure->call = end_closure_call;
    closure->parser = parser;
    closure->error = error;
    Scheduler_schedule(scheduler, (struct CueClosure*)closure);
}

static void parse(struct CueParser* parser, struct CueFile* file, struct CueScheduler* scheduler) {
    while (parser->amount--) {
        int c = *parser->start++;
        int isEOW = isspace(c);
        int isEOL = (c == '\r') || (c == '\n');
        int isSpace = isEOW && !isEOL;
        if (!isEOW) keyword_add_char(parser, c);
        if (parser->inQuotes) {
            if (c == '"') {
                parser->inQuotes = 0;
                parser->afterQuotes = 1;
            } else {
                if (!append_to_word(parser->word, c)) {
                    end_parse(parser, scheduler, "cuesheet argument too long");
                    return;
                }
            }
            continue;
        }
        if (parser->inRem) {
            if (isEOL) parser->inRem = 0;
            continue;
        }
        if (parser->afterQuotes) {
            if (!isEOW) {
                end_parse(parser, scheduler, "cuesheet quote imbalance (got characters after quotes)");
                return;
            }
            parser->afterQuotes = 0;
        }
        if (!isEOW) {
            if (needs_argument(parser)) {
                if (c == '"') {
                    if (parser->gotSpace) {
                        parser->inQuotes = 1;
                    } else {
                        end_parse(parser, scheduler,
                                  "cuesheet quote imbalance (got a quote in the middle of an argument)");
                        return;
                    }
                } else if (!append_to_word(parser->word, c)) {
                    end_parse(parser, scheduler, "cuesheet argument too long");
                    return;
                }
            }
            parser->gotSpace = 0;
            continue;
        }
        parser->gotSpace = 1;
        enum Keyword keyword = parser->keyword;
        if ((keyword == KW_EMPTY) && isSpace) continue;
        int len = word_len(parser->word);
        if (needs_argument(parser)) end_word(parser->word);
        new_keyword(parser);
        switch (parser->state) {
            case CUE_PARSER_START:
                switch (keyword) {
                    case KW_EMPTY:
                        break;
                    case KW_REM:
                        parser->inRem = 1;
                        break;
                    case KW_CATALOG:
                        if (parser->disc->catalog[0]) {
                            end_parse(parser, scheduler, "cuesheet has too many CATALOG arguments");
                            return;
                        }
                        parser->state = CUE_PARSER_CATALOG;
                        break;
                    case KW_CDTEXTFILE:
                        parser->state = CUE_PARSER_CDTEXTFILE;
                        break;
                    case KW_FILE:
                        parser->state = CUE_PARSER_FILE_FILENAME;
                        break;
                    case KW_FLAGS:
                        parser->state = CUE_PARSER_FLAGS;
                        break;
                    case KW_INDEX:
                        parser->state = CUE_PARSER_INDEX_NUMBER;
                        break;
                    case KW_ISRC:
                        if (parser->disc->isrc[0]) {
                            end_parse(parser, scheduler, "cuesheet has too many ISRC arguments");
                            return;
                        }
                        parser->state = CUE_PARSER_ISRC;
                        break;
                    case KW_PERFORMER:
                        parser->state = CUE_PARSER_PERFORMER;
                        break;
                    case KW_POSTGAP:
                        parser->state = CUE_PARSER_POSTGAP;
                        break;
                    case KW_PREGAP:
                        parser->state = CUE_PARSER_PREGAP;
                        break;
                    case KW_SONGWRITER:
                        parser->state = CUE_PARSER_SONGWRITER;
                        break;
                    case KW_TITLE:
                        parser->state = CUE_PARSER_SONGWRITER;
                        break;
                    case KW_TRACK:
                        parser->state = CUE_PARSER_TRACK_NUMBER;
                        break;
                    default:
                        end_parse(parser, scheduler, "unknown keyword in cuesheet");
                        return;
                }
                break;
            case CUE_PARSER_CATALOG:
                if (len != 13) {
                    end_parse(parser, scheduler, "cuesheet CATALOG argument isn't 13 characters");
                    return;
                }
                memcpy(parser->disc->catalog, parser->word, 14);
                parser->state = CUE_PARSER_START;
                break;
            case CUE_PARSER_CDTEXTFILE:
                if (keyword == KW_EMPTY) {
                    end_parse(parser, scheduler, "cuesheet CDTEXTFILE missing its filename argument");
                    return;
                }
                parser->state = CUE_PARSER_START;
                end_parse(parser, scheduler, "cuesheet CDTEXTFILE not supported at the moment");
                return;
                break;
            case CUE_PARSER_FILE_FILENAME:
                if (keyword == KW_EMPTY) {
                    end_parse(parser, scheduler, "cuesheet FILE missing its filename argument");
                    return;
                } else {
                    struct CueFile* binaryFile = malloc(sizeof(struct CueFile));
                    assert(binaryFile);
                    binaryFile->user = file;
                    if (parser->isTrackANewFile) {
                        end_parse(parser, scheduler, "cuesheet has too many FILE without TRACK");
                        return;
                    }
                    if (parser->currentFile) {
                        if (parser->currentFile->references == 1) {
                            end_parse(parser, scheduler, "cuesheet has too many FILE without TRACK");
                            return;
                        }
                        parser->currentFile->references--;
                        parser->currentFile = NULL;
                    }
                    if (!parser->open(binaryFile, scheduler, parser->word)) {
                        binaryFile->destroy(binaryFile);
                        free(binaryFile);
                        end_parse(parser, scheduler, "cuesheet references a file that can't be found");
                        return;
                    }
                    parser->isTrackANewFile = 1;
                    parser->currentFile = binaryFile;
                }
                parser->state = CUE_PARSER_FILE_FILETYPE;
                break;
            case CUE_PARSER_FILE_FILETYPE:
                parser->state = CUE_PARSER_START;
                switch (keyword) {
                    case KW_EMPTY:
                        end_parse(parser, scheduler, "cuesheet FILE missing its filetype argument");
                        return;
                        break;
                    case KW_BINARY:
                        parser->currentFileType = CUE_FILE_TYPE_BINARY;
                        parser->currentFile->size(parser->currentFile, scheduler, 0, size_cb);
                        return;
                        break;
                    case KW_MOTOROLA:
                        parser->currentFileType = CUE_FILE_TYPE_MOTOROLA;
                        end_parse(parser, scheduler, "cuesheet FILETYPE MOTOROLA not supported at the moment");
                        return;
                        break;
                    case KW_AIFF:
                        parser->currentFileType = CUE_FILE_TYPE_AIFF;
                        end_parse(parser, scheduler, "cuesheet FILETYPE AIFF not supported at the moment");
                        return;
                        break;
                    case KW_WAVE:
                        parser->currentFileType = CUE_FILE_TYPE_WAVE;
                        parser->currentFile->size(parser->currentFile, scheduler, 1, size_cb);
                        return;
                        break;
                    case KW_MP3:
                        parser->currentFileType = CUE_FILE_TYPE_MP3;
                        parser->currentFile->size(parser->currentFile, scheduler, 1, size_cb);
                        return;
                        break;
                    default:
                        end_parse(parser, scheduler, "cuesheet unknown FILE filetype");
                        return;
                }
                break;
            case CUE_PARSER_FLAGS: {
                struct CueTrack* track = &parser->disc->tracks[parser->currentTrack];
                switch (keyword) {
                    case KW_EMPTY:
                        assert(isEOL);
                        parser->state = CUE_PARSER_START;
                        break;
                    case KW_DCP:
                        track->digitalCopyPermitted = 1;
                        break;
                    case KW_4CH:
                        track->fourChannelAudio = 1;
                        break;
                    case KW_PRE:
                        track->preEmphasis = 1;
                        break;
                    case KW_SCMS:
                        track->serialCopyManagementSystem = 1;
                        break;
                    default:
                        end_parse(parser, scheduler, "cuesheet FLAGS argument unknown");
                        return;
                }
            } break;
            case CUE_PARSER_INDEX_NUMBER: {
                if (keyword == KW_EMPTY) {
                    end_parse(parser, scheduler, "cuesheet INDEX missing index number argument");
                    return;
                }
                char* endptr;
                int indexNum = strtol(parser->word, &endptr, 10);
                if (*endptr || (indexNum < 0) || (indexNum >= MAXINDEX)) {
                    end_parse(parser, scheduler, "cuesheet INDEX number invalid");
                    return;
                }
                struct CueTrack* track = &parser->disc->tracks[parser->currentTrack];
                if ((track->indexCount == -1) & (indexNum == 1)) {
                    parser->implicitIndex = 1;
                } else if (track->indexCount != (indexNum - 1)) {
                    end_parse(parser, scheduler, "cuesheet INDEX not consecutive");
                    return;
                }
                track->indexCount = indexNum;
                track->compressed = parser->currentFileType != CUE_FILE_TYPE_BINARY;
                parser->state = CUE_PARSER_INDEX_TIMECODE;
            } break;
            case CUE_PARSER_INDEX_TIMECODE: {
                if (keyword == KW_EMPTY) {
                    end_parse(parser, scheduler, "cuesheet INDEX missing timecode argument");
                    return;
                }
                int32_t sectorNumber = timecodeToSectorNumber(parser->word);
                if (sectorNumber < 0) {
                    end_parse(parser, scheduler, "cuesheet INDEX timecode invalid");
                    return;
                }
                struct CueTrack* track = &parser->disc->tracks[parser->currentTrack];
                track->indices[track->indexCount] = parser->currentSectorNumber + sectorNumber;
                if (parser->implicitIndex) {
                    if (parser->currentTrack == 1) {
                        track->indices[0] = 0;
                    } else {
                        track->indices[0] = track->indices[1] - parser->currentPregap;
                        track->fileOffset += parser->currentPregap;
                        parser->currentSectorNumber += parser->currentPregap;
                    }
                    parser->implicitIndex = 0;
                }
                parser->state = CUE_PARSER_START;
            } break;
            case CUE_PARSER_ISRC:
                if (len != 12) {
                    end_parse(parser, scheduler, "cuesheet ISRC doesn't have 12 characters");
                    return;
                }
                memcpy(parser->disc->isrc, parser->word, 13);
                parser->state = CUE_PARSER_START;
                break;
            case CUE_PARSER_PERFORMER:
                if (keyword == KW_EMPTY) {
                    end_parse(parser, scheduler, "cuesheet PERFORMER missing its argument");
                    return;
                }
                parser->state = CUE_PARSER_START;
                end_parse(parser, scheduler, "cuesheet PERFORMER argument not supported at the moment");
                return;
                break;
            case CUE_PARSER_POSTGAP:
                if (keyword == KW_EMPTY) {
                    end_parse(parser, scheduler, "cuesheet POSTGAP missing its argument");
                    return;
                }
                parser->state = CUE_PARSER_START;
                end_parse(parser, scheduler, "cuesheet POSTGAP argument not supported at the moment");
                return;
                break;
            case CUE_PARSER_PREGAP: {
                if (keyword == KW_EMPTY) {
                    end_parse(parser, scheduler, "cuesheet PREGAP missing its argument");
                    return;
                }
                if (parser->currentTrack == 0) {
                    end_parse(parser, scheduler, "cuesheet PREGAP before any TRACK");
                    return;
                }
                struct CueTrack* track = &parser->disc->tracks[parser->currentTrack];
                if (track->indexCount != -1) {
                    end_parse(parser, scheduler, "cuesheet PREGAP after an INDEX");
                    return;
                }
                int32_t pregapLength = timecodeToSectorNumber(parser->word);
                if (pregapLength < 0) {
                    end_parse(parser, scheduler, "cuesheet PREGAP length invalid");
                    return;
                }
                parser->currentPregap = pregapLength;
                parser->state = CUE_PARSER_START;
            } break;
            case CUE_PARSER_SONGWRITER:
                if (keyword == KW_EMPTY) {
                    end_parse(parser, scheduler, "cuesheet SONGWRITER missing its argument");
                    return;
                }
                parser->state = CUE_PARSER_START;
                end_parse(parser, scheduler, "cuesheet SONGWRITER argument not supported at the moment");
                return;
                break;
            case CUE_PARSER_TITLE:
                if (keyword == KW_EMPTY) {
                    end_parse(parser, scheduler, "cuesheet TITLE missing its argument");
                    return;
                }
                parser->state = CUE_PARSER_START;
                end_parse(parser, scheduler, "cuesheet TITLE argument not supported at the moment");
                return;
                break;
            case CUE_PARSER_TRACK_NUMBER:
                if (keyword == KW_EMPTY) {
                    end_parse(parser, scheduler, "cuesheet TRACK missing its track number argument");
                    return;
                } else {
                    parser->state = CUE_PARSER_TRACK_DATATYPE;
                    char* endptr;
                    int trackNum = strtol(parser->word, &endptr, 10);
                    if (*endptr || (trackNum < 1) || (trackNum >= MAXTRACK)) {
                        end_parse(parser, scheduler, "cuesheet TRACK number invalid");
                        return;
                    }
                    if (parser->currentTrack != (trackNum - 1)) {
                        end_parse(parser, scheduler, "cuesheet TRACK not consecutive");
                        return;
                    }
                    parser->currentTrack = trackNum;
                    struct CueTrack* track = &parser->disc->tracks[trackNum];
                    if (track->file) {
                        end_parse(parser, scheduler, "cuesheet TRACK already exists");
                        return;
                    }
                    if (!parser->currentFile) {
                        end_parse(parser, scheduler, "cuesheet TRACK without a FILE first");
                        return;
                    }
                    track->file = parser->currentFile;
                    track->file->references++;
                    track->fileOffset = 0;
                    track->indexCount = -1;
                    track->postgap = 0;
                    track->size = 0;
                    track->trackType = TRACK_TYPE_UNKNOWN;
                    track->compressed = 0;
                    track->digitalCopyPermitted = 0;
                    track->fourChannelAudio = 0;
                    track->preEmphasis = 0;
                    track->serialCopyManagementSystem = 0;
                    parser->currentPregap = 0;
                    if (parser->isTrackANewFile) {
                        parser->currentSectorNumber += (parser->previousFileSize + 2351) / 2352;
                        parser->isTrackANewFile = 0;
                        track->fileOffset = parser->currentSectorNumber;
                    } else {
                        track->fileOffset = parser->disc->tracks[parser->currentTrack - 1].fileOffset;
                    }
                    parser->disc->trackCount = trackNum;
                }
                break;
            case CUE_PARSER_TRACK_DATATYPE:
                switch (keyword) {
                    case KW_AUDIO:
                        parser->disc->tracks[parser->currentTrack].trackType = TRACK_TYPE_AUDIO;
                        parser->state = CUE_PARSER_START;
                        break;
                    case KW_CDG:
                        end_parse(parser, scheduler, "cuesheet TRACK type CDG not supported at the moment");
                        parser->state = CUE_PARSER_START;
                        return;
                        break;
                    case KW_CDI_2336:
                        end_parse(parser, scheduler, "cuesheet TRACK type CDI_2336 not supported at the moment");
                        parser->state = CUE_PARSER_START;
                        return;
                        break;
                    case KW_CDI_2352:
                        end_parse(parser, scheduler, "cuesheet TRACK type CDI_2352 not supported at the moment");
                        parser->state = CUE_PARSER_START;
                        return;
                        break;
                    case KW_MODE1_2048:
                        end_parse(parser, scheduler, "cuesheet TRACK type MODE1_2048 not supported at the moment");
                        parser->state = CUE_PARSER_START;
                        return;
                        break;
                    case KW_MODE1_2352:
                        parser->disc->tracks[parser->currentTrack].trackType = TRACK_TYPE_DATA;
                        parser->state = CUE_PARSER_START;
                        break;
                    case KW_MODE2_2336:
                        end_parse(parser, scheduler, "cuesheet TRACK type MODE2_2336 not supported at the moment");
                        parser->state = CUE_PARSER_START;
                        return;
                        break;
                    case KW_MODE2_2352:
                        parser->disc->tracks[parser->currentTrack].trackType = TRACK_TYPE_DATA;
                        parser->state = CUE_PARSER_START;
                        break;
                    default:
                        end_parse(parser, scheduler, "cuesheet TRACK has unknown or missing datatype");
                        return;
                }
                break;
            default:
                end_parse(parser, scheduler, "cuesheet parser internal error");
                return;
        }
    }
    parser->amount = 0;
    schedule_read(parser, file, scheduler);
}

static void parse_eof(struct CueParser* parser, struct CueScheduler* scheduler) {
    if (parser->currentFile) {
        if (parser->currentFile->references == 1) {
            end_parse(parser, scheduler, "cuesheet has too many FILE without TRACK");
            return;
        }
        parser->currentFile->references--;
    }
    parser->currentFile = NULL;
    if (parser->disc->trackCount == 0) {
        end_parse(parser, scheduler, "cuesheet has no track");
        return;
    }
    for (unsigned i = 1; i < parser->disc->trackCount; i++) {
        struct CueTrack* track = &parser->disc->tracks[i];
        if (track->indexCount < 1) {
            end_parse(parser, scheduler, "cuesheet TRACK doesn't have enough indices");
            return;
        }
    }
    for (unsigned i = 2; i <= parser->disc->trackCount; i++) {
        struct CueTrack* prevTrack = &parser->disc->tracks[i - 1];
        struct CueTrack* track = &parser->disc->tracks[i];
        prevTrack->size = track->indices[0] - prevTrack->indices[0];
    }
    parser->currentSectorNumber += (parser->currentFileSize + 2351) / 2352;
    struct CueTrack* track = &parser->disc->tracks[parser->disc->trackCount];
    track->size = parser->currentSectorNumber - track->indices[0];
    end_parse(parser, scheduler, NULL);
}

static void read_bytes(struct CueFile* file, struct CueScheduler* scheduler, int error, uint32_t amount,
                       uint8_t* buffer) {
    struct CueParser* parser = file->user;
    if (amount == 0) {
        parse_eof(parser, scheduler);
    } else {
        parser->amount = amount;
        parser->cursor += amount;
        parse(parser, file, scheduler);
    }
}
static void size_cb(struct CueFile* binaryFile, struct CueScheduler* scheduler, uint64_t size) {
    struct CueFile* file = binaryFile->user;
    struct CueParser* parser = file->user;
    parser->previousFileSize = parser->currentFileSize;
    parser->currentFileSize = size;
    parse(parser, file, scheduler);
}

static void schedule_read(struct CueParser* parser, struct CueFile* file, struct CueScheduler* scheduler) {
    assert(parser->amount == 0);
    parser->start = parser->buffer;
    file->read(file, scheduler, sizeof(parser->buffer), parser->cursor, (uint8_t*)parser->buffer, read_bytes);
}

void CueParser_parse(struct CueParser* parser, struct CueFile* file, struct CueScheduler* scheduler,
                     struct CueFile* (*fileopen)(struct CueFile*, struct CueScheduler*, const char*),
                     void (*cb)(struct CueParser*, struct CueScheduler*, const char*)) {
    file->user = parser;
    parser->cb = cb;
    parser->open = fileopen;
    schedule_read(parser, file, scheduler);
}
