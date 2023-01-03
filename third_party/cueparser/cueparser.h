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

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

struct CueDisc;
struct CueFile;
struct CueScheduler;

enum CueParserState {
    CUE_PARSER_START,
    CUE_PARSER_CATALOG,
    CUE_PARSER_CDTEXTFILE,
    CUE_PARSER_FILE_FILENAME,
    CUE_PARSER_FILE_FILETYPE,
    CUE_PARSER_FLAGS,
    CUE_PARSER_INDEX_NUMBER,
    CUE_PARSER_INDEX_TIMECODE,
    CUE_PARSER_ISRC,
    CUE_PARSER_PERFORMER,
    CUE_PARSER_POSTGAP,
    CUE_PARSER_PREGAP,
    CUE_PARSER_SONGWRITER,
    CUE_PARSER_TITLE,
    CUE_PARSER_TRACK_NUMBER,
    CUE_PARSER_TRACK_DATATYPE,
};

enum CueFileType {
    CUE_FILE_TYPE_BINARY,
    CUE_FILE_TYPE_MOTOROLA,
    CUE_FILE_TYPE_AIFF,
    CUE_FILE_TYPE_WAVE,
    CUE_FILE_TYPE_MP3,
};

struct CueParser {
    struct CueDisc* disc;
    int gotSpace;
    int inQuotes;
    int afterQuotes;
    int inRem;
    void (*cb)(struct CueParser*, struct CueScheduler*, const char* error);
    char buffer[256];  // adjustable without issue
    char* start;
    unsigned amount;
    char word[256];  // non-adjustable
    uint32_t keyword;
    enum CueParserState state;
    uint64_t cursor;
    void* user;
    struct CueFile* (*open)(struct CueFile*, struct CueScheduler*, const char*);
    struct CueFile* currentFile;
    enum CueFileType currentFileType;
    uint64_t previousFileSize;
    uint64_t currentFileSize;
    unsigned currentTrack;
    uint32_t currentSectorNumber;
    int implicitIndex;
    int isTrackANewFile;
    uint32_t currentPregap;
};

void CueParser_construct(struct CueParser*, struct CueDisc*);
void CueParser_close(struct CueParser*, struct CueScheduler*,
                     void (*)(struct CueParser*, struct CueScheduler*, const char* error));
void CueParser_destroy(struct CueParser*);
void CueParser_parse(struct CueParser* parser, struct CueFile* file, struct CueScheduler* scheduler,
                     struct CueFile* (*fileopen)(struct CueFile*, struct CueScheduler*, const char* filename),
                     void (*cb)(struct CueParser*, struct CueScheduler*, const char* error));

#ifdef __cplusplus
}
#endif
