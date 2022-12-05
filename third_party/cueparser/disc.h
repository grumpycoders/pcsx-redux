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

struct CueFile;

#ifndef MAXTRACK
#define MAXTRACK 100
#endif

#ifndef MAXINDEX
#define MAXINDEX 100
#endif

enum CueTrackType { TRACK_TYPE_UNKNOWN, TRACK_TYPE_AUDIO, TRACK_TYPE_DATA };

struct CueTrack {
    struct CueFile* file;
    uint32_t size;        // size of the track in sectors, including pregaps and postgaps
    uint32_t fileOffset;  // offset in sectors within the disc at which this file begins
    int indexCount;
    uint32_t indices[MAXINDEX];  // each index is an absolute value in sectors from the beginning
                                 // of the disc; adjust using fileOffset
                                 // index 0 is for the pregap, and shouldn't be considered
                                 // physically present within the data files
                                 // the lead-in isn't taken into account
    uint32_t postgap;            // size of the postgap in sectors
    enum CueTrackType trackType;
    int compressed;
};

struct CueDisc {
    int trackCount;
    struct CueTrack tracks[MAXTRACK];  // track 0 isn't valid; technically can be considered the lead-in
    char catalog[14];
    char isrc[13];
};

#ifdef __cplusplus
}
#endif