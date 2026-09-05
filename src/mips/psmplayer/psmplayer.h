/*

MIT License

Copyright (c) 2025 PCSX-Redux authors

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

#include <stdint.h>

// PSM Player - Real-time MIDI playback via PSM event stream + VAB instrument bank
//
// Usage:
//   1. PSM_LoadBank(vabData, vabSize)  - parse VAB, DMA samples to SPU RAM
//   2. PSM_LoadSong(psmData, psmSize)  - parse PSM header, point to event array
//   3. Poll with hblank timer using PSM_hblanks interval
//   4. PSM_Poll() each tick to advance playback
//
// The player allocates voices 0 through (PSM_voiceCount-1) for music.
// Voices above PSM_voiceCount are available for sound effects.

// Number of hblank ticks between PSM_Poll() calls.
// Updated when the song contains tempo changes.
extern uint32_t PSM_hblanks;

// Maximum voices used for music playback (default 16, set before PSM_LoadSong).
extern unsigned PSM_voiceCount;

// Current event index (read-only, for display/debugging).
extern uint32_t PSM_currentEvent;

// Total event count in current song.
extern uint32_t PSM_eventCount;

// 1 if playback is active, 0 if stopped/finished.
extern int PSM_playing;

// Load a combined VAB file (VH header + VB sample body in one buffer).
// Parses the header, program/tone tables, and DMA uploads all VAG
// sample data to SPU RAM starting at 0x1010.
// Returns the number of programs, or 0 on failure.
unsigned PSM_LoadBank(const void* vabData, uint32_t vabSize);

// Load a VAB with separate VH (header) and VB (sample body) buffers.
// The VB buffer contains only the raw concatenated VAG ADPCM data and
// can be freed after this call returns - it is DMA'd to SPU RAM during
// loading. If vbData is NULL, samples are assumed to already be in SPU
// RAM (e.g. from a previous call).
// Returns the number of programs, or 0 on failure.
unsigned PSM_LoadBankEx(const void* vhData, uint32_t vhSize,
                        const void* vbData, uint32_t vbSize);

// Load a PSM event stream for playback. Must be called after PSM_LoadBank.
// Returns the event count, or 0 on failure.
uint32_t PSM_LoadSong(const void* psmData, uint32_t psmSize);

// Advance playback by one tick. Call this at the rate indicated by PSM_hblanks.
void PSM_Poll(void);

// Stop all playback and silence all voices.
void PSM_Silence(void);
