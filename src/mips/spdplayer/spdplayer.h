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

// Once SPD_Load returns, these values will be valid.
extern unsigned SPD_VoiceCount;
extern unsigned SPD_OrderCount;
extern unsigned SPD_CurrentOrder;
extern unsigned SPD_PatternCount;
extern unsigned SPD_SampleCount;

// Indicates the number of hblank ticks to wait before
// calling SPD_Poll. This value may change after a call
// to SPD_Poll if the stream contains a tick rate change.
extern uint32_t SPD_hblanks;

// Validates an SPUDUMP file. Returns 1 if valid, 0 if not.
unsigned SPD_Check(const void* data, uint32_t size);

// Loads the specified SPUDUMP file and gets it ready for
// playback. Uploads sample data to SPU RAM and parses the
// order table and pattern offsets. Returns the voice count,
// or 0 if the file is invalid.
unsigned SPD_Load(const void* data, uint32_t size);

// Loads the specified SPUDUMP file with separate sample data.
// The sampleData pointer contains the raw sample data file
// (a standalone SPUDUMP file containing only sample directory
// and sample data packets). The sampleData buffer can be freed
// after this call returns, as it is DMA'd to SPU RAM during
// loading. If sampleData is NULL, the function assumes samples
// are already loaded in SPU RAM (e.g. from a previous call).
// Returns the voice count, or 0 if invalid.
unsigned SPD_LoadEx(const void* data, uint32_t size,
                    const void* sampleData, uint32_t sampleSize);

// Call this function periodically to play sound. The
// frequency at which this is called is determined by the
// tick rate embedded in the file. Use SPD_hblanks with
// timer1's hblank counter to determine when to call next.
// To pause playback, simply stop calling this function.
void SPD_Poll();

// Seek to a specific order position. The pattern at the
// given order is entered cold using its SPU state snapshot.
// Playback continues from the start of that pattern on the
// next call to SPD_Poll.
void SPD_Seek(unsigned order);

// These are fine to change outside of SPD_Poll.
// SPD_ChangeOrderNextTick is a boolean; SPD_NextOrder is
// the target order index. Setting the boolean causes the
// player to jump to the specified order on the next tick.
extern int SPD_ChangeOrderNextTick;
extern unsigned SPD_NextOrder;

// Set master volume (0-65535). Defaults to 16384.
// Not reset by subsequent SPD_Load calls.
void SPD_SetMasterVolume(uint32_t volume);

// Play a sound effect on a spare voice (above SPD_VoiceCount).
// The pitch is a raw SPU sample rate register value (0x1000 = 44100 Hz).
// Volume is 0-16383. The voice must be >= SPD_VoiceCount.
void SPD_PlaySoundEffect(unsigned voice, unsigned sampleID, uint16_t pitch, int16_t volume);

// Stop all playback and reset the SPU.
void SPD_Silence();
