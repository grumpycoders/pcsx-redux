/*

MIT License

Copyright (c) 2021 PCSX-Redux authors

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

// Once MOD_Load returns, these values will be valid.
// Unless specified, consider them read only, but
// modifying them might be doable if you know what you are doing.
extern unsigned MOD_Channels;
extern unsigned MOD_SongLength;
extern unsigned MOD_CurrentOrder;
extern unsigned MOD_CurrentPattern;
extern unsigned MOD_CurrentRow;
extern unsigned MOD_Speed;
extern unsigned MOD_Tick;
extern unsigned MOD_BPM;
extern unsigned MOD_LoopStart;
extern unsigned MOD_LoopCount;
extern uint8_t MOD_PatternDelay;

// This is a pointer to the current row that's
// being played. Used for decoding. The number
// of relevant bytes for a row is 4 * MOD_Channels.
extern const uint8_t* MOD_RowPointer;

// These four are fine to change outside of MOD_Poll.
// The first two are booleans, and the next two are the values
// you need them to be set at when MOD_Poll is called next.
// If you need immediate row / pattern change, also set
// MOD_Tick to MOD_Speed.
extern int MOD_ChangeRowNextTick;
extern int MOD_ChangeOrderNextTick;
extern unsigned MOD_NextRow;
extern unsigned MOD_NextOrder;

// This can be used to decode MOD_RowPointer.
extern const uint16_t MOD_PeriodTable[];

// Internal HIT file structure, but conformant to
// http://www.aes.id.au/modformat.html
struct MODFileFormat;

// Returns the number of channel from this module,
// or 0 if the module is invalid.
unsigned MOD_Check(const struct MODFileFormat* module);

// Loads the specified module and gets it ready for
// playback. Returns the number of bytes needed if
// relocation is desired. The pointer has to be
// aligned to a 4-bytes boundary. Will also setup
// the SPU.
uint32_t MOD_Load(const struct MODFileFormat* module);

// Call this function periodically to play sound. The
// frequency at which this is called will determine the
// actual playback speed of the module. Most modules will
// not change the default tempo, which requires calling
// MOD_Poll 50 times per second, or exactly the vertical
// refresh rate in PAL. Preferably call this from timer1's
// IRQ however, and look up MOD_hblanks to decide of the
// next target value to use.
// To pause or stop playback, simply stop calling this
// function. The internal player doesn't need any
// sort of cleanup, and switching to another song simply
// requires calling MOD_Load with a new file.
void MOD_Poll();

// New APIs from the original code from there on.

// Defaults to 0. This is a boolean indicating if we
// want the volume settings to be monaural or the same
// as the original Amiga's Paula chip.
extern int MOD_Stereo;

// Indicates the number of hblank ticks to wait before
// calling MOD_Poll. This value may or may not change
// after a call to MOD_Poll, if the track requested a
// tempo change.
extern uint32_t MOD_hblanks;

// It is possible to reclaim memory from the initial call
// to MOD_Load, in case the module was loaded from an
// external source. The number of bytes needed for the
// player will be returned by MOD_Load. Call MOD_Relocate
// with a new memory buffer that has at least this many bytes.
// Caller is responsible for managing the memory.
// It is fine to reuse the same buffer as the original input,
// if you wish to simply realloc it after relocating it,
// provided your realloc implementation guarantees that the
// shrunk buffer will remain at the same location.
//
// For example, this pseudo-code is valid:
// bool load_mod_file(File mod_file) {
//   void * buffer = malloc(file_size(mod_file));
//   readfile(mod_file, buffer);
//   uint32_t size = MOD_Load(buffer);
//   if (size == 0) {
//     free(buffer);
//     return false;
//   }
//   MOD_Relocate(buffer);
//   void * newbuffer = realloc(buffer, size);
//   if (newbuffer != buffer) {
//     free(newbuffer);
//     return false;
//   }
//   return true;
// }
void MOD_Relocate(uint8_t* buffer);

// Set MOD Volume to musicVolume, where musicVolume is between 0 and 65535.
// Defaults to 16384, and won't be reset by a subsequent MOD_Load, as it
// behaves as a master music volume throughout the lifetime of the app.
void MOD_SetMusicVolume(uint32_t musicVolume);

// Plays an arbitrary note from the MOD's samples bank.
// The volume will always be centered, so the sample will
// be monaural. The voiceID ideally should be set to a
// value that is above MOD_Channels. Remember the PS1
// has 24 channels total, so voiceID can be between 0 and 23.
// The note is a value between 0 and 35. The exact note played
// is on the normal 12-notes, C, C#, D, ... scale, and there
// are three octaves available, which gives the 12*3=36
// interval value of the note argument. The volume argument
// is between 0 and 63. You can simulate KeyOff by simply
// setting the volume of the voice to 0. The volume will
// be affected by the music volume as set by the function above.
void MOD_PlayNote(unsigned voiceID, unsigned sampleID, unsigned note, int16_t volume);

// Plays a sound effect.
// As opposed to MOD_PlayNote(), MOD_PlaySoundEffect()'s volume
// won't be affected by the global volume setting.
// 0 == mute, 63 == max SPU voice volume
void MOD_PlaySoundEffect(unsigned channel, unsigned sampleID, unsigned note, int16_t volume);

// Added API to reset the SPU and silence everything.
void MOD_Silence();
