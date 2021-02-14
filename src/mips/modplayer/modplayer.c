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

#include "modplayer/modplayer.h"

#include <stddef.h>
#include <stdint.h>

#include "common/hardware/dma.h"
#include "common/hardware/spu.h"
#include "common/syscalls/syscalls.h"

/* This code is a reverse engineering of the file MODPLAY.BIN, located in the zip file
   "Asm-Mod" from http://hitmen.c02.at/html/psx_tools.html, that has the CRC32 bb91769f. */

struct MODSampleData {
    char name[22];
    union {
        uint16_t length;
        uint8_t lenarr[2];
    };
    uint8_t finetune;
    uint8_t volume;
    uint16_t repeatLocation;
    uint16_t repeatLength;
};

struct MODFileFormat {
    char title[20];
    struct MODSampleData samples[31];
    uint8_t songLength;
    uint8_t padding;
    uint8_t patternTable[128];
    uint8_t signature[4];
};

struct SPUChannelData {
    uint16_t note;
    int16_t period;
    uint16_t slideTo;
    uint8_t slideSpeed;
    uint8_t volume;
    uint8_t sampleID;
    int8_t vibrato;
    uint8_t fx[4];
    uint16_t samplePos;
};

struct SpuInstrumentData {
    uint16_t baseAddress;
    uint8_t finetune;
    uint8_t volume;
};

static struct SpuInstrumentData s_spuInstrumentData[31];

static void SPUInit() {
    DPCR |= 0x000b0000;
    SPU_VOL_MAIN_LEFT = 0x3800;
    SPU_VOL_MAIN_RIGHT = 0x3800;
    SPU_CTRL = 0;
    SPU_KEY_ON_LOW = 0;
    SPU_KEY_ON_HIGH = 0;
    SPU_KEY_OFF_LOW = 0xffff;
    SPU_KEY_OFF_HIGH = 0xffff;
    SPU_RAM_DTC = 4;
    SPU_VOL_CD_LEFT = 0;
    SPU_VOL_CD_RIGHT = 0;
    SPU_PITCH_MOD_LOW = 0;
    SPU_PITCH_MOD_HIGH = 0;
    SPU_NOISE_EN_LOW = 0;
    SPU_NOISE_EN_HIGH = 0;
    SPU_REVERB_EN_LOW = 0;
    SPU_REVERB_EN_HIGH = 0;
    SPU_VOL_EXT_LEFT = 0;
    SPU_VOL_EXT_RIGHT = 0;
    SPU_CTRL = 0x8000;
}

static void SPUResetVoice(int voiceID) {
    SPU_VOICES[voiceID].volumeLeft = 0;
    SPU_VOICES[voiceID].volumeRight = 0;
    SPU_VOICES[voiceID].sampleRate = 0;
    SPU_VOICES[voiceID].sampleStartAddr = 0;
    SPU_VOICES[voiceID].ad = 0x000f;
    SPU_VOICES[voiceID].currentVolume = 0;
    SPU_VOICES[voiceID].sampleRepeatAddr = 0;
    SPU_VOICES[voiceID].sr = 0x0000;
}

static void SPUUploadInstruments(uint32_t SpuAddr, const uint8_t* data, uint32_t size) {
    uint32_t bcr = size >> 6;
    if (size & 0x3f) bcr++;
    bcr <<= 16;
    bcr |= 0x10;

    SPU_RAM_DTA = SpuAddr >> 3;
    SPU_CTRL = (SPU_CTRL & ~0x0030) | 0x0020;
    while ((SPU_CTRL & 0x0030) != 0x0020)
        ;
    // original code erroneously was doing SBUS_DEV4_CTRL = SBUS_DEV4_CTRL;
    SBUS_DEV4_CTRL &= ~0x0f000000;
    DMA_CTRL[DMA_SPU].MADR = (uint32_t)data;
    DMA_CTRL[DMA_SPU].BCR = bcr;
    DMA_CTRL[DMA_SPU].CHCR = 0x01000201;

    while ((DMA_CTRL[DMA_SPU].CHCR & 0x01000000) != 0)
        ;
}

static void SPUUnMute() { SPU_CTRL = 0xc000; }

static void SPUSetVoiceVolume(int voiceID, uint16_t left, uint16_t right) {
    SPU_VOICES[voiceID].volumeLeft = left;
    SPU_VOICES[voiceID].volumeRight = right;
}

static void SPUSetStartAddress(int voiceID, uint32_t spuAddr) { SPU_VOICES[voiceID].sampleStartAddr = spuAddr >> 3; }

static void SPUWaitIdle() {
    do {
        for (unsigned c = 0; c < 2045; c++) __asm__ volatile("");
    } while ((SPU_STATUS & 0x07ff) != 0);
}

static void SPUKeyOn(uint32_t voiceBits) {
    SPU_KEY_ON_LOW = voiceBits;
    SPU_KEY_ON_HIGH = voiceBits >> 16;
}

static void SPUSetVoiceSampleRate(int voiceID, uint16_t sampleRate) { SPU_VOICES[voiceID].sampleRate = sampleRate; }

unsigned MOD_Check(const struct MODFileFormat* module) {
    if (syscall_strncmp(module->signature, "HIT", 3) == 0) {
        return module->signature[3] - '0';
    } else if (syscall_strncmp(module->signature, "HM", 2) == 0) {
        return ((module->signature[2] - '0') * 10) + module->signature[3] - '0';
    }
    return 0;
}

unsigned MOD_Channels = 0;
unsigned MOD_SongLength = 0;
// original code keeps this one to the very beginning of the file,
// while this code keeps the pointer to the beginning of the order table
static const uint8_t* MOD_ModuleData = NULL;
unsigned MOD_CurrentOrder = 0;
unsigned MOD_CurrentPattern = 0;
unsigned MOD_CurrentRow = 0;
unsigned MOD_Speed = 0;
unsigned MOD_Tick = 0;
// this never seems to be updated in the original code, which is a
// mistake; the F command handler was all wrong
unsigned MOD_BPM = 0;
// original code keeps this one to the NEXT row,
// while this code keeps the pointer to the CURRENT row
const uint8_t* MOD_RowPointer = NULL;
int MOD_ChangeRowNextTick = 0;
unsigned MOD_NextRow = 0;
int MOD_ChangeOrderNextTick = 0;
unsigned MOD_NextOrder = 0;
uint8_t MOD_PatternDelay = 0;
unsigned MOD_LoopStart = 0;
unsigned MOD_LoopCount = 0;
int MOD_Stereo = 0;
uint32_t MOD_hblanks;

// This function is now more of a helper to calculate the number of hsync
// values to wait until the next call to MOD_Poll. If the user wants to use
// another method, they will have to inspect MOD_BPM manually and make their
// own math based on their own timer.
static void MOD_SetBPM(unsigned bpm) {
    MOD_BPM = bpm;
    // The original code only uses 39000 here but the reality is a bit more
    // complex than that, as not all clocks are exactly the same, depending
    // on the machine's region, and the video mode selected.

    uint32_t status = GPU_STATUS;
    int isPalConsole = *((const char*)0xbfc7ff52) == 'E';
    int isPal = (status & 0x00100000) != 0;
    uint32_t base;
    if (isPal && isPalConsole) {          // PAL video on PAL console
        base = 39062;                     // 312.5 * 125 * 50.000 / 50 or 314 * 125 * 49.761 / 50
    } else if (isPal && !isPalConsole) {  // PAL video on NTSC console
        base = 39422;                     // 312.5 * 125 * 50.460 / 50 or 314 * 125 * 50.219 / 50
    } else if (!isPal && isPalConsole) {  // NTSC video on PAL console
        base = 38977;                     // 262.5 * 125 * 59.393 / 50 or 263 * 125 * 59.280 / 50
    } else {                              // NTSC video on NTSC console
        base = 39336;                     // 262.5 * 125 * 59.940 / 50 or 263 * 125 * 59.826 / 50
    }
    MOD_hblanks = base / bpm;
}

static struct SPUChannelData s_channelData[24];

uint32_t MOD_Load(const struct MODFileFormat* module) {
    SPUInit();
    MOD_Channels = MOD_Check(module);

    if (MOD_Channels == 0) return 0;

    uint32_t currentSpuAddress = 0x1010;
    for (unsigned i = 0; i < 31; i++) {
        s_spuInstrumentData[i].baseAddress = currentSpuAddress >> 4;
        s_spuInstrumentData[i].finetune = module->samples[i].finetune;
        s_spuInstrumentData[i].volume = module->samples[i].volume;
        currentSpuAddress += module->samples[i].lenarr[0] * 0x100 + module->samples[i].lenarr[1];
    }

    MOD_SongLength = module->songLength;

    unsigned maxPatternID = 0;
    for (unsigned i = 0; i < 128; i++) {
        if (maxPatternID < module->patternTable[i]) maxPatternID = module->patternTable[i];
    }

    MOD_ModuleData = (const uint8_t*)&module->patternTable[0];

    SPUUploadInstruments(0x1010, MOD_ModuleData + 4 + 128 + MOD_Channels * 0x100 * (maxPatternID + 1),
                         currentSpuAddress - 0x1010);

    MOD_CurrentOrder = 0;
    MOD_CurrentPattern = module->patternTable[0];
    MOD_CurrentRow = 0;
    MOD_Speed = 6;
    MOD_Tick = 6;
    MOD_RowPointer = MOD_ModuleData + 4 + 128 + MOD_CurrentPattern * MOD_Channels * 0x100;
    // original code goes only up to MOD_Channels; let's reset all 24
    for (unsigned i = 0; i < 24; i++) SPUResetVoice(i);
    MOD_ChangeRowNextTick = 0;
    MOD_ChangeOrderNextTick = 0;
    MOD_LoopStart = 0;
    MOD_LoopCount = 0;

    // these two are erroneously missing from the original code, at
    // least for being able to play more than one music
    MOD_PatternDelay = 0;
    syscall_memset(s_channelData, 0, sizeof(s_channelData));

    SPUUnMute();

    // this one is also missing, and is necessary, for being able to call MOD_Load
    // after another song that changed the tempo previously
    MOD_SetBPM(125);

    // the original code would do:
    // return MOD_Channels;
    // but we are returning the size for the MOD_Relocate call
    return 4 + 128 + MOD_Channels * 0x100 * (maxPatternID + 1);
}

void MOD_Relocate(uint8_t* s1) {
    if (MOD_ModuleData == s1) return;
    unsigned maxPatternID = 0;
    for (unsigned i = 0; i < 128; i++) {
        if (maxPatternID < MOD_ModuleData[i]) maxPatternID = MOD_ModuleData[i];
    }

    size_t n = 4 + 128 + MOD_Channels * 0x100 * (maxPatternID + 1);

    const uint8_t* s2 = MOD_ModuleData;
    size_t i;

    if (s1 < s2) {
        for (i = 0; i < n; i++) *s1++ = *s2++;
    } else if (s1 > s2) {
        s1 += n;
        s2 += n;
        for (i = 0; i < n; i++) *--s1 = *--s2;
    }

    MOD_ModuleData = s1;
}

static const uint8_t MOD_SineTable[32] = {
    0x00, 0x18, 0x31, 0x4a, 0x61, 0x78, 0x8d, 0xa1, 0xb4, 0xc5, 0xd4, 0xe0, 0xeb, 0xf4, 0xfa, 0xfd,
    0xff, 0xfd, 0xfa, 0xf4, 0xeb, 0xe0, 0xd4, 0xc5, 0xb4, 0xa1, 0x8d, 0x78, 0x61, 0x4a, 0x31, 0x18,
};

//   C    C#   D    D#   E    F    F#   G    G#   A    A#   B
const uint16_t MOD_PeriodTable[36 * 16] = {
    856, 808, 762, 720, 678, 640, 604, 570, 538, 508, 480, 453,  // octave 1 tune 0
    428, 404, 381, 360, 339, 320, 302, 285, 269, 254, 240, 226,  // octave 2 tune 0
    214, 202, 190, 180, 170, 160, 151, 143, 135, 127, 120, 113,  // octave 3 tune 0
    850, 802, 757, 715, 674, 637, 601, 567, 535, 505, 477, 450,  // octave 1 tune 1
    425, 401, 379, 357, 337, 318, 300, 284, 268, 253, 239, 225,  // octave 2 tune 1
    213, 201, 189, 179, 169, 159, 150, 142, 134, 126, 119, 113,  // octave 3 tune 1
    844, 796, 752, 709, 670, 632, 597, 563, 532, 502, 474, 447,  // octave 1 tune 2
    422, 398, 376, 355, 335, 316, 298, 282, 266, 251, 237, 224,  // octave 2 tune 2
    211, 199, 188, 177, 167, 158, 149, 141, 133, 125, 118, 112,  // octave 3 tune 2
    838, 791, 746, 704, 665, 628, 592, 559, 528, 498, 470, 444,  // octave 1 tune 3
    419, 395, 373, 352, 332, 314, 296, 280, 264, 249, 235, 222,  // octave 2 tune 3
    209, 198, 187, 176, 166, 157, 148, 140, 132, 125, 118, 111,  // octave 3 tune 3
    832, 785, 741, 699, 660, 623, 588, 555, 524, 495, 467, 441,  // octave 1 tune 4
    416, 392, 370, 350, 330, 312, 294, 278, 262, 247, 233, 220,  // octave 2 tune 4
    208, 196, 185, 175, 165, 156, 147, 139, 131, 124, 117, 110,  // octave 3 tune 4
    826, 779, 736, 694, 655, 619, 584, 551, 520, 491, 463, 437,  // octave 1 tune 5
    413, 390, 368, 347, 328, 309, 292, 276, 260, 245, 232, 219,  // octave 2 tune 5
    206, 195, 184, 174, 164, 155, 146, 138, 130, 123, 116, 109,  // octave 3 tune 5
    820, 774, 730, 689, 651, 614, 580, 547, 516, 487, 460, 434,  // octave 1 tune 6
    410, 387, 365, 345, 325, 307, 290, 274, 258, 244, 230, 217,  // octave 2 tune 6
    205, 193, 183, 172, 163, 154, 145, 137, 129, 122, 115, 109,  // octave 3 tune 6
    814, 768, 725, 684, 646, 610, 575, 543, 513, 484, 457, 431,  // octave 1 tune 7
    407, 384, 363, 342, 323, 305, 288, 272, 256, 242, 228, 216,  // octave 2 tune 7
    204, 192, 181, 171, 161, 152, 144, 136, 128, 121, 114, 108,  // octave 3 tune 7
    907, 856, 808, 762, 720, 678, 640, 604, 570, 538, 508, 480,  // octave 1 tune -8
    453, 428, 404, 381, 360, 339, 320, 302, 285, 269, 254, 240,  // octave 2 tune -8
    226, 214, 202, 190, 180, 170, 160, 151, 143, 135, 127, 120,  // octave 3 tune -8
    900, 850, 802, 757, 715, 675, 636, 601, 567, 535, 505, 477,  // octave 1 tune -7
    450, 425, 401, 379, 357, 337, 318, 300, 284, 268, 253, 238,  // octave 2 tune -7
    225, 212, 200, 189, 179, 169, 159, 150, 142, 134, 126, 119,  // octave 3 tune -7
    894, 844, 796, 752, 709, 670, 632, 597, 563, 532, 502, 474,  // octave 1 tune -6
    447, 422, 398, 376, 355, 335, 316, 298, 282, 266, 251, 237,  // octave 2 tune -6
    223, 211, 199, 188, 177, 167, 158, 149, 141, 133, 125, 118,  // octave 3 tune -6
    887, 838, 791, 746, 704, 665, 628, 592, 559, 528, 498, 470,  // octave 1 tune -5
    444, 419, 395, 373, 352, 332, 314, 296, 280, 264, 249, 235,  // octave 2 tune -5
    222, 209, 198, 187, 176, 166, 157, 148, 140, 132, 125, 118,  // octave 3 tune -5
    881, 832, 785, 741, 699, 660, 623, 588, 555, 524, 494, 467,  // octave 1 tune -4
    441, 416, 392, 370, 350, 330, 312, 294, 278, 262, 247, 233,  // octave 2 tune -4
    220, 208, 196, 185, 175, 165, 156, 147, 139, 131, 123, 117,  // octave 3 tune -4
    875, 826, 779, 736, 694, 655, 619, 584, 551, 520, 491, 463,  // octave 1 tune -3
    437, 413, 390, 368, 347, 328, 309, 292, 276, 260, 245, 232,  // octave 2 tune -3
    219, 206, 195, 184, 174, 164, 155, 146, 138, 130, 123, 116,  // octave 3 tune -3
    868, 820, 774, 730, 689, 651, 614, 580, 547, 516, 487, 460,  // octave 1 tune -2
    434, 410, 387, 365, 345, 325, 307, 290, 274, 258, 244, 230,  // octave 2 tune -2
    217, 205, 193, 183, 172, 163, 154, 145, 137, 129, 122, 115,  // octave 3 tune -2
    862, 814, 768, 725, 684, 646, 610, 575, 543, 513, 484, 457,  // octave 1 tune -1
    431, 407, 384, 363, 342, 323, 305, 288, 272, 256, 242, 228,  // octave 2 tune -1
    216, 203, 192, 181, 171, 161, 152, 144, 136, 128, 121, 114,  // octave 3 tune -1
};

#define SETVOICESAMPLERATE(channel, newPeriod) \
    SPUSetVoiceSampleRate(channel, ((7093789 / (newPeriod * 2)) << 12) / 44100)
#define SETVOICEVOLUME(channel, volume)             \
    volume <<= 8;                                   \
    if (MOD_Stereo) {                               \
        int pan = (channel & 1) ^ (channel >> 1);   \
        int16_t left = pan == 0 ? volume : 0;       \
        int16_t right = pan == 0 ? 0 : volume;      \
        SPUSetVoiceVolume(channel, left, right);    \
    } else {                                        \
        SPUSetVoiceVolume(channel, volume, volume); \
    }

static void MOD_UpdateEffect() {
    const uint8_t* rowPointer = MOD_RowPointer;
    const unsigned channels = MOD_Channels;
    for (unsigned channel = 0; channel < channels; channel++) {
        uint8_t effectNibble23 = rowPointer[3];
        uint8_t effectNibble1 = rowPointer[2] & 0x0f;
        uint8_t effectNibble2 = effectNibble23 & 0x0f;
        uint8_t effectNibble3 = effectNibble23 >> 4;

        uint8_t arpeggioTick;
        int32_t newPeriod;
        int16_t volume;
        uint16_t slideTo;
        uint8_t fx;
        uint32_t mutation;
        int8_t newValue;

        struct SPUChannelData* const channelData = &s_channelData[channel];

        switch (effectNibble1) {
            case 0:  // arpeggio
                if (effectNibble23 == 0) break;
                arpeggioTick = MOD_Tick;
                arpeggioTick %= 3;
                switch (arpeggioTick) {
                    case 0:
                        newPeriod = channelData->period;
                        break;
                    case 1:
                        newPeriod = MOD_PeriodTable[channelData->note + effectNibble3];
                        break;
                    case 2:
                        newPeriod = MOD_PeriodTable[channelData->note + effectNibble2];
                        break;
                }
                SETVOICESAMPLERATE(channel, newPeriod);
                break;
            case 1:  // portamento up
                newPeriod = channelData->period;
                newPeriod -= effectNibble23;
                if (newPeriod < 108) newPeriod = 108;
                channelData->period = newPeriod;
                SETVOICESAMPLERATE(channel, newPeriod);
                break;
            case 2:  // portamento down
                newPeriod = channelData->period;
                newPeriod += effectNibble23;
                if (newPeriod > 907) newPeriod = 907;
                channelData->period = newPeriod;
                SETVOICESAMPLERATE(channel, newPeriod);
                break;
            case 5:
                volume = channelData->volume;
                if (effectNibble23 <= 0x10) {
                    volume -= effectNibble23;
                    if (volume < 0) volume = 0;
                } else {
                    volume += effectNibble3;
                    if (volume > 63) volume = 63;
                }
                channelData->volume = volume;
                SETVOICEVOLUME(channel, volume);
                /* fall through */
            case 3:  // glissando
                newPeriod = channelData->period;
                slideTo = channelData->slideTo;
                if (newPeriod < slideTo) {
                    newPeriod += channelData->slideSpeed;
                    if (newPeriod > slideTo) newPeriod = slideTo;
                } else if (newPeriod > slideTo) {
                    newPeriod -= channelData->slideSpeed;
                    if (newPeriod < slideTo) newPeriod = slideTo;
                }
                channelData->period = newPeriod;
                SETVOICESAMPLERATE(channel, newPeriod);
                break;
            case 6:
                volume = channelData->volume;
                if (effectNibble23 <= 0x10) {
                    volume -= effectNibble23;
                    if (volume < 0) volume = 0;
                } else {
                    volume += effectNibble3;
                    if (volume > 63) volume = 63;
                }
                channelData->volume = volume;
                SETVOICEVOLUME(channel, volume);
                /* fall through */
            case 4:  // vibrato
                mutation = channelData->vibrato & 0x1f;
                switch (channelData->fx[3] & 3) {
                    case 0:
                    case 3:  // 3 is technically random
                        mutation = MOD_SineTable[mutation];
                        break;
                    case 1:
                        if (channelData->vibrato < 0) {
                            mutation *= -8;
                            mutation += 0xff;
                        } else {
                            mutation *= 8;
                        }
                        break;
                    case 2:
                        mutation = 0xff;
                        break;
                }
                mutation *= channelData->fx[1] >> 4;
                mutation >>= 7;
                newPeriod = channelData->period;
                if (channelData->vibrato < 0) {
                    newPeriod -= mutation;
                } else {
                    newPeriod += mutation;
                }
                newValue = channelData->vibrato;
                newValue += channelData->fx[1] & 0x0f;
                if (newValue >= 32) newValue -= 64;
                channelData->vibrato = newValue;
                SETVOICESAMPLERATE(channel, newPeriod);
                break;
            case 7:  // tremolo
                mutation = s_channelData[0].fx[0] & 0x1f;
                switch (s_channelData[0].fx[3] & 3) {
                    case 0:
                    case 3:  // 3 is technically random
                        mutation = MOD_SineTable[mutation];
                        break;
                    case 1:
                        if (channelData->fx[0] & 0x80) {
                            mutation *= -8;
                            mutation += 0xff;
                        } else {
                            mutation *= 8;
                        }
                        break;
                    case 2:
                        mutation = 0xff;
                        break;
                }
                mutation *= channelData->fx[3] >> 4;
                mutation >>= 6;
                volume = channelData->volume;
                if (channelData->fx[0] & 0x80) {
                    volume -= mutation;
                } else {
                    volume += mutation;
                }
                newValue = channelData->fx[0] + (channelData->fx[2] & 0x0f);
                if (newValue >= 32) newValue -= 64;
                channelData->fx[0] = newValue;
                if (volume > 63) volume = 63;
                SETVOICEVOLUME(channel, volume);
                break;
            case 10:  // volume slide
                volume = channelData->volume;
                if (effectNibble23 <= 0x10) {
                    volume -= effectNibble23;
                    if (volume < 0) volume = 0;
                } else {
                    volume += effectNibble3;
                    if (volume > 63) volume = 63;
                }
                channelData->volume = volume;
                SETVOICEVOLUME(channel, volume);
                break;
            case 14:  // extended
                switch (effectNibble3) {
                    case 9:  // retrigger sample
                        // this doesn't look right, we probably want to reset the sample location
                        if ((MOD_Tick % effectNibble2) == 0) SPUKeyOn(1 << channel);
                        break;
                    case 12:  // cut sample
                        if (MOD_Tick != effectNibble2) break;
                        channelData->volume = 0;
                        SPUSetVoiceVolume(channel, 0, 0);
                }
                break;
        }

        rowPointer += 4;
    }
}

static void MOD_UpdateRow() {
    const unsigned channels = MOD_Channels;
    if (MOD_ChangeOrderNextTick) {
        unsigned newOrder = MOD_NextOrder;
        if (newOrder >= MOD_SongLength) newOrder = 0;
        MOD_CurrentRow = 0;
        MOD_CurrentOrder = newOrder;
        MOD_CurrentPattern = MOD_ModuleData[newOrder];
    }
    if (MOD_ChangeRowNextTick) {
        unsigned newRow = (MOD_NextRow >> 4) * 10 + (MOD_NextRow & 0x0f);
        if (newRow >= 64) newRow = 0;
        MOD_CurrentRow = newRow;
        if (MOD_ChangeOrderNextTick) {
            if (++MOD_CurrentOrder >= MOD_SongLength) MOD_CurrentOrder = 0;
            MOD_CurrentPattern = MOD_ModuleData[MOD_CurrentOrder];
        }
    }
    MOD_ChangeRowNextTick = 0;
    MOD_ChangeOrderNextTick = 0;
    MOD_RowPointer =
        MOD_ModuleData + 128 + 4 + MOD_CurrentPattern * MOD_Channels * 0x100 + MOD_CurrentRow * channels * 4;
    const uint8_t* rowPointer = MOD_RowPointer;

    for (unsigned channel = 0; channel < channels; channel++) {
        int16_t volume;
        struct SPUChannelData* const channelData = &s_channelData[channel];

        uint8_t effectNibble1 = rowPointer[2];
        uint8_t effectNibble23 = rowPointer[3];
        uint16_t nibble0 = rowPointer[0];
        unsigned sampleID = (nibble0 & 0xf0) | (effectNibble1 >> 4);
        uint8_t effectNibble2 = effectNibble23 & 0x0f;
        uint8_t effectNibble3 = effectNibble23 >> 4;
        unsigned period = ((nibble0 & 0x0f) << 8) | rowPointer[1];
        int32_t newPeriod;
        uint8_t fx;
        effectNibble1 &= 0x0f;

        if (effectNibble1 != 9) channelData->samplePos = 0;
        if (sampleID != 0) {
            channelData->sampleID = --sampleID;
            volume = s_spuInstrumentData[sampleID].volume;
            if (volume > 63) volume = 63;
            channelData->volume = volume;
            if (effectNibble1 != 7) {
                SETVOICEVOLUME(channel, volume);
            }
            SPUSetStartAddress(channel, s_spuInstrumentData[sampleID].baseAddress << 4 + channelData->samplePos);
        }

        if (period != 0) {
            int periodIndex;
            // original code erroneously does >= 0
            for (periodIndex = 35; periodIndex--; periodIndex > 0) {
                if (MOD_PeriodTable[periodIndex] == period) break;
            }
            channelData->note = periodIndex + s_spuInstrumentData[channelData->sampleID].finetune * 36;
            fx = channelData->fx[3];
            if ((fx & 0x0f) < 4) {
                channelData->vibrato = 0;
            }
            if ((fx >> 4) < 4) {
                channelData->fx[0] = 0;
            }
            if ((effectNibble1 != 3) && (effectNibble1 != 5)) {
                SPUWaitIdle();
                SPUKeyOn(1 << channel);
                channelData->period = MOD_PeriodTable[channelData->note];
            }
            newPeriod = channelData->period;
            SETVOICESAMPLERATE(channel, newPeriod);
        }

        switch (effectNibble1) {
            case 3:  // glissando
                if (effectNibble23 != 0) {
                    channelData->slideSpeed = effectNibble23;
                }
                if (period != 0) {
                    channelData->slideTo = MOD_PeriodTable[channelData->note];
                }
                break;
            case 4:  // vibrato
                if (effectNibble3 != 0) {
                    fx = channelData->fx[1];
                    fx &= ~0x0f;
                    fx |= effectNibble3;
                    channelData->fx[1] = fx;
                }
                if (effectNibble2 != 0) {
                    fx = channelData->fx[1];
                    fx &= ~0xf0;
                    fx |= effectNibble3 << 4;
                    channelData->fx[1] = fx;
                }
                break;
            case 7:  // tremolo
                if (effectNibble3 != 0) {
                    fx = channelData->fx[2];
                    fx &= ~0x0f;
                    fx |= effectNibble3;
                    channelData->fx[2] = fx;
                }
                if (effectNibble2 != 0) {
                    fx = channelData->fx[2];
                    fx &= ~0xf0;
                    fx |= effectNibble2 << 4;
                    channelData->fx[2] = fx;
                }
                break;
            case 9:  // sample jump
                if (effectNibble23 != 0) {
                    uint16_t newSamplePos = effectNibble23;
                    channelData->samplePos = newSamplePos << 7;
                }
                break;
            case 11:  // order jump
                if (!MOD_ChangeOrderNextTick) {
                    MOD_ChangeOrderNextTick = 1;
                    MOD_NextOrder = effectNibble23;
                }
                break;
            case 12:  // set volume
                volume = effectNibble23;
                if (volume > 64) volume = 63;
                channelData->volume = volume;
                SETVOICEVOLUME(channel, volume);
                break;
            case 13:  // pattern break
                if (!MOD_ChangeRowNextTick) {
                    MOD_ChangeRowNextTick = 1;
                    MOD_NextRow = effectNibble23;
                }
                break;
            case 14:  // extended
                switch (effectNibble3) {
                    case 1:  // fineslide up
                        newPeriod = channelData->period;
                        newPeriod -= effectNibble2;
                        channelData->period = newPeriod;
                        SETVOICESAMPLERATE(channel, newPeriod);
                        break;
                    case 2:  // fineslide down
                        newPeriod = channelData->period;
                        newPeriod += effectNibble2;
                        channelData->period = newPeriod;
                        SETVOICESAMPLERATE(channel, newPeriod);
                        break;
                    case 4:  // set vibrato waveform
                        fx = channelData->fx[3];
                        fx &= ~0x0f;
                        fx |= effectNibble2;
                        channelData->fx[3] = fx;
                        break;
                    case 5:  // set finetune value
                        s_spuInstrumentData[sampleID].finetune = effectNibble2;
                        break;
                    case 6:  // loop pattern
                        if (MOD_LoopCount-- == 0) {
                            MOD_LoopCount = effectNibble2;
                        }
                        if (MOD_LoopCount != 0) {
                            MOD_CurrentRow = MOD_LoopStart;
                        }
                        break;
                    case 7:  // set tremolo waveform
                        fx = channelData->fx[3];
                        fx &= ~0xf0;
                        fx |= effectNibble2 << 4;
                        channelData->fx[3] = fx;
                        break;
                    case 10:  // fine volume up
                        volume = channelData->volume;
                        volume += effectNibble2;
                        if (volume > 63) volume = 63;
                        channelData->volume = volume;
                        SETVOICEVOLUME(channel, volume);
                        break;
                    case 11:  // fine volume down
                        volume = channelData->volume;
                        volume -= effectNibble2;
                        if (volume < 0) volume = 0;
                        channelData->volume = volume;
                        SETVOICEVOLUME(channel, volume);
                        break;
                    case 14:  // delay pattern
                        MOD_PatternDelay = effectNibble2;
                        break;
                }
                break;
            case 15:  // set speed
                // the original code here is very wrong with regards to
                // how to interpret the command; also it was very opinionated
                // about using timer1 for its clock source
                if (effectNibble23 == 0) break;
                if (effectNibble23 < 32) {
                    MOD_Speed = effectNibble23;
                } else {
                    MOD_SetBPM(effectNibble23);
                }
                break;
        }

        rowPointer += 4;
    }
}

void MOD_Poll() {
    // the original code is getting the delay pattern wrong here, and
    // isn't processing them as actual line delays, rather as a sort
    // of ticks delay, and was basically going too fast
    uint8_t newPatternDelay = MOD_PatternDelay;
    if (++MOD_Tick < MOD_Speed) {
        MOD_UpdateEffect();
    } else {
        MOD_Tick = 0;
        if (newPatternDelay-- == 0) {
            MOD_UpdateRow();
            newPatternDelay = MOD_PatternDelay;
            // I don't think the original code was handling this properly...
            if (++MOD_CurrentRow >= 64 || MOD_ChangeRowNextTick) {
                MOD_CurrentRow = 0;
                if (++MOD_CurrentOrder >= MOD_SongLength) {
                    MOD_CurrentOrder = 0;
                }
                MOD_CurrentPattern = MOD_ModuleData[MOD_CurrentOrder];
            }
        } else {
            MOD_UpdateEffect();
        }
    }
    MOD_PatternDelay = newPatternDelay;
}

void MOD_PlayNote(unsigned channel, unsigned sampleID, unsigned note, int16_t volume) {
    if (volume < 0) volume = 0;
    if (volume > 63) volume = 63;
    struct SPUChannelData* const channelData = &s_channelData[channel];
    channelData->samplePos = 0;
    SPUSetVoiceVolume(channel, volume << 8, volume << 8);
    SPUSetStartAddress(channel, s_spuInstrumentData[sampleID].baseAddress << 4 + channelData->samplePos);
    SPUWaitIdle();
    SPUKeyOn(1 << channel);
    channelData->note = note = note + s_spuInstrumentData[sampleID].finetune * 36;
    int32_t newPeriod = channelData->period = MOD_PeriodTable[note];
    SETVOICESAMPLERATE(channel, newPeriod);
}
