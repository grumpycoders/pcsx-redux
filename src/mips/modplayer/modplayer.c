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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common/hardware/dma.h"
#include "common/hardware/hwregs.h"
#include "common/hardware/spu.h"

/* This code is a reverse engineering of the file MODPLAY.BIN, located in the zip file
   "Asm-Mod" from http://hitmen.c02.at/html/psx_tools.html, that has the CRC32 bb91769f. */

struct MODSampleData {
    char name[22];
    uint16_t length;
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

static void SPUUploadInstruments(uint32_t SpuAddr, uint32_t* data, uint32_t size) {
    uint32_t bcr = size >> 6;
    if (size & 0x3f) bcr++;
    bcr <<= 16;
    bcr |= 0x10;

    SPU_RAM_DTA = SpuAddr >> 3;
    SPU_CTRL = (SPU_CTRL & ~0x0030) | 0x0020;
    while ((SPU_CTRL & 0x0030) != 0x0020)
        ;
    SBUS_DEV4_CTRL = SBUS_DEV4_CTRL;  // ah?
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
    if (strncmp(module->signature, "HIT", 3) == 0) {
        return module->signature[3] - '0';
    } else if (strncmp(module->signature, "HM", 2) == 0) {
        return ((module->signature[2] - '0') * 10) + module->signature[3] - '0';
    }
    return 0;
}

int TimerSetTarget(int timerID, uint16_t target, uint32_t flags) {
    if (timerID >= 3) return 0;
    uint32_t mode = timerID == 2 ? 0x248 : 0x148;
    COUNTERS[timerID].mode = 0;
    COUNTERS[timerID].target = target;
    if (flags & 0x1000) mode |= 0x0010;
    COUNTERS[timerID].mode = mode;
    return 1;
}

unsigned MOD_Channels = 0;
unsigned MOD_SongLength = 0;
const uint8_t* MOD_ModuleData = NULL;
unsigned MOD_CurrentOrder = 0;
unsigned MOD_CurrentPattern = 0;
unsigned MOD_CurrentRow = 0;
unsigned MOD_Speed = 0;
unsigned MOD_Tick = 0;
unsigned MOD_BPM = 0;
const uint8_t* MOD_RowPointer = NULL;
int MOD_ChangeRowNextTick = 0;
unsigned MOD_NextRow = 0;
int MOD_ChangeOrderNextTick = 0;
unsigned MOD_NextOrder = 0;
uint8_t MOD_PatternDelay = 0;
unsigned MOD_LoopStart = 0;
unsigned MOD_LoopCount = 0;
static struct SPUChannelData s_channelData[24];

unsigned MOD_Load(const struct MODFileFormat* module) {
    SPUInit();
    MOD_Channels = MOD_Check(module);

    if (MOD_Channels == 0) return 0;

    uint32_t currentSpuAddress = 0x1010;
    for (unsigned i = 0; i < 31; i++) {
        s_spuInstrumentData[i].baseAddress = currentSpuAddress >> 4;
        s_spuInstrumentData[i].finetune = module->samples[i].finetune;
        s_spuInstrumentData[i].volume = module->samples[i].volume;
        currentSpuAddress += module->samples[i].length;
    }

    MOD_SongLength = module->songLength;

    unsigned maxPatternID = 0;
    for (unsigned i = 0; i < 128; i++) {
        if (maxPatternID < module->patternTable[i]) maxPatternID = module->patternTable[i];
    }

    SPUUploadInstruments(0x1010,
                         MOD_ModuleData + sizeof(struct MODFileFormat) + MOD_Channels * 0x100 * (maxPatternID + 1),
                         currentSpuAddress - 0x1010);

    MOD_CurrentOrder = 0;
    MOD_CurrentPattern = module->patternTable[0];
    MOD_CurrentRow = 0;
    MOD_Speed = 6;
    MOD_Tick = 6;
    MOD_BPM = 125;
    MOD_RowPointer = MOD_ModuleData + sizeof(struct MODFileFormat) + MOD_CurrentPattern * MOD_Channels * 0x100;
    for (unsigned i = 0; i < MOD_Channels; i++) SPUResetVoice(i);
    MOD_ChangeRowNextTick = 0;
    MOD_ChangeOrderNextTick = 0;
    MOD_LoopStart = 0;
    MOD_LoopCount = 0;
    // these two are erroneously missing from the original code, at least for being able to play more than one music
    MOD_PatternDelay = 0;
    memset(s_channelData, 0, sizeof(s_channelData));
    //
    SPUUnMute();

    return MOD_Channels;
}

static const uint8_t MOD_SineTable[32] = {
    0x00, 0x18, 0x31, 0x4a, 0x61, 0x78, 0x8d, 0xa1, 0xb4, 0xc5, 0xd4, 0xe0, 0xeb, 0xf4, 0xfa, 0xfd,
    0xff, 0xfd, 0xfa, 0xf4, 0xeb, 0xe0, 0xd4, 0xc5, 0xb4, 0xa1, 0x8d, 0x78, 0x61, 0x4a, 0x31, 0x18,
};

static const uint16_t MOD_PeriodTable[36 * 16] = {
    856, 808, 762, 720, 678, 640, 604, 570, 538, 508, 480, 453, 428, 404, 381, 360, 339, 320,  // tune 0
    302, 285, 269, 254, 240, 226, 214, 202, 190, 180, 170, 160, 151, 143, 135, 127, 120, 113,  // tune 0
    850, 802, 757, 715, 674, 637, 601, 567, 535, 505, 477, 450, 425, 401, 379, 357, 337, 318,  // tune 1
    300, 284, 268, 253, 239, 225, 213, 201, 189, 179, 169, 159, 150, 142, 134, 126, 119, 113,  // tune 1
    844, 796, 752, 709, 670, 632, 597, 563, 532, 502, 474, 447, 422, 398, 376, 355, 335, 316,  // tune 2
    298, 282, 266, 251, 237, 224, 211, 199, 188, 177, 167, 158, 149, 141, 133, 125, 118, 112,  // tune 2
    838, 791, 746, 704, 665, 628, 592, 559, 528, 498, 470, 444, 419, 395, 373, 352, 332, 314,  // tune 3
    296, 280, 264, 249, 235, 222, 209, 198, 187, 176, 166, 157, 148, 140, 132, 125, 118, 111,  // tune 3
    832, 785, 741, 699, 660, 623, 588, 555, 524, 495, 467, 441, 416, 392, 370, 350, 330, 312,  // tune 4
    294, 278, 262, 247, 233, 220, 208, 196, 185, 175, 165, 156, 147, 139, 131, 124, 117, 110,  // tune 4
    826, 779, 736, 694, 655, 619, 584, 551, 520, 491, 463, 437, 413, 390, 368, 347, 328, 309,  // tune 5
    292, 276, 260, 245, 232, 219, 206, 195, 184, 174, 164, 155, 146, 138, 130, 123, 116, 109,  // tune 5
    820, 774, 730, 689, 651, 614, 580, 547, 516, 487, 460, 434, 410, 387, 365, 345, 325, 307,  // tune 6
    290, 274, 258, 244, 230, 217, 205, 193, 183, 172, 163, 154, 145, 137, 129, 122, 115, 109,  // tune 6
    814, 768, 725, 684, 646, 610, 575, 543, 513, 484, 457, 431, 407, 384, 363, 342, 323, 305,  // tune 7
    288, 272, 256, 242, 228, 216, 204, 192, 181, 171, 161, 152, 144, 136, 128, 121, 114, 108,  // tune 7
    907, 856, 808, 762, 720, 678, 640, 604, 570, 538, 508, 480, 453, 428, 404, 381, 360, 339,  // tune -8
    320, 302, 285, 269, 254, 240, 226, 214, 202, 190, 180, 170, 160, 151, 143, 135, 127, 120,  // tune -8
    900, 850, 802, 757, 715, 675, 636, 601, 567, 535, 505, 477, 450, 425, 401, 379, 357, 337,  // tune -7
    318, 300, 284, 268, 253, 238, 225, 212, 200, 189, 179, 169, 159, 150, 142, 134, 126, 119,  // tune -7
    894, 844, 796, 752, 709, 670, 632, 597, 563, 532, 502, 474, 447, 422, 398, 376, 355, 335,  // tune -6
    316, 298, 282, 266, 251, 237, 223, 211, 199, 188, 177, 167, 158, 149, 141, 133, 125, 118,  // tune -6
    887, 838, 791, 746, 704, 665, 628, 592, 559, 528, 498, 470, 444, 419, 395, 373, 352, 332,  // tune -5
    314, 296, 280, 264, 249, 235, 222, 209, 198, 187, 176, 166, 157, 148, 140, 132, 125, 118,  // tune -5
    881, 832, 785, 741, 699, 660, 623, 588, 555, 524, 494, 467, 441, 416, 392, 370, 350, 330,  // tune -4
    312, 294, 278, 262, 247, 233, 220, 208, 196, 185, 175, 165, 156, 147, 139, 131, 123, 117,  // tune -4
    875, 826, 779, 736, 694, 655, 619, 584, 551, 520, 491, 463, 437, 413, 390, 368, 347, 328,  // tune -3
    309, 292, 276, 260, 245, 232, 219, 206, 195, 184, 174, 164, 155, 146, 138, 130, 123, 116,  // tune -3
    868, 820, 774, 730, 689, 651, 614, 580, 547, 516, 487, 460, 434, 410, 387, 365, 345, 325,  // tune -2
    307, 290, 274, 258, 244, 230, 217, 205, 193, 183, 172, 163, 154, 145, 137, 129, 122, 115,  // tune -2
    862, 814, 768, 725, 684, 646, 610, 575, 543, 513, 484, 457, 431, 407, 384, 363, 342, 323,  // tune -1
    305, 288, 272, 256, 242, 228, 216, 203, 192, 181, 171, 161, 152, 144, 136, 128, 121, 114,  // tune -1
};

static void MOD_UpdateEffect() {
    uint8_t* rowPointer = MOD_RowPointer - MOD_Channels * 4;
    for (unsigned channel = 0; channel < MOD_Channels; channel++) {
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
        int16_t volume;

        switch (effectNibble1) {
            case 0:  // arpeggio
                arpeggioTick = MOD_Tick;
                arpeggioTick %= 3;
                switch (arpeggioTick) {
                    case 0:
                        newPeriod = s_channelData[channel].period;
                        break;
                    case 1:
                        newPeriod = MOD_PeriodTable[s_channelData[channel].note + effectNibble3];
                        break;
                    case 2:
                        newPeriod = MOD_PeriodTable[s_channelData[channel].note + effectNibble2];
                        break;
                }
                newPeriod *= 2;
                SPUSetVoiceSampleRate(channel, ((7093789 / newPeriod) << 12) / 44100);
                break;
            case 1:
                newPeriod = s_channelData[channel].period;
                newPeriod -= effectNibble23;
                if (newPeriod < 108) newPeriod = 108;
                s_channelData[channel].period = newPeriod;
                newPeriod *= 2;
                SPUSetVoiceSampleRate(channel, ((7093789 / newPeriod) << 12) / 44100);
                break;
            case 2:
                newPeriod = s_channelData[channel].period;
                newPeriod += effectNibble23;
                if (newPeriod > 907) newPeriod = 907;
                s_channelData[channel].period = newPeriod;
                newPeriod *= 2;
                SPUSetVoiceSampleRate(channel, ((7093789 / newPeriod) << 12) / 44100);
                break;
            case 5:
                volume = s_channelData[channel].volume;
                if (effectNibble23 <= 0x10) {
                    volume -= effectNibble23;
                    if (volume < 0) volume = 0;
                } else {
                    volume += effectNibble3;
                    if (volume > 63) volume = 63;
                }
                s_channelData[channel].volume = volume;
                volume <<= 8;
                SPUSetVoiceVolume(channel, volume, volume);
                /* fall through */
            case 3:
                newPeriod = s_channelData[channel].period;
                slideTo = s_channelData[channel].slideTo;
                if (newPeriod < slideTo) {
                    newPeriod += s_channelData[channel].slideSpeed;
                    if (newPeriod > slideTo) newPeriod = slideTo;
                } else if (newPeriod > slideTo) {
                    newPeriod -= s_channelData[channel].slideSpeed;
                    if (newPeriod < slideTo) newPeriod = slideTo;
                }
                s_channelData[channel].period = newPeriod;
                newPeriod *= 2;
                SPUSetVoiceSampleRate(channel, ((7093789 / newPeriod) << 12) / 44100);
                break;
            case 6:
                volume = s_channelData[channel].volume;
                if (effectNibble23 <= 0x10) {
                    volume -= effectNibble23;
                    if (volume < 0) volume = 0;
                } else {
                    volume += effectNibble3;
                    if (volume > 63) volume = 63;
                }
                s_channelData[channel].volume = volume;
                volume <<= 8;
                SPUSetVoiceVolume(channel, volume, volume);
                /* fall through */
            case 4:
                mutation = s_channelData[channel].vibrato & 0x1f;
                switch (s_channelData[channel].fx[3] & 3) {
                    // this looks buggy
                    case 0:
                    case 3:
                        mutation = MOD_SineTable[mutation];
                        break;
                    case 1:
                        if (s_channelData[channel].vibrato < 0) {
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
                mutation *= s_channelData[channel].fx[1] >> 4;
                mutation >>= 7;
                newPeriod = s_channelData[channel].period;
                if (s_channelData[channel].vibrato < 0) {
                    newPeriod -= mutation;
                } else {
                    newPeriod += mutation;
                }
                newValue = s_channelData[channel].vibrato;
                newValue += s_channelData[channel].fx[1] & 0x0f;
                if (newValue >= 32) newValue -= 64;
                s_channelData[channel].vibrato = newValue;
                newPeriod *= 2;
                SPUSetVoiceSampleRate(channel, ((7093789 / newPeriod) << 12) / 44100);
                break;
            case 7:
                mutation = s_channelData[0].fx[0] & 0x1f;
                switch (s_channelData[0].fx[3] & 3) {
                    // this looks buggy
                    case 0:
                    case 3:
                        mutation = MOD_SineTable[mutation];
                        break;
                    case 1:
                        if (s_channelData[channel].fx[0] & 0x80) {
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
                mutation *= s_channelData[channel].fx[3] >> 4;
                mutation >>= 6;
                volume = s_channelData[channel].volume;
                if (s_channelData[channel].fx[0] & 0x80) {
                    volume -= mutation;
                } else {
                    volume += mutation;
                }
                newValue = s_channelData[channel].fx[0] + (s_channelData[channel].fx[2] & 0x0f);
                if (newValue >= 32) newValue -= 64;
                s_channelData[channel].fx[0] = newValue;
                if (volume > 63) volume = 63;
                volume <<= 8;
                SPUSetVoiceVolume(channel, volume, volume);
                break;
            case 10:
                volume = s_channelData[channel].volume;
                if (effectNibble23 <= 0x10) {
                    volume -= effectNibble23;
                    if (volume < 0) volume = 0;
                } else {
                    volume += effectNibble3;
                    if (volume > 63) volume = 63;
                }
                s_channelData[channel].volume = volume;
                volume <<= 8;
                SPUSetVoiceVolume(channel, volume, volume);
                break;
            case 14:
                switch (effectNibble3) {
                    case 9:
                        if ((MOD_Tick % effectNibble2) == 0) SPUKeyOn(1 << channel);
                        break;
                    case 12:
                        if (MOD_Tick != effectNibble2) break;
                        s_channelData[channel].volume = 0;
                        SPUSetVoiceVolume(channel, volume, volume);
                }
                break;
        }

        rowPointer += 4;
    }
}

static void MOD_UpdateRow() {
    if (MOD_ChangeOrderNextTick) {
        unsigned newOrder = MOD_NextOrder;
        if (newOrder >= MOD_SongLength) newOrder = 0;
        MOD_CurrentRow = 0;
        MOD_CurrentOrder = newOrder;
        MOD_CurrentPattern = ((struct MODFileFormat*)MOD_ModuleData)->patternTable[newOrder];
    }
    if (MOD_ChangeRowNextTick) {
        unsigned newRow = (MOD_NextRow >> 4) * 10 + (MOD_NextRow & 0x0f);
        if (newRow >= 64) newRow = 0;
        MOD_CurrentRow = newRow;
        if (MOD_ChangeOrderNextTick) {
            if (++MOD_CurrentOrder >= MOD_SongLength) MOD_CurrentOrder = 0;
            MOD_CurrentPattern = ((struct MODFileFormat*)MOD_ModuleData)->patternTable[MOD_CurrentOrder];
        }
    }
    MOD_ChangeRowNextTick = 0;
    MOD_ChangeOrderNextTick = 0;
    MOD_RowPointer = MOD_ModuleData + sizeof(struct MODFileFormat) + MOD_CurrentPattern * MOD_Channels * 0x100 +
                     MOD_CurrentRow * MOD_Channels * 4;

    for (unsigned channel = 0; channel < MOD_Channels; channel++) {
        int16_t volume;

        uint8_t effectNibble1 = MOD_RowPointer[2];
        uint8_t effectNibble23 = MOD_RowPointer[3];
        unsigned sampleID = (MOD_RowPointer[0] & 0xf0) | (effectNibble1 >> 4);
        effectNibble1 &= 0x0f;
        unsigned period = ((MOD_RowPointer[0] & 0x0f) << 8) | MOD_RowPointer[1];
        if (effectNibble1 != 9) s_channelData[channel].samplePos = 0;
        if (sampleID != 0) {
            s_channelData[channel].sampleID = --sampleID;
            volume = s_spuInstrumentData[sampleID].volume;
            if (volume > 63) volume = 63;
            s_channelData[channel].volume = volume;
            if (effectNibble1 != 7) {
                volume <<= 8;
                SPUSetVoiceVolume(channel, volume, volume);
            }
            SPUSetStartAddress(channel,
                               s_spuInstrumentData[sampleID].baseAddress << 4 + s_channelData[channel].samplePos);
        }

        int32_t newPeriod;
        uint8_t fx;

        if (period != 0) {
            int periodIndex;
            // original code erroneously does >= 0
            for (periodIndex = 35; periodIndex--; periodIndex > 0) {
                if (MOD_PeriodTable[periodIndex] == period) break;
            }
            s_channelData[channel].note =
                periodIndex + s_spuInstrumentData[s_channelData[channel].sampleID].finetune * 36;
            fx = s_channelData[channel].fx[3];
            if ((fx & 0x0f) < 4) {
                s_channelData[channel].vibrato = 0;
            }
            if ((fx >> 4) < 4) {
                s_channelData[channel].fx[0] = 0;
            }
            if ((effectNibble1 != 3) && (effectNibble1 != 5)) {
                SPUWaitIdle();
                SPUKeyOn(1 << channel);
                s_channelData[channel].period = MOD_PeriodTable[s_channelData[channel].note];
            }
            newPeriod = s_channelData[channel].period;
            newPeriod *= 2;
            SPUSetVoiceSampleRate(channel, ((7093789 / newPeriod) << 12) / 44100);
        }

        uint8_t effectNibble2 = effectNibble23 & 0x0f;
        uint8_t effectNibble3 = effectNibble23 >> 4;

        switch (effectNibble1) {
            case 3:  // glissando
                if (effectNibble23 != 0) {
                    s_channelData[channel].slideSpeed = effectNibble23;
                }
                if (period != 0) {
                    s_channelData[channel].slideTo = MOD_PeriodTable[s_channelData[channel].note];
                }
                break;
            case 4:  // vibrato
                if (effectNibble3 != 0) {
                    fx = s_channelData[channel].fx[1];
                    fx &= ~0x0f;
                    fx |= effectNibble3;
                    s_channelData[channel].fx[1] = fx;
                }
                if (effectNibble2 != 0) {
                    fx = s_channelData[channel].fx[1];
                    fx &= ~0xf0;
                    fx |= effectNibble3 << 4;
                    s_channelData[channel].fx[1] = fx;
                }
                break;
            case 7:
                if (effectNibble3 != 0) {
                    fx = s_channelData[channel].fx[2];
                    fx &= ~0x0f;
                    fx |= effectNibble3;
                    s_channelData[channel].fx[2] = fx;
                }
                if (effectNibble2 != 0) {
                    fx = s_channelData[channel].fx[2];
                    fx &= ~0xf0;
                    fx |= effectNibble2 << 4;
                    s_channelData[channel].fx[2] = fx;
                }
                break;
            case 9:  // sample jump
                if (effectNibble23 != 0) {
                    uint16_t newSamplePos = effectNibble23;
                    s_channelData[channel].samplePos = newSamplePos << 7;
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
                s_channelData[channel].volume = volume;
                volume <<= 8;
                SPUSetVoiceVolume(channel, volume, volume);
                break;
            case 13:  // pattern break
                if (!MOD_ChangeRowNextTick) {
                    MOD_ChangeRowNextTick = 1;
                    MOD_NextRow = effectNibble23;
                }
                break;
            case 14:  // extended
                switch (effectNibble3) {
                    case 1:
                        newPeriod = s_channelData[channel].period;
                        newPeriod -= effectNibble2;
                        s_channelData[channel].period = newPeriod;
                        newPeriod *= 2;
                        SPUSetVoiceSampleRate(channel, ((7093789 / newPeriod) << 12) / 44100);
                        break;
                    case 2:
                        newPeriod = s_channelData[channel].period;
                        newPeriod += effectNibble2;
                        s_channelData[channel].period = newPeriod;
                        newPeriod *= 2;
                        SPUSetVoiceSampleRate(channel, ((7093789 / newPeriod) << 12) / 44100);
                        break;
                    case 4:
                        fx = s_channelData[channel].fx[3];
                        fx &= ~0x0f;
                        fx |= effectNibble2;
                        s_channelData[channel].fx[3] = fx;
                        break;
                    case 5:
                        s_spuInstrumentData[sampleID].finetune = effectNibble2;
                        break;
                    case 6:
                        if (MOD_LoopCount-- == 0) {
                            MOD_LoopCount = effectNibble2;
                        }
                        if (MOD_LoopCount != 0) {
                            MOD_CurrentRow = MOD_LoopStart;
                        }
                        break;
                    case 7:
                        fx = s_channelData[channel].fx[3];
                        fx &= ~0xf0;
                        fx |= effectNibble2 << 4;
                        s_channelData[channel].fx[3] = fx;
                        break;
                    case 10:
                        volume = s_channelData[channel].volume;
                        volume += effectNibble2;
                        if (volume > 63) volume = 63;
                        s_channelData[channel].volume = volume;
                        volume <<= 8;
                        SPUSetVoiceVolume(channel, volume, volume);
                        break;
                    case 11:
                        volume = s_channelData[channel].volume;
                        volume -= effectNibble2;
                        if (volume < 0) volume = 0;
                        s_channelData[channel].volume = volume;
                        volume <<= 8;
                        SPUSetVoiceVolume(channel, volume, volume);
                        break;
                    case 14:
                        MOD_PatternDelay = effectNibble2;
                        break;
                }
                break;
            case 15:  // set speed
                MOD_Speed = effectNibble23;
                // this very likely needs to change
                TimerSetTarget(1, 39000 / effectNibble23, 0x1000);
                break;
        }

        MOD_RowPointer += 4;
    }
}

void MOD_Poll() {
    uint8_t newPatternDelay;
    if (++MOD_Tick < MOD_Speed) {
        MOD_UpdateEffect();
        newPatternDelay = MOD_PatternDelay;
    } else {
        newPatternDelay = MOD_PatternDelay - 1;
        if (MOD_PatternDelay == 0) {
            MOD_UpdateRow();
            MOD_Tick = 0;
            newPatternDelay = MOD_PatternDelay;
            if (++MOD_CurrentRow >= 64) {
                MOD_CurrentRow = 0;
                if (++MOD_CurrentOrder >= MOD_SongLength) {
                    MOD_CurrentOrder = 0;
                }
                MOD_CurrentPattern = ((struct MODFileFormat*)MOD_ModuleData)->patternTable[MOD_CurrentOrder];
            }
        }
    }
    MOD_PatternDelay = newPatternDelay;
}
