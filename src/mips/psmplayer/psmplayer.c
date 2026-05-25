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

#include "psmplayer/psmplayer.h"

#include <stddef.h>
#include <stdint.h>
#include "common/hardware/dma.h"
#include "common/hardware/spu.h"

// ============================================================================
// PSM format structures
// ============================================================================

#define PSM_NOTE_ON       0x00
#define PSM_NOTE_OFF      0x01
#define PSM_PITCH_BEND    0x02
#define PSM_CC_VOLUME     0x03
#define PSM_CC_PAN        0x04
#define PSM_CC_EXPRESSION 0x05
#define PSM_CC_SUSTAIN    0x06
#define PSM_CC_MODULATION 0x07
#define PSM_CC_REVERB     0x08
#define PSM_PROGRAM_CHANGE 0x09
#define PSM_TEMPO_CHANGE  0x0A
#define PSM_LOOP_POINT    0x0B
#define PSM_END           0x0C
#define PSM_LONG_WAIT     0xFF

struct PsmHeader {
    uint8_t magic[4];      // "PSM\0"
    uint32_t version;
    uint32_t tickRate;     // 16.16 fixed-point Hz
    uint32_t eventCount;
};

struct PsmEvent {
    uint16_t deltaTick;
    uint8_t type;
    uint8_t channel;
    uint32_t data;
};

// ============================================================================
// VAB format structures
// ============================================================================

struct VabHdr {
    uint8_t magic[4];      // "pBAV"
    uint32_t version;
    uint32_t id;
    uint32_t fileSize;
    uint16_t reserved0;
    uint16_t numPrograms;
    uint16_t numTones;
    uint16_t numVags;
    uint8_t masterVol;
    uint8_t masterPan;
    uint8_t attr1;
    uint8_t attr2;
    uint32_t reserved1;
};

struct ProgAtr {
    uint8_t tones;
    uint8_t mvol;
    uint8_t prior;
    uint8_t mode;
    uint8_t mpan;
    uint8_t reserved0;
    int16_t attr;
    uint32_t reserved1;
    uint32_t reserved2;
};

struct VagAtr {
    uint8_t prior;
    uint8_t mode;
    uint8_t vol;
    uint8_t pan;
    uint8_t center;        // adjusted root key (folds in sample rate + transpose)
    uint8_t shift;         // fine tune in cents (signed, as uint8)
    uint8_t min;
    uint8_t max;
    uint8_t vibW;
    uint8_t vibT;
    uint8_t porW;
    uint8_t porT;
    uint8_t pbmin;
    uint8_t pbmax;
    uint8_t reserved0;
    uint8_t reserved1;
    uint16_t adsr1;        // SPU ADSR register (voice +0x08)
    uint16_t adsr2;        // SPU ADSR register (voice +0x0A)
    int16_t prog;
    int16_t vag;           // VAG index (0-based, -1 = unused)
    int16_t reserved2[4];
};

// ============================================================================
// Pitch computation
// ============================================================================

// Semitone frequency ratios in 12-bit fixed-point (x4096).
// semitoneRatio[i] = 2^(i/12) * 4096
static const uint16_t s_semitoneRatio[12] = {
    4096, 4340, 4598, 4871, 5161, 5468, 5793, 6137, 6502, 6889, 7298, 7732
};

// Compute SPU pitch register value for a given MIDI note and VagAtr center/shift.
// center = adjusted root key (sample rate + transpose folded in by offline tool)
// shift = fine tune in cents (signed int8 stored as uint8)
// Returns 0x0000 - 0x3FFF.
static uint16_t computePitch(uint8_t note, uint8_t center, int8_t shift, int16_t bendCents) {
    // pitch = freq(note) / freq(center) * 0x1000
    //       = 2^((note - center) / 12) * 0x1000
    //
    // Decompose (note - center) into octaves and semitones to avoid large intermediates.
    // diff = note - center (signed)
    // octaves = diff / 12 (round toward negative infinity)
    // semitones = diff - octaves * 12 (always 0..11)
    // pitch = semitoneRatio[semitones] * 2^octaves * 0x1000 / 4096
    //       = semitoneRatio[semitones] * 2^octaves  (since 0x1000 == 4096)

    if (note > 127) note = 127;
    if (center > 127) center = 127;

    int diff = (int)note - (int)center;
    int octaves, semi;

    // Floor division for negative diff
    if (diff >= 0) {
        octaves = diff / 12;
        semi = diff % 12;
    } else {
        // For negative: octaves = floor(diff/12), semi = diff - octaves*12
        octaves = (diff - 11) / 12;  // floor division
        semi = diff - octaves * 12;
    }

    uint32_t pitch = s_semitoneRatio[semi];  // 12-bit fixed-point ratio * 4096

    // pitch is ratio * 4096. SPU base is 0x1000 = 4096. So pitch = ratio * 0x1000.
    // Apply octave shift: multiply or divide by powers of 2.
    if (octaves > 0) {
        pitch <<= octaves;
    } else if (octaves < 0) {
        pitch >>= (-octaves);
    }
    // pitch is now the SPU pitch value (0x1000 = same frequency as center)

    // Apply fine tune (shift, in cents) and pitch bend (in cents)
    int totalCents = (int)shift + (int)bendCents;
    if (totalCents != 0) {
        // Approximate 2^(cents/1200) using linear interpolation.
        // ratio ~= 1 + cents * ln(2)/1200 ~= 1 + cents * 0.000578
        // In 16-bit fixed-point: multiply by (65536 + cents * 38) >> 16
        int correction = 65536 + totalCents * 38;
        if (correction < 0) correction = 0;
        pitch = (pitch * (uint32_t)correction) >> 16;
    }

    if (pitch > 0x3FFF) pitch = 0x3FFF;
    return (uint16_t)pitch;
}

// ============================================================================
// Voice allocator
// ============================================================================

#define MAX_VOICES 24

struct Voice {
    uint8_t active;
    uint8_t sustainHeld;
    uint8_t channel;
    uint8_t note;
    uint8_t velocity;
    uint8_t program;
    uint8_t toneIndex;
    uint8_t padding;
    uint32_t startTick;
};

static struct Voice s_voices[MAX_VOICES];
static uint32_t s_globalTick = 0;

static int allocateVoice(uint8_t channel, uint8_t note, uint8_t velocity, unsigned maxVoices) {
    // Find a free voice
    for (unsigned i = 0; i < maxVoices; i++) {
        if (!s_voices[i].active) {
            return (int)i;
        }
    }
    // Steal: prefer sustain-held, then lowest velocity, then oldest
    int best = 0;
    int bestScore = -1;
    for (unsigned i = 0; i < maxVoices; i++) {
        int score = 0;
        if (s_voices[i].sustainHeld) score += 10000;
        score += (127 - s_voices[i].velocity) * 10;
        score += (int)(s_globalTick - s_voices[i].startTick);
        if (score > bestScore) {
            bestScore = score;
            best = (int)i;
        }
    }
    return best;
}

// ============================================================================
// Channel state
// ============================================================================

struct ChannelState {
    uint8_t volume;       // CC#7 (default 100)
    uint8_t pan;          // CC#10 (default 64)
    uint8_t expression;   // CC#11 (default 127)
    uint8_t sustain;      // CC#64 (0 = off)
    uint8_t modulation;   // CC#1 (default 0)
    uint8_t reverb;       // CC#91 (default 40)
    uint8_t program;      // current program
    uint8_t padding;
    int16_t pitchBend;    // -8192 to 8191
    uint16_t padding2;
};

static struct ChannelState s_channels[16];

// GM velocity curve: vel^2/127
static uint8_t velocityCurve(uint8_t vel) {
    return (uint8_t)(((uint16_t)vel * vel + 63) / 127);
}

// Compute left/right volume for a voice
static void computeVolume(uint8_t velocity, const struct ChannelState* ch,
                          const struct VagAtr* tone,
                          uint16_t* volL, uint16_t* volR) {
    int vel = velocityCurve(velocity);
    // tone->vol already accounts for SF2 attenuation (0-127)
    int vol = (vel * ch->volume * ch->expression * tone->vol) / (127 * 127 * 127);

    // Combine channel pan with tone pan
    int chanPanOff = (int)ch->pan - 64;
    int tonePanOff = (int)tone->pan - 64;
    int effectivePan = 64 + chanPanOff + tonePanOff;
    if (effectivePan < 0) effectivePan = 0;
    if (effectivePan > 127) effectivePan = 127;

    int panL = (effectivePan <= 64) ? 127 : (127 - effectivePan) * 2;
    int panR = (effectivePan >= 64) ? 127 : effectivePan * 2;
    if (panL > 127) panL = 127;
    if (panR > 127) panR = 127;

    *volL = (uint16_t)((vol * panL * 0x3FFF) / (127 * 127));
    *volR = (uint16_t)((vol * panR * 0x3FFF) / (127 * 127));
}

// ============================================================================
// Player state
// ============================================================================

// Public state
uint32_t PSM_hblanks = 0;
unsigned PSM_voiceCount = 16;
uint32_t PSM_currentEvent = 0;
uint32_t PSM_eventCount = 0;
int PSM_playing = 0;

// Private state
static const struct PsmEvent* s_events = NULL;
static uint32_t s_loopEventIndex = 0;
static uint32_t s_waitRemaining = 0;
static uint32_t s_tickRateFP = 0;

// VAB data pointers (kept after load for tone lookups during playback)
static const struct ProgAtr* s_progAtrs = NULL;
static const struct VagAtr* s_vagAtrs = NULL;
static unsigned s_numPrograms = 0;
static unsigned s_numVags = 0;

// VAG SPU RAM addresses (computed during bank load)
#define MAX_VAGS 254
static uint32_t s_vagAddrs[MAX_VAGS];  // SPU address in 8-byte units

// Reverb state
static uint32_t s_reverbMask = 0;

// ============================================================================
// SPU helpers (same as spudump player)
// ============================================================================

static void SPUInit(void) {
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

static void SPUResetVoice(int v) {
    SPU_VOICES[v].volumeLeft = 0;
    SPU_VOICES[v].volumeRight = 0;
    SPU_VOICES[v].sampleRate = 0;
    SPU_VOICES[v].sampleStartAddr = 0;
    SPU_VOICES[v].adsrLo = 0x000f;
    SPU_VOICES[v].currentVolume = 0;
    SPU_VOICES[v].sampleRepeatAddr = 0;
    SPU_VOICES[v].adsrHi = 0x0000;
}

static void SPUUpload(uint32_t spuAddr, const uint8_t* data, uint32_t size) {
    uint32_t bcr = size >> 6;
    if (size & 0x3f) bcr++;
    bcr <<= 16;
    bcr |= 0x10;

    SPU_RAM_DTA = spuAddr >> 3;
    SPU_CTRL = (SPU_CTRL & ~0x0030) | 0x0020;
    while ((SPU_CTRL & 0x0030) != 0x0020)
        ;
    SBUS_DEV4_CTRL &= ~0x0f000000;
    DMA_CTRL[DMA_SPU].MADR = (uint32_t)data;
    DMA_CTRL[DMA_SPU].BCR = bcr;
    DMA_CTRL[DMA_SPU].CHCR = 0x01000201;

    while ((DMA_CTRL[DMA_SPU].CHCR & 0x01000000) != 0)
        ;
}

static void SPUUnMute(void) { SPU_CTRL = 0xc000; }

static void updateHblanks(void) {
    uint32_t status = GPU_STATUS;
    int isPalConsole = *((const char*)0xbfc7ff52) == 'E';
    int isPal = (status & 0x00100000) != 0;
    uint32_t hlinesPerSecond;
    if (isPal && isPalConsole) {
        hlinesPerSecond = 15625;
    } else if (isPal && !isPalConsole) {
        hlinesPerSecond = 15769;
    } else if (!isPal && isPalConsole) {
        hlinesPerSecond = 15607;
    } else {
        hlinesPerSecond = 15734;
    }
    if (s_tickRateFP > 0) {
        PSM_hblanks = (hlinesPerSecond << 16) / s_tickRateFP;
    } else {
        PSM_hblanks = hlinesPerSecond / 50;
    }
}

// ============================================================================
// Reverb presets (from PS1 BIOS / psx-spx documentation)
// ============================================================================

struct ReverbPreset {
    uint32_t bufferSize;       // bytes needed at top of SPU RAM
    uint16_t regs[32];         // dAPF1 through vRIN
    uint16_t outVolL;
    uint16_t outVolR;
};

static const struct ReverbPreset s_reverbPresets[] = {
    // 0: off
    { 0x10, {
        0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
        0x0000, 0x0000, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001,
        0x0000, 0x0000, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001,
        0x0000, 0x0000, 0x0001, 0x0001, 0x0001, 0x0001, 0x0000, 0x0000
    }, 0x0000, 0x0000 },
    // 1: room (Studio Small)
    { 0x1F40, {
        0x0033, 0x0025, 0x70F0, 0x4FA8, 0xBCE0, 0x4410, 0xC0F0, 0x9C00,
        0x5280, 0x4EC0, 0x03E4, 0x031B, 0x03A4, 0x02AF, 0x0372, 0x0266,
        0x031C, 0x025D, 0x025C, 0x018E, 0x022F, 0x0135, 0x01D2, 0x00B7,
        0x018F, 0x00B5, 0x00B4, 0x0080, 0x004C, 0x0026, 0x8000, 0x8000
    }, 0x3800, 0x3800 },
    // 2: studio (Studio Medium)
    { 0x4840, {
        0x00B1, 0x007F, 0x70F0, 0x4FA8, 0xBCE0, 0x4510, 0xBEF0, 0xB4C0,
        0x5280, 0x4EC0, 0x0904, 0x076B, 0x0824, 0x065F, 0x07A2, 0x0616,
        0x076C, 0x05ED, 0x05EC, 0x042E, 0x050F, 0x0305, 0x0462, 0x02B7,
        0x042F, 0x0265, 0x0264, 0x01B2, 0x0100, 0x0080, 0x8000, 0x8000
    }, 0x3800, 0x3800 },
    // 3: hall
    { 0xADE0, {
        0x01A5, 0x0139, 0x6000, 0x5000, 0x4C00, 0xB800, 0xBC00, 0xC000,
        0x6000, 0x5C00, 0x15BA, 0x11BB, 0x14C2, 0x10BD, 0x11BC, 0x0DC1,
        0x11C0, 0x0DC3, 0x0DC0, 0x09C1, 0x0BC4, 0x07C1, 0x0A00, 0x06CD,
        0x09C2, 0x05C1, 0x05C0, 0x041A, 0x0274, 0x013A, 0x8000, 0x8000
    }, 0x3000, 0x3000 },
    // 4: space (Space Echo)
    { 0xF6C0, {
        0x033D, 0x0231, 0x7E00, 0x5000, 0xB400, 0xB000, 0x4C00, 0xB000,
        0x6000, 0x5400, 0x1ED6, 0x1A31, 0x1D14, 0x183B, 0x1BC2, 0x16B2,
        0x1A32, 0x15EF, 0x15EE, 0x1055, 0x1334, 0x0F2D, 0x11F6, 0x0C5D,
        0x1056, 0x0AE1, 0x0AE0, 0x07A2, 0x0464, 0x0232, 0x8000, 0x8000
    }, 0x2800, 0x2800 },
};

#define REVERB_PRESET_COUNT 5
#define SPU_REVERB_CFG_BASE 0x1f801dc0

static int s_reverbPreset = 3;  // default: hall

static void setupReverb(void) {
    if (s_reverbPreset <= 0 || s_reverbPreset >= REVERB_PRESET_COUNT) return;
    const struct ReverbPreset* preset = &s_reverbPresets[s_reverbPreset];

    volatile uint16_t* reverbCfg = (volatile uint16_t*)SPU_REVERB_CFG_BASE;

    // Set reverb work area base (top of SPU RAM minus buffer)
    uint16_t mBase = (uint16_t)((0x80000 - preset->bufferSize) >> 3);
    SPU_REVERB_ADDR = mBase;

    // Write all 32 reverb config registers
    for (int i = 0; i < 32; i++) {
        reverbCfg[i] = preset->regs[i];
    }

    // Set reverb output volumes
    SPU_REVERB_LEFT = preset->outVolL;
    SPU_REVERB_RIGHT = preset->outVolR;

    // Enable reverb master: SPU enable (bit 15) + unmute (bit 14) + reverb enable (bit 7)
    SPU_CTRL = 0xC080;
}

// ============================================================================
// Bank loading
// ============================================================================

// Parse VH (header portion of VAB): header, ProgAtr, VagAtr, offset table.
// Returns pointer to VAG offset table, or NULL on failure.
static const uint16_t* parseVH(const uint8_t* p, uint32_t size) {
    if (size < 32) return NULL;

    // Check magic
    if (p[0] != 'p' || p[1] != 'B' || p[2] != 'A' || p[3] != 'V') return NULL;

    const struct VabHdr* hdr = (const struct VabHdr*)p;
    s_numPrograms = hdr->numPrograms;
    s_numVags = hdr->numVags;
    if (s_numVags > MAX_VAGS) s_numVags = MAX_VAGS;

    // Program attribute table starts at offset 32
    s_progAtrs = (const struct ProgAtr*)(p + 32);

    // Tone attribute table follows 128 ProgAtrs
    s_vagAtrs = (const struct VagAtr*)(p + 32 + 128 * sizeof(struct ProgAtr));

    // VAG offset table follows the tone table
    uint32_t toneTableSize = (uint32_t)s_numPrograms * 16 * sizeof(struct VagAtr);
    return (const uint16_t*)(p + 32 + 128 * sizeof(struct ProgAtr) + toneTableSize);
}

// Upload VAG samples to SPU RAM using the offset table and a body pointer.
static void uploadVAGs(const uint16_t* vagOffsetTable, const uint8_t* vagBody) {
    uint32_t spuAddr = 0x1010;  // first usable address after capture buffers
    uint32_t bodyOffset = 0;

    for (unsigned i = 0; i < s_numVags; i++) {
        uint32_t vagSize = (uint32_t)vagOffsetTable[i] << 3;
        s_vagAddrs[i] = spuAddr >> 3;  // store in 8-byte units for SPU register

        if (vagSize > 0) {
            SPUUpload(spuAddr, vagBody + bodyOffset, vagSize);
            spuAddr += vagSize;
            bodyOffset += vagSize;
        }
    }
}

// Compute VAG addresses without uploading (when samples are already in SPU RAM).
static void computeVAGAddrs(const uint16_t* vagOffsetTable) {
    uint32_t spuAddr = 0x1010;
    for (unsigned i = 0; i < s_numVags; i++) {
        uint32_t vagSize = (uint32_t)vagOffsetTable[i] << 3;
        s_vagAddrs[i] = spuAddr >> 3;
        spuAddr += vagSize;
    }
}

unsigned PSM_LoadBank(const void* vabData, uint32_t vabSize) {
    const uint8_t* p = (const uint8_t*)vabData;
    const uint16_t* vagOffsetTable = parseVH(p, vabSize);
    if (!vagOffsetTable) return 0;

    // Initialize SPU
    SPUInit();
    for (int i = 0; i < 24; i++) SPUResetVoice(i);

    // VAG body follows the offset table (256 entries * 2 bytes = 512 bytes)
    const uint8_t* vagBody = (const uint8_t*)(vagOffsetTable + 256);
    uploadVAGs(vagOffsetTable, vagBody);

    SPUUnMute();
    setupReverb();

    return s_numPrograms;
}

unsigned PSM_LoadBankEx(const void* vhData, uint32_t vhSize,
                        const void* vbData, uint32_t vbSize) {
    const uint8_t* p = (const uint8_t*)vhData;
    const uint16_t* vagOffsetTable = parseVH(p, vhSize);
    if (!vagOffsetTable) return 0;

    // Initialize SPU
    SPUInit();
    for (int i = 0; i < 24; i++) SPUResetVoice(i);

    if (vbData != NULL && vbSize > 0) {
        // Upload samples from separate VB buffer (can be freed after this call)
        uploadVAGs(vagOffsetTable, (const uint8_t*)vbData);
    } else if (vbData == NULL) {
        // Samples already in SPU RAM - just compute addresses
        computeVAGAddrs(vagOffsetTable);
    }

    SPUUnMute();
    setupReverb();

    return s_numPrograms;
}

// ============================================================================
// Song loading
// ============================================================================

uint32_t PSM_LoadSong(const void* psmData, uint32_t psmSize) {
    const uint8_t* p = (const uint8_t*)psmData;
    if (psmSize < 16) return 0;

    // Check magic
    if (p[0] != 'P' || p[1] != 'S' || p[2] != 'M' || p[3] != 0) return 0;

    const struct PsmHeader* hdr = (const struct PsmHeader*)p;
    if (hdr->version != 1) return 0;

    s_tickRateFP = hdr->tickRate;
    PSM_eventCount = hdr->eventCount;
    s_events = (const struct PsmEvent*)(p + sizeof(struct PsmHeader));

    // Reset playback state
    PSM_currentEvent = 0;
    s_loopEventIndex = 0;
    s_waitRemaining = 0;
    s_globalTick = 0;
    s_reverbMask = 0;
    PSM_playing = 1;

    // Reset channel state
    for (int i = 0; i < 16; i++) {
        s_channels[i].volume = 100;
        s_channels[i].pan = 64;
        s_channels[i].expression = 127;
        s_channels[i].sustain = 0;
        s_channels[i].modulation = 0;
        s_channels[i].reverb = 40;
        s_channels[i].program = 0;
        s_channels[i].pitchBend = 0;
    }

    // Reset voice state
    for (int i = 0; i < MAX_VOICES; i++) {
        s_voices[i].active = 0;
        s_voices[i].sustainHeld = 0;
    }

    // Calculate hblank timing
    updateHblanks();

    return PSM_eventCount;
}

// ============================================================================
// Event processing helpers
// ============================================================================

// Look up the VagAtr for a given (program, toneIndex)
static const struct VagAtr* lookupTone(uint8_t program, uint8_t toneIndex) {
    if (program >= s_numPrograms) return NULL;
    unsigned idx = (unsigned)program * 16 + toneIndex;
    return &s_vagAtrs[idx];
}

// Update volume registers for all active voices on a channel
static void updateChannelVolumes(uint8_t ch) {
    const struct ChannelState* chanState = &s_channels[ch];
    for (unsigned v = 0; v < PSM_voiceCount; v++) {
        if (s_voices[v].active && s_voices[v].channel == ch) {
            const struct VagAtr* tone = lookupTone(s_voices[v].program, s_voices[v].toneIndex);
            if (!tone) continue;
            uint16_t volL, volR;
            computeVolume(s_voices[v].velocity, chanState, tone, &volL, &volR);
            SPU_VOICES[v].volumeLeft = volL;
            SPU_VOICES[v].volumeRight = volR;
        }
    }
}

// Update pitch registers for all active voices on a channel
static void updateChannelPitch(uint8_t ch) {
    const struct ChannelState* chanState = &s_channels[ch];
    int16_t bendCents = (int16_t)(((int32_t)chanState->pitchBend * 200) / 8192);  // 2 semitone range

    for (unsigned v = 0; v < PSM_voiceCount; v++) {
        if (s_voices[v].active && s_voices[v].channel == ch) {
            const struct VagAtr* tone = lookupTone(s_voices[v].program, s_voices[v].toneIndex);
            if (!tone) continue;
            uint16_t pitch = computePitch(s_voices[v].note, tone->center,
                                          (int8_t)tone->shift, bendCents);
            SPU_VOICES[v].sampleRate = pitch;
        }
    }
}

// Process a single event
static void processEvent(const struct PsmEvent* ev) {
    uint8_t ch = ev->channel;
    struct ChannelState* chanState = &s_channels[ch];

    switch (ev->type) {
        case PSM_NOTE_ON: {
            uint8_t note = ev->data & 0xFF;
            uint8_t velocity = (ev->data >> 8) & 0xFF;
            uint8_t program = (ev->data >> 16) & 0xFF;
            uint8_t toneIndex = (ev->data >> 24) & 0xFF;

            const struct VagAtr* tone = lookupTone(program, toneIndex);
            if (!tone || tone->vag < 0) break;

            int v = allocateVoice(ch, note, velocity, PSM_voiceCount);

            // Key off the stolen voice first
            if (s_voices[v].active) {
                uint32_t bit = 1u << v;
                SPU_KEY_OFF_LOW = bit & 0xFFFF;
                if (v >= 16) SPU_KEY_OFF_HIGH = (bit >> 16) & 0xFFFF;
            }

            // Set up voice state
            s_voices[v].active = 1;
            s_voices[v].sustainHeld = 0;
            s_voices[v].channel = ch;
            s_voices[v].note = note;
            s_voices[v].velocity = velocity;
            s_voices[v].program = program;
            s_voices[v].toneIndex = toneIndex;
            s_voices[v].startTick = s_globalTick;

            // Set SPU registers
            uint16_t volL, volR;
            computeVolume(velocity, chanState, tone, &volL, &volR);

            int16_t bendCents = (int16_t)(((int32_t)chanState->pitchBend * 200) / 8192);
            uint16_t pitch = computePitch(note, tone->center, (int8_t)tone->shift, bendCents);

            SPU_VOICES[v].volumeLeft = volL;
            SPU_VOICES[v].volumeRight = volR;
            SPU_VOICES[v].sampleRate = pitch;
            SPU_VOICES[v].sampleStartAddr = s_vagAddrs[tone->vag];
            SPU_VOICES[v].adsrLo = tone->adsr1;   // offset +0x08: sustain rate/mode + release rate/mode
            SPU_VOICES[v].adsrHi = tone->adsr2;   // offset +0x0A: attack mode/rate + decay rate + sustain level

            // Update reverb mask
            if (chanState->reverb > 0) {
                s_reverbMask |= (1u << v);
            } else {
                s_reverbMask &= ~(1u << v);
            }
            SPU_REVERB_EN_LOW = s_reverbMask & 0xFFFF;
            SPU_REVERB_EN_HIGH = (s_reverbMask >> 16) & 0xFFFF;

            // Key on
            {
                uint32_t bit = 1u << v;
                SPU_KEY_ON_LOW = bit & 0xFFFF;
                if (v >= 16) SPU_KEY_ON_HIGH = (bit >> 16) & 0xFFFF;
            }
            break;
        }

        case PSM_NOTE_OFF: {
            uint8_t note = ev->data & 0xFF;
            uint32_t keyOffBits = 0;

            for (unsigned v = 0; v < PSM_voiceCount; v++) {
                if (s_voices[v].active && s_voices[v].channel == ch && s_voices[v].note == note) {
                    if (chanState->sustain >= 64) {
                        s_voices[v].sustainHeld = 1;
                    } else {
                        s_voices[v].active = 0;
                        keyOffBits |= (1u << v);
                    }
                }
            }

            if (keyOffBits) {
                SPU_KEY_OFF_LOW = keyOffBits & 0xFFFF;
                SPU_KEY_OFF_HIGH = (keyOffBits >> 16) & 0xFFFF;
            }
            break;
        }

        case PSM_PITCH_BEND: {
            chanState->pitchBend = (int16_t)(ev->data & 0xFFFF);
            updateChannelPitch(ch);
            break;
        }

        case PSM_CC_VOLUME:
            chanState->volume = ev->data & 0x7F;
            updateChannelVolumes(ch);
            break;

        case PSM_CC_PAN:
            chanState->pan = ev->data & 0x7F;
            updateChannelVolumes(ch);
            break;

        case PSM_CC_EXPRESSION:
            chanState->expression = ev->data & 0x7F;
            updateChannelVolumes(ch);
            break;

        case PSM_CC_SUSTAIN: {
            uint8_t val = ev->data & 0x7F;
            chanState->sustain = val;
            if (val < 64) {
                // Release all sustain-held voices on this channel
                uint32_t keyOffBits = 0;
                for (unsigned v = 0; v < PSM_voiceCount; v++) {
                    if (s_voices[v].active && s_voices[v].sustainHeld && s_voices[v].channel == ch) {
                        s_voices[v].active = 0;
                        s_voices[v].sustainHeld = 0;
                        keyOffBits |= (1u << v);
                    }
                }
                if (keyOffBits) {
                    SPU_KEY_OFF_LOW = keyOffBits & 0xFFFF;
                    SPU_KEY_OFF_HIGH = (keyOffBits >> 16) & 0xFFFF;
                }
            }
            break;
        }

        case PSM_CC_MODULATION:
            chanState->modulation = ev->data & 0x7F;
            // Vibrato is not implemented in this minimal player;
            // would require per-tick pitch updates like midi2spd does.
            break;

        case PSM_CC_REVERB:
            chanState->reverb = ev->data & 0x7F;
            break;

        case PSM_PROGRAM_CHANGE:
            chanState->program = ev->data & 0x7F;
            break;

        case PSM_TEMPO_CHANGE:
            s_tickRateFP = ev->data;
            updateHblanks();
            break;

        case PSM_LOOP_POINT:
            s_loopEventIndex = PSM_currentEvent;
            break;

        case PSM_END:
            // Loop back to loop point
            if (s_loopEventIndex < PSM_eventCount) {
                PSM_currentEvent = s_loopEventIndex;
                s_waitRemaining = 0;
                // Don't set PSM_playing = 0; we loop
            } else {
                PSM_playing = 0;
            }
            break;

        case PSM_LONG_WAIT:
            s_waitRemaining += ev->data;
            break;

        default:
            break;
    }
}

// ============================================================================
// Main poll function
// ============================================================================

void PSM_Poll(void) {
    if (!PSM_playing || s_events == NULL) return;

    s_globalTick++;

    // Consume any remaining wait from previous tick
    if (s_waitRemaining > 0) {
        s_waitRemaining--;
        return;
    }

    // Process events until we need to wait
    while (PSM_currentEvent < PSM_eventCount) {
        const struct PsmEvent* ev = &s_events[PSM_currentEvent];

        // Check delta tick - do we need to wait?
        if (ev->deltaTick > 0) {
            // Consume the delta by setting wait and decrementing
            s_waitRemaining = ev->deltaTick - 1;  // -1 because this tick counts
            // Process the event, then return
            PSM_currentEvent++;
            processEvent(ev);

            // If the event was END and we looped, don't return - continue processing
            if (ev->type == PSM_END && PSM_playing) continue;

            return;
        }

        // Delta is 0 - process immediately and continue
        PSM_currentEvent++;
        processEvent(ev);

        // If we just hit END and looped, continue from the loop point
        if (ev->type == PSM_END && PSM_playing) continue;

        // If LONG_WAIT added wait ticks, return
        if (s_waitRemaining > 0) {
            s_waitRemaining--;
            return;
        }
    }

    // Ran out of events without hitting END
    PSM_playing = 0;
}

void PSM_Silence(void) {
    SPUInit();
    for (int i = 0; i < 24; i++) SPUResetVoice(i);
    for (int i = 0; i < MAX_VOICES; i++) {
        s_voices[i].active = 0;
        s_voices[i].sustainHeld = 0;
    }
    PSM_playing = 0;
    s_events = NULL;
    s_waitRemaining = 0;
}
