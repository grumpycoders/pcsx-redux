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

#include "spdplayer/spdplayer.h"

#include <stddef.h>
#include <stdint.h>

#include "common/hardware/dma.h"
#include "common/hardware/spu.h"

// SPUDUMP magic: "PSXSPUDUMP v1r1\0\0"
static const uint8_t s_magic[16] = {
    'P', 'S', 'X', 'S', 'P', 'U', 'D', 'U',
    'M', 'P', 'v', '1', 'r', '1', '\0', '\0',
};

// Packet types
#define PKT_REG_WRITE    0x00
#define PKT_WAIT         0x01
#define PKT_END_PATTERN  0x02
#define PKT_LOOP_POINT   0x03
#define PKT_TRACE_BEGIN  0x04
#define PKT_ORDER_TABLE  0x10
#define PKT_PATTERN_HDR  0x11
#define PKT_SUBSONG_TBL  0x12
#define PKT_MACRO_DEF    0x13
#define PKT_MACRO_INVOKE 0x14
#define PKT_SAMPLE_DIR   0x20
#define PKT_SAMPLE_DATA  0x21
#define PKT_TICK_RATE    0x30
#define PKT_TITLE        0x40
#define PKT_AUTHOR       0x41
#define PKT_GAME_ID      0x42
#define PKT_COMMENT      0x43
#define PKT_SUBSONG_NAME 0x44
#define PKT_VOICE_COUNT  0x45

#define MAX_ORDERS   256
#define MAX_PATTERNS 256
#define MAX_SAMPLES  128
#define MAX_MACROS   256
#define MAX_MACRO_WRITES 8

struct SPDSampleInfo {
    uint16_t spuAddr;   // in 8-byte units
    uint16_t length;    // in 8-byte units
    uint16_t loopAddr;  // in 8-byte units
    uint16_t flags;     // bit 0: has loop
};

// Public state
unsigned SPD_VoiceCount = 24;
unsigned SPD_OrderCount = 0;
unsigned SPD_CurrentOrder = 0;
unsigned SPD_PatternCount = 0;
unsigned SPD_SampleCount = 0;
uint32_t SPD_hblanks = 0;
int SPD_ChangeOrderNextTick = 0;
unsigned SPD_NextOrder = 0;

// Private state
static const uint8_t* s_fileBase = NULL;
static const uint32_t* s_stream = NULL;
static const uint32_t* s_loopPoint = NULL;
static uint32_t s_waitRemaining = 0;
static uint32_t s_masterVolume = 16384;

// Order table: each entry is a pattern index
static uint16_t s_orderTable[MAX_ORDERS];
static uint32_t s_orderFlags = 0;
static uint32_t s_orderLoopTarget = 0;

// Pattern table: each entry is a byte offset from file start
static uint32_t s_patternOffsets[MAX_PATTERNS];

// Sample directory for SFX playback
static struct SPDSampleInfo s_samples[MAX_SAMPLES];

// Macro system: stored sequences of voice-0-relative register writes
struct SPDMacroWrite {
    uint16_t offset;  // voice-0-relative register offset
    uint16_t value;
};

struct SPDMacro {
    struct SPDMacroWrite writes[MAX_MACRO_WRITES];
    uint8_t writeCount;
};

static struct SPDMacro s_macros[MAX_MACROS];
static unsigned s_macroCount = 0;

// Tick rate in 16.16 fixed-point Hz
static uint32_t s_tickRateFP = 50 << 16;  // default 50 Hz

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
    SPU_VOICES[voiceID].adsrLo = 0x000f;
    SPU_VOICES[voiceID].currentVolume = 0;
    SPU_VOICES[voiceID].sampleRepeatAddr = 0;
    SPU_VOICES[voiceID].adsrHi = 0x0000;
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

static void SPUUnMute() { SPU_CTRL = 0xc000; }

static void SPUWaitIdle() {
    do {
        for (unsigned c = 0; c < 2045; c++) __asm__ volatile("");
    } while ((SPU_STATUS & 0x07ff) != 0);
}

static void updateHblanks() {
    uint32_t status = GPU_STATUS;
    int isPalConsole = *((const char*)0xbfc7ff52) == 'E';
    int isPal = (status & 0x00100000) != 0;
    uint32_t hlinesPerSecond;
    if (isPal && isPalConsole) {
        hlinesPerSecond = 15625;   // 312.5 * 50.000
    } else if (isPal && !isPalConsole) {
        hlinesPerSecond = 15769;   // 312.5 * 50.460
    } else if (!isPal && isPalConsole) {
        hlinesPerSecond = 15607;   // 262.5 * 59.393 (approx)
    } else {
        hlinesPerSecond = 15734;   // 262.5 * 59.940
    }
    // s_tickRateFP is 16.16 fixed-point Hz.
    // hblanks = hlinesPerSecond / tickRate
    // To avoid losing precision: hblanks = (hlinesPerSecond << 16) / s_tickRateFP
    if (s_tickRateFP > 0) {
        SPD_hblanks = (hlinesPerSecond << 16) / s_tickRateFP;
    } else {
        SPD_hblanks = hlinesPerSecond / 50;
    }
}

// Read a packet header. Returns the type in the upper 8 bits of the return
// value and the payload length in 32-bit words in the lower 24 bits.
static inline uint32_t readPacketHeader(const uint32_t* ptr) { return *ptr; }

static inline uint8_t packetType(uint32_t header) { return (header >> 24) & 0xff; }

static inline uint32_t packetLength(uint32_t header) { return header & 0x00ffffff; }

// Apply a macro invocation: look up macro by index, apply writes with voice offset.
static void applyMacro(uint16_t macroIdx, uint16_t voice) {
    if (macroIdx >= s_macroCount) return;
    volatile uint16_t* spuBase = (volatile uint16_t*)0x1f801c00;
    struct SPDMacro* macro = &s_macros[macroIdx];
    uint16_t voiceOffset = voice * 0x10;
    for (uint8_t i = 0; i < macro->writeCount; i++) {
        uint16_t offset = macro->writes[i].offset + voiceOffset;
        spuBase[offset / 2] = macro->writes[i].value;
    }
}

// Apply a batch of register writes from a packet payload.
// Virtual register addresses:
//   0xEFFF = inline wait (value = tick count)
//   0xF000+ = macro invocation (offset & 0x0FFF = macroIndex, value = voice)
// Returns the number of words consumed. Sets *waitOut if an inline wait is hit.
// Returns accumulated inline wait ticks (0 if no inline wait encountered).
static uint32_t applyRegWrites(const uint32_t* payload, uint32_t count) {
    volatile uint16_t* spuBase = (volatile uint16_t*)0x1f801c00;
    uint32_t waitAccum = 0;
    for (uint32_t i = 0; i < count; i++) {
        uint32_t word = payload[i];
        uint16_t offset = (word >> 16) & 0xffff;
        uint16_t value = word & 0xffff;
        if (offset == 0xEFFF) {
            // Inline wait - accumulate (may span multiple words for large values)
            waitAccum += value;
        } else if (offset >= 0xF000) {
            // Macro invocation
            applyMacro(offset & 0x0FFF, value);
        } else {
            spuBase[offset / 2] = value;
        }
    }
    return waitAccum;
}

unsigned SPD_Check(const void* data, uint32_t size) {
    if (size < 16) return 0;
    const uint8_t* p = (const uint8_t*)data;
    for (int i = 0; i < 16; i++) {
        if (p[i] != s_magic[i]) return 0;
    }
    return 1;
}

// Parse packets from a buffer, optionally skipping sample uploads.
static void parsePackets(const uint8_t* base, uint32_t size, int skipSamples) {
    const uint32_t* ptr = (const uint32_t*)(base + 16);
    const uint32_t* end = (const uint32_t*)(base + size);

    while (ptr < end) {
        uint32_t header = readPacketHeader(ptr);
        uint8_t type = packetType(header);
        uint32_t len = packetLength(header);
        const uint32_t* payload = ptr + 1;

        switch (type) {
            case PKT_ORDER_TABLE:
                if (len >= 2) {
                    s_orderFlags = payload[0];
                    s_orderLoopTarget = payload[1];
                    SPD_OrderCount = len - 2;
                    if (SPD_OrderCount > MAX_ORDERS) SPD_OrderCount = MAX_ORDERS;
                    for (unsigned i = 0; i < SPD_OrderCount; i++) {
                        s_orderTable[i] = payload[2 + i] & 0xffff;
                    }
                }
                break;

            case PKT_PATTERN_HDR:
                if (len >= 1 && SPD_PatternCount < MAX_PATTERNS) {
                    s_patternOffsets[SPD_PatternCount] = payload[0];
                    SPD_PatternCount++;
                }
                break;

            case PKT_MACRO_DEF:
                if (len >= 2) {
                    uint16_t macroIdx = payload[0] & 0xffff;
                    if (macroIdx < MAX_MACROS) {
                        uint32_t writeCount = len - 1;
                        if (writeCount > MAX_MACRO_WRITES) writeCount = MAX_MACRO_WRITES;
                        s_macros[macroIdx].writeCount = (uint8_t)writeCount;
                        for (uint32_t j = 0; j < writeCount; j++) {
                            uint32_t word = payload[1 + j];
                            s_macros[macroIdx].writes[j].offset = (word >> 16) & 0xffff;
                            s_macros[macroIdx].writes[j].value = word & 0xffff;
                        }
                        if (macroIdx >= s_macroCount) s_macroCount = macroIdx + 1;
                    }
                }
                break;

            case PKT_SAMPLE_DIR:
                if (len >= 1) {
                    SPD_SampleCount = payload[0];
                    if (SPD_SampleCount > MAX_SAMPLES) SPD_SampleCount = MAX_SAMPLES;
                    for (unsigned i = 0; i < SPD_SampleCount; i++) {
                        uint32_t w0 = payload[1 + i * 2];
                        uint32_t w1 = payload[1 + i * 2 + 1];
                        s_samples[i].spuAddr = (w0 >> 16) & 0xffff;
                        s_samples[i].length = w0 & 0xffff;
                        s_samples[i].loopAddr = (w1 >> 16) & 0xffff;
                        s_samples[i].flags = w1 & 0xffff;
                    }
                }
                break;

            case PKT_SAMPLE_DATA:
                if (!skipSamples && len >= 1) {
                    uint32_t baseAddr = payload[0];         // in 8-byte units
                    uint32_t dataSize = (len - 1) * 4;      // remaining payload in bytes
                    SPUUpload(baseAddr * 8, (const uint8_t*)&payload[1], dataSize);
                }
                break;

            case PKT_TICK_RATE:
                if (len >= 1) {
                    s_tickRateFP = payload[0];
                }
                break;

            case PKT_VOICE_COUNT:
                if (len >= 1) {
                    SPD_VoiceCount = payload[0];
                    if (SPD_VoiceCount > 24) SPD_VoiceCount = 24;
                }
                break;

            default:
                // Skip unknown packets (metadata, etc.)
                break;
        }

        ptr = payload + len;
    }
}

static unsigned loadInternal(const void* data, uint32_t size,
                             const void* sampleData, uint32_t sampleSize) {
    if (!SPD_Check(data, size)) return 0;

    SPUInit();

    s_fileBase = (const uint8_t*)data;
    s_stream = NULL;
    s_loopPoint = NULL;
    s_waitRemaining = 0;
    SPD_VoiceCount = 24;
    SPD_OrderCount = 0;
    SPD_CurrentOrder = 0;
    SPD_PatternCount = 0;
    SPD_SampleCount = 0;
    SPD_ChangeOrderNextTick = 0;
    SPD_NextOrder = 0;
    s_orderFlags = 0;
    s_orderLoopTarget = 0;
    s_tickRateFP = 50 << 16;
    s_macroCount = 0;

    if (sampleData && sampleSize > 16) {
        // Load samples from separate file, skip samples in main file
        if (SPD_Check(sampleData, sampleSize)) {
            parsePackets((const uint8_t*)sampleData, sampleSize, 0);
        }
        parsePackets(s_fileBase, size, 1);
    } else if (sampleData == NULL) {
        // Samples already in SPU RAM, skip sample upload
        parsePackets(s_fileBase, size, 1);
    } else {
        // Self-contained file: load everything including samples
        parsePackets(s_fileBase, size, 0);
    }

    // Reset all 24 voices
    for (unsigned i = 0; i < 24; i++) SPUResetVoice(i);

    SPUUnMute();

    // Calculate hblank timing
    updateHblanks();

    // Position stream at the first pattern if we have an order table
    if (SPD_OrderCount > 0 && SPD_PatternCount > 0) {
        SPD_CurrentOrder = 0;
        uint16_t patIdx = s_orderTable[0];
        if (patIdx < SPD_PatternCount) {
            s_stream = (const uint32_t*)(s_fileBase + s_patternOffsets[patIdx]);
        }
    }

    return SPD_VoiceCount;
}

unsigned SPD_Load(const void* data, uint32_t size) {
    return loadInternal(data, size, (const void*)-1, 0);
}

unsigned SPD_LoadEx(const void* data, uint32_t size,
                    const void* sampleData, uint32_t sampleSize) {
    return loadInternal(data, size, sampleData, sampleSize);
}

void SPD_Seek(unsigned order) {
    if (order >= SPD_OrderCount) return;

    uint16_t patIdx = s_orderTable[order];
    if (patIdx >= SPD_PatternCount) return;

    SPD_CurrentOrder = order;
    s_stream = (const uint32_t*)(s_fileBase + s_patternOffsets[patIdx]);
    s_loopPoint = NULL;
    s_waitRemaining = 0;
}

static void advanceOrder() {
    SPD_CurrentOrder++;
    if (SPD_CurrentOrder >= SPD_OrderCount) {
        if (s_orderFlags & 1) {
            // Loop
            SPD_CurrentOrder = s_orderLoopTarget;
        } else {
            // Stop - park at last order
            SPD_CurrentOrder = SPD_OrderCount - 1;
            s_stream = NULL;
            return;
        }
    }

    uint16_t patIdx = s_orderTable[SPD_CurrentOrder];
    if (patIdx < SPD_PatternCount) {
        s_stream = (const uint32_t*)(s_fileBase + s_patternOffsets[patIdx]);
    } else {
        s_stream = NULL;
    }
    s_loopPoint = NULL;
}

void SPD_Poll() {
    if (SPD_ChangeOrderNextTick) {
        SPD_ChangeOrderNextTick = 0;
        SPD_Seek(SPD_NextOrder);
    }

    if (s_waitRemaining > 0) {
        s_waitRemaining--;
        return;
    }

    if (s_stream == NULL) return;

    // Process packets until we hit a wait or run out of stream
    while (1) {
        uint32_t header = readPacketHeader(s_stream);
        uint8_t type = packetType(header);
        uint32_t len = packetLength(header);
        const uint32_t* payload = s_stream + 1;

        switch (type) {
            case PKT_REG_WRITE: {
                uint32_t waitTicks = applyRegWrites(payload, len);
                if (waitTicks > 0) {
                    s_waitRemaining = waitTicks;
                    s_stream = payload + len;
                    return;
                }
                break;
            }

            case PKT_WAIT:
                if (len >= 1) {
                    s_waitRemaining = payload[0];
                }
                s_stream = payload + len;
                return;

            case PKT_END_PATTERN:
                s_stream = payload + len;
                advanceOrder();
                if (s_stream == NULL) return;
                continue;

            case PKT_LOOP_POINT:
                s_loopPoint = s_stream;
                break;

            case PKT_TICK_RATE:
                if (len >= 1) {
                    s_tickRateFP = payload[0];
                    updateHblanks();
                }
                break;

            default:
                // Skip unknown packets in the stream
                break;
        }

        s_stream = payload + len;
    }
}

void SPD_SetMasterVolume(uint32_t volume) { s_masterVolume = volume; }

void SPD_PlaySoundEffect(unsigned voice, unsigned sampleID, uint16_t pitch, int16_t volume) {
    if (voice >= 24) return;
    if (sampleID >= SPD_SampleCount) return;

    struct SPDSampleInfo* sample = &s_samples[sampleID];

    // Key off first
    uint32_t voiceBit = 1 << voice;
    SPU_KEY_OFF_LOW = voiceBit & 0xffff;
    SPU_KEY_OFF_HIGH = (voiceBit >> 16) & 0xffff;

    SPU_VOICES[voice].volumeLeft = volume;
    SPU_VOICES[voice].volumeRight = volume;
    SPU_VOICES[voice].sampleStartAddr = sample->spuAddr;
    SPU_VOICES[voice].sampleRate = pitch;
    SPU_VOICES[voice].adsrLo = 0x00ff;  // fast release, moderate sustain rate
    SPU_VOICES[voice].adsrHi = 0x001f;  // fast attack, fast decay, max sustain
    // No repeat address write needed - loop points are in the ADPCM block flags

    // Key on
    SPU_KEY_ON_LOW = voiceBit & 0xffff;
    SPU_KEY_ON_HIGH = (voiceBit >> 16) & 0xffff;
}

void SPD_Silence() {
    SPUInit();
    for (unsigned i = 0; i < 24; i++) {
        SPUResetVoice(i);
    }
    s_stream = NULL;
    s_waitRemaining = 0;
}
