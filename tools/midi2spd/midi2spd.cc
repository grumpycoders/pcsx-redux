/***************************************************************************
 *   Copyright (C) 2025 PCSX-Redux authors                                 *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <map>
#include <numbers>
#include <string>
#include <string_view>
#include <vector>

#include "flags.h"
#include "fmt/format.h"
#include "support/file.h"
#include "supportpsx/adpcm.h"

#define TSF_IMPLEMENTATION
#define TSF_NO_STDIO
#include "tsf.h"

// ============================================================================
// MIDI Parser
// ============================================================================

// MIDI status byte types (upper nibble of status byte)
enum MidiStatus : uint8_t {
    MIDI_NOTE_OFF = 0x80,
    MIDI_NOTE_ON = 0x90,
    MIDI_POLY_PRESSURE = 0xA0,
    MIDI_CONTROL_CHANGE = 0xB0,
    MIDI_PROGRAM_CHANGE = 0xC0,
    MIDI_CHANNEL_PRESSURE = 0xD0,
    MIDI_PITCH_BEND = 0xE0,
    MIDI_SYSTEM = 0xF0,
    MIDI_META = 0xFF,
};

// MIDI meta event types
enum MidiMeta : uint8_t {
    MIDI_META_TEXT = 0x01,
    MIDI_META_COPYRIGHT = 0x02,
    MIDI_META_TRACK_NAME = 0x03,
    MIDI_META_MARKER = 0x06,
    MIDI_META_END_OF_TRACK = 0x2F,
    MIDI_META_TEMPO = 0x51,
};

// MIDI control change numbers
enum MidiCC : uint8_t {
    MIDI_CC_BANK_MSB = 0,
    MIDI_CC_MODULATION = 1,
    MIDI_CC_VOLUME = 7,
    MIDI_CC_PAN = 10,
    MIDI_CC_EXPRESSION = 11,
    MIDI_CC_BANK_LSB = 32,
    MIDI_CC_SUSTAIN = 64,
    MIDI_CC_RPN_LSB = 100,
    MIDI_CC_RPN_MSB = 101,
    MIDI_CC_DATA_ENTRY_MSB = 6,
    MIDI_CC_DATA_ENTRY_LSB = 38,
    MIDI_CC_REVERB_SEND = 91,
    MIDI_CC_ALL_SOUND_OFF = 120,
    MIDI_CC_RESET_ALL = 121,
    MIDI_CC_ALL_NOTES_OFF = 123,
    MIDI_CC_LOOP_POINT = 111,
};

// MIDI drum channel (0-indexed)
static constexpr uint8_t MIDI_DRUM_CHANNEL = 9;

struct MidiEvent {
    uint32_t absoluteTick;
    uint8_t type;     // MidiStatus value (upper nibble) or MIDI_META
    uint8_t channel;  // 0-15
    uint8_t data1;
    uint8_t data2;
    uint32_t tempo;        // microseconds per quarter note (for tempo meta events)
    std::string textData;  // for marker/text meta events
};

static uint32_t readVLQ(const uint8_t*& p, const uint8_t* end) {
    uint32_t value = 0;
    while (p < end) {
        uint8_t b = *p++;
        value = (value << 7) | (b & 0x7F);
        if ((b & 0x80) == 0) break;
    }
    return value;
}

static uint32_t readBE16(const uint8_t* p) { return (p[0] << 8) | p[1]; }
static uint32_t readBE32(const uint8_t* p) { return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]; }

struct MidiFile {
    uint16_t format;
    uint16_t trackCount;
    uint16_t tpqn;  // ticks per quarter note
    std::vector<MidiEvent> events;

    bool parse(const uint8_t* data, size_t size) {
        const uint8_t* p = data;
        const uint8_t* end = data + size;

        // Check for RIFF/RMID wrapper (RMI files)
        if (size >= 20 && memcmp(p, "RIFF", 4) == 0 && memcmp(p + 8, "RMID", 4) == 0) {
            // Skip RIFF header, find "data" chunk containing the MIDI
            p += 12;
            while (p + 8 <= end) {
                uint32_t chunkSize = p[4] | (p[5] << 8) | (p[6] << 16) | (p[7] << 24);
                if (memcmp(p, "data", 4) == 0) {
                    p += 8;
                    end = p + chunkSize;
                    break;
                }
                p += 8 + ((chunkSize + 1) & ~1);  // RIFF chunks are 2-byte aligned
            }
        }

        // MThd header
        if (p + 14 > end || memcmp(p, "MThd", 4) != 0) return false;
        uint32_t headerLen = readBE32(p + 4);
        format = readBE16(p + 8);
        trackCount = readBE16(p + 10);
        tpqn = readBE16(p + 12);
        p += 8 + headerLen;

        // Parse all tracks
        for (uint16_t t = 0; t < trackCount && p + 8 <= end; t++) {
            if (memcmp(p, "MTrk", 4) != 0) return false;
            uint32_t trackLen = readBE32(p + 4);
            const uint8_t* trackStart = p + 8;
            const uint8_t* trackEnd = trackStart + trackLen;
            if (trackEnd > end) return false;
            parseTrack(trackStart, trackEnd);
            p = trackEnd;
        }

        // Sort all events by absolute tick (stable sort preserves order within same tick)
        std::stable_sort(events.begin(), events.end(),
                         [](const MidiEvent& a, const MidiEvent& b) { return a.absoluteTick < b.absoluteTick; });
        return true;
    }

  private:
    void parseTrack(const uint8_t* p, const uint8_t* end) {
        uint32_t absTick = 0;
        uint8_t runningStatus = 0;

        while (p < end) {
            uint32_t delta = readVLQ(p, end);
            absTick += delta;
            if (p >= end) break;

            uint8_t status = *p;
            if (status & 0x80) {
                p++;
                if (status < MIDI_SYSTEM) runningStatus = status;
            } else {
                status = runningStatus;
            }

            uint8_t type = status & 0xF0;
            uint8_t channel = status & 0x0F;

            if (status == MIDI_META) {
                // Meta event
                if (p + 1 >= end) break;
                uint8_t metaType = *p++;
                uint32_t metaLen = readVLQ(p, end);
                if (p + metaLen > end) break;
                if (metaType == MIDI_META_TEMPO && metaLen == 3) {
                    // Tempo change
                    MidiEvent ev = {};
                    ev.absoluteTick = absTick;
                    ev.type = MIDI_META;
                    ev.data1 = MIDI_META_TEMPO;
                    ev.tempo = (p[0] << 16) | (p[1] << 8) | p[2];
                    events.push_back(ev);
                } else if (metaType == MIDI_META_MARKER || metaType == MIDI_META_TEXT ||
                           metaType == MIDI_META_TRACK_NAME || metaType == MIDI_META_COPYRIGHT) {
                    // Text-based meta events
                    MidiEvent ev = {};
                    ev.absoluteTick = absTick;
                    ev.type = MIDI_META;
                    ev.data1 = metaType;
                    ev.textData = std::string((const char*)p, metaLen);
                    events.push_back(ev);
                } else if (metaType == MIDI_META_END_OF_TRACK) {
                    // End of track
                    p += metaLen;
                    break;
                }
                p += metaLen;
            } else if (status >= MIDI_SYSTEM) {
                // SysEx - skip
                uint32_t sysLen = readVLQ(p, end);
                p += sysLen;
            } else if (type == MIDI_NOTE_OFF || type == MIDI_NOTE_ON || type == MIDI_POLY_PRESSURE ||
                       type == MIDI_CONTROL_CHANGE || type == MIDI_PITCH_BEND) {
                // Two data bytes
                if (p + 2 > end) break;
                MidiEvent ev = {};
                ev.absoluteTick = absTick;
                ev.type = type;
                ev.channel = channel;
                ev.data1 = p[0];
                ev.data2 = p[1];
                // Note on with velocity 0 is actually note off
                if (type == MIDI_NOTE_ON && ev.data2 == 0) {
                    ev.type = MIDI_NOTE_OFF;
                }
                events.push_back(ev);
                p += 2;
            } else if (type == MIDI_PROGRAM_CHANGE || type == MIDI_CHANNEL_PRESSURE) {
                // One data byte
                if (p + 1 > end) break;
                MidiEvent ev = {};
                ev.absoluteTick = absTick;
                ev.type = type;
                ev.channel = channel;
                ev.data1 = *p++;
                events.push_back(ev);
            }
        }
    }
};

// ============================================================================
// SPU ADPCM Sample Management
// ============================================================================

struct SpuSample {
    uint32_t spuAddr;     // SPU RAM address in bytes
    uint32_t adpcmSize;   // size in bytes
    uint32_t sampleRate;  // original sample rate
    uint32_t rootKey;     // MIDI note of natural pitch (pitch_keycenter)
    int32_t transpose;    // semitone offset (SF2 coarseTune)
    int32_t tune;         // fine tuning in cents (SF2 fineTune + pitchCorrection)
    bool hasLoop;
    uint32_t loopStartByte;  // byte offset within ADPCM data where loop starts
    std::vector<uint8_t> adpcmData;
};

// Key for deduplicating SF2 samples: based on actual sample data identity
// Two regions referencing the same range in fontSamples share one SPU sample
struct SampleKey {
    unsigned int offset;  // start index in fontSamples
    unsigned int end;     // end index in fontSamples
    bool operator<(const SampleKey& o) const {
        if (offset != o.offset) return offset < o.offset;
        return end < o.end;
    }
};

static bool encodeSample(const int16_t* pcm, size_t sampleCount, bool loop, size_t loopStart, SpuSample& out) {
    PCSX::ADPCM::Encoder encoder;
    encoder.reset();

    // Pad to multiple of 28 samples
    size_t paddedCount = ((sampleCount + 27) / 28) * 28;
    std::vector<int16_t> padded(paddedCount, 0);
    memcpy(padded.data(), pcm, sampleCount * sizeof(int16_t));

    size_t totalBlocks = paddedCount / 28;
    out.adpcmData.resize(totalBlocks * 16 + 16);  // +16 for end block

    size_t loopStartBlock = loop ? (loopStart / 28) : 0;

    for (size_t b = 0; b < totalBlocks; b++) {
        PCSX::ADPCM::Encoder::BlockAttribute attr;
        if (loop) {
            if (b == loopStartBlock) {
                attr = PCSX::ADPCM::Encoder::BlockAttribute::LoopStart;
            } else if (b == totalBlocks - 1) {
                attr = PCSX::ADPCM::Encoder::BlockAttribute::LoopEnd;
            } else if (b > loopStartBlock) {
                attr = PCSX::ADPCM::Encoder::BlockAttribute::LoopBody;
            } else {
                attr = PCSX::ADPCM::Encoder::BlockAttribute::OneShot;
            }
        } else {
            attr = (b == totalBlocks - 1) ? PCSX::ADPCM::Encoder::BlockAttribute::OneShotEnd
                                          : PCSX::ADPCM::Encoder::BlockAttribute::OneShot;
        }
        encoder.processSPUBlock(&padded[b * 28], &out.adpcmData[b * 16], attr);
    }

    if (!loop) {
        encoder.finishSPU(&out.adpcmData[totalBlocks * 16]);
        out.adpcmData.resize((totalBlocks + 1) * 16);
    } else {
        out.adpcmData.resize(totalBlocks * 16);
    }

    out.loopStartByte = loopStartBlock * 16;
    out.hasLoop = loop;
    out.adpcmSize = out.adpcmData.size();
    return true;
}

// ============================================================================
// Voice Allocator
// ============================================================================

struct VoiceSlot {
    bool active;
    bool sustainHeld;  // note-off received but sustain pedal is down
    uint8_t midiChannel;
    uint8_t midiNote;
    uint8_t velocity;
    uint32_t startTick;
    int exclusiveGroup;  // SF2 exclusive group (0 = none)
    // Per-voice pitch state for pitch bend
    int baseMidiNote;      // the MIDI note being played
    uint32_t sampleRate;   // sample rate of the assigned sample
    int rootKey;           // root key of the assigned sample
    int transpose;         // SF2 transpose
    int tuneCents;         // SF2 fine tune
    float sf2Pan;          // SF2 region pan (-0.5 to +0.5)
    float sf2Attenuation;  // SF2 initial attenuation (centibels)
};

struct VoiceAllocator {
    VoiceSlot voices[24];
    unsigned maxVoices;
    unsigned peakVoices;
    unsigned voiceSteals;

    void init(unsigned max) {
        maxVoices = max;
        peakVoices = 0;
        voiceSteals = 0;
        memset(voices, 0, sizeof(voices));
    }

    int allocate(uint8_t channel, uint8_t note, uint8_t velocity, uint32_t tick) {
        // Find a free voice
        for (unsigned i = 0; i < maxVoices; i++) {
            if (!voices[i].active) {
                voices[i] = {};
                voices[i].active = true;
                voices[i].midiChannel = channel;
                voices[i].midiNote = note;
                voices[i].velocity = velocity;
                voices[i].startTick = tick;
                unsigned used = 0;
                for (unsigned j = 0; j < maxVoices; j++) {
                    if (voices[j].active) used++;
                }
                if (used > peakVoices) peakVoices = used;
                return (int)i;
            }
        }
        // Voice stealing priority:
        // 1. Prefer sustain-held voices (already logically released)
        // 2. Prefer lowest velocity (least audible)
        // 3. Fall back to oldest note
        int bestVoice = -1;
        int bestScore = -1;  // higher = better candidate for stealing
        for (unsigned i = 0; i < maxVoices; i++) {
            int score = 0;
            if (voices[i].sustainHeld) score += 10000;    // strongly prefer sustain-held
            score += (127 - voices[i].velocity) * 10;     // prefer low velocity
            score += (tick - voices[i].startTick) / 100;  // slight preference for older
            if (score > bestScore) {
                bestScore = score;
                bestVoice = (int)i;
            }
        }
        if (bestVoice < 0) bestVoice = 0;
        voiceSteals++;
        voices[bestVoice] = {};
        voices[bestVoice].active = true;
        voices[bestVoice].midiChannel = channel;
        voices[bestVoice].midiNote = note;
        voices[bestVoice].velocity = velocity;
        voices[bestVoice].startTick = tick;
        return bestVoice;
    }

    // Kill all active voices in a given exclusive group, returning bitmask of killed voices
    uint32_t killExclusiveGroup(int group) {
        if (group == 0) return 0;
        uint32_t mask = 0;
        for (unsigned i = 0; i < maxVoices; i++) {
            if (voices[i].active && voices[i].exclusiveGroup == group) {
                voices[i].active = false;
                voices[i].sustainHeld = false;
                mask |= (1 << i);
            }
        }
        return mask;
    }

    int find(uint8_t channel, uint8_t note) {
        for (unsigned i = 0; i < maxVoices; i++) {
            if (voices[i].active && voices[i].midiChannel == channel && voices[i].midiNote == note) {
                return (int)i;
            }
        }
        return -1;
    }

    void release(int voice) {
        if (voice >= 0 && voice < 24) {
            voices[voice].active = false;
            voices[voice].sustainHeld = false;
        }
    }

    // Mark a voice as sustain-held instead of releasing it
    void holdSustain(int voice) {
        if (voice >= 0 && voice < 24) {
            voices[voice].sustainHeld = true;
        }
    }

    // Release all sustain-held voices on a channel, returning bitmask
    uint32_t releaseSustainedVoices(uint8_t channel) {
        uint32_t mask = 0;
        for (unsigned i = 0; i < maxVoices; i++) {
            if (voices[i].active && voices[i].sustainHeld && voices[i].midiChannel == channel) {
                voices[i].active = false;
                voices[i].sustainHeld = false;
                mask |= (1 << i);
            }
        }
        return mask;
    }
};

// ============================================================================
// SPUDUMP Writer
// ============================================================================

// SPU register offsets from base 0x1F801C00
#define SPU_VOICE_OFF(v, r) ((v) * 0x10 + (r))
#define SPU_VOL_LEFT(v) SPU_VOICE_OFF(v, 0x00)
#define SPU_VOL_RIGHT(v) SPU_VOICE_OFF(v, 0x02)
#define SPU_PITCH(v) SPU_VOICE_OFF(v, 0x04)
#define SPU_SAMPLE_START(v) SPU_VOICE_OFF(v, 0x06)
#define SPU_ADSR_LO(v) SPU_VOICE_OFF(v, 0x08)
#define SPU_ADSR_HI(v) SPU_VOICE_OFF(v, 0x0A)
#define SPU_REPEAT_ADDR(v) SPU_VOICE_OFF(v, 0x0E)
#define SPU_KEY_ON_LO 0x188
#define SPU_KEY_ON_HI 0x18A
#define SPU_KEY_OFF_LO 0x18C
#define SPU_KEY_OFF_HI 0x18E
#define SPU_MAIN_VOL_L 0x180
#define SPU_MAIN_VOL_R 0x182
#define SPU_NOISE_LO 0x194
#define SPU_NOISE_HI 0x196
#define SPU_REVERB_LO 0x198
#define SPU_REVERB_HI 0x19A
#define SPU_REVERB_OUT_L 0x184
#define SPU_REVERB_OUT_R 0x186
#define SPU_REVERB_BASE 0x1A2  // mBASE: reverb work area start address (in 8-byte units)
#define SPU_SPUCNT 0x1AA       // SPU control register (bit 7 = reverb master enable)
#define SPU_REVERB_CFG 0x1C0   // Start of 32 reverb configuration registers (0x1C0-0x1FE)

// ============================================================================
// SPU Reverb Presets
// ============================================================================

// Each preset has 32 configuration register values and a buffer size requirement.
// The reverb buffer occupies the top of SPU RAM: mBASE*8 through 0x7FFFE.
struct ReverbPreset {
    const char* name;
    uint32_t bufferSize;  // bytes needed at top of SPU RAM
    uint16_t regs[32];    // dAPF1 through vRIN
    uint16_t outVolL;     // reverb output volume left
    uint16_t outVolR;     // reverb output volume right
};

// Presets from PS1 BIOS / psx-spx documentation
static const ReverbPreset REVERB_PRESETS[] = {
    {"off",
     0x10,
     {0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001,
      0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0000, 0x0000, 0x0001, 0x0001, 0x0001, 0x0001,
      0x0001, 0x0001, 0x0000, 0x0000, 0x0001, 0x0001, 0x0001, 0x0001, 0x0000, 0x0000},
     0x0000,
     0x0000},
    {"room",
     0x1F40,
     {// Studio Small
      0x0033, 0x0025, 0x70F0, 0x4FA8, 0xBCE0, 0x4410, 0xC0F0, 0x9C00, 0x5280, 0x4EC0, 0x03E4,
      0x031B, 0x03A4, 0x02AF, 0x0372, 0x0266, 0x031C, 0x025D, 0x025C, 0x018E, 0x022F, 0x0135,
      0x01D2, 0x00B7, 0x018F, 0x00B5, 0x00B4, 0x0080, 0x004C, 0x0026, 0x8000, 0x8000},
     0x3800,
     0x3800},
    {"studio",
     0x4840,
     {// Studio Medium
      0x00B1, 0x007F, 0x70F0, 0x4FA8, 0xBCE0, 0x4510, 0xBEF0, 0xB4C0, 0x5280, 0x4EC0, 0x0904,
      0x076B, 0x0824, 0x065F, 0x07A2, 0x0616, 0x076C, 0x05ED, 0x05EC, 0x042E, 0x050F, 0x0305,
      0x0462, 0x02B7, 0x042F, 0x0265, 0x0264, 0x01B2, 0x0100, 0x0080, 0x8000, 0x8000},
     0x3800,
     0x3800},
    {"hall",
     0xADE0,
     {// Hall
      0x01A5, 0x0139, 0x6000, 0x5000, 0x4C00, 0xB800, 0xBC00, 0xC000, 0x6000, 0x5C00, 0x15BA,
      0x11BB, 0x14C2, 0x10BD, 0x11BC, 0x0DC1, 0x11C0, 0x0DC3, 0x0DC0, 0x09C1, 0x0BC4, 0x07C1,
      0x0A00, 0x06CD, 0x09C2, 0x05C1, 0x05C0, 0x041A, 0x0274, 0x013A, 0x8000, 0x8000},
     0x3000,
     0x3000},
    {"space",
     0xF6C0,
     {// Space Echo
      0x033D, 0x0231, 0x7E00, 0x5000, 0xB400, 0xB000, 0x4C00, 0xB000, 0x6000, 0x5400, 0x1ED6,
      0x1A31, 0x1D14, 0x183B, 0x1BC2, 0x16B2, 0x1A32, 0x15EF, 0x15EE, 0x1055, 0x1334, 0x0F2D,
      0x11F6, 0x0C5D, 0x1056, 0x0AE1, 0x0AE0, 0x07A2, 0x0464, 0x0232, 0x8000, 0x8000},
     0x2800,
     0x2800},
};
static constexpr int REVERB_PRESET_COUNT = sizeof(REVERB_PRESETS) / sizeof(REVERB_PRESETS[0]);
static constexpr int REVERB_DEFAULT_PRESET = 3;  // hall

// SPUDUMP packet types
enum SpdPacket : uint8_t {
    SPD_PKT_REG_WRITE = 0x00,
    SPD_PKT_WAIT = 0x01,
    SPD_PKT_END_PATTERN = 0x02,
    SPD_PKT_LOOP_POINT = 0x03,
    SPD_PKT_ORDER_TABLE = 0x10,
    SPD_PKT_PATTERN_HDR = 0x11,
    SPD_PKT_MACRO_DEF = 0x13,
    SPD_PKT_SAMPLE_DIR = 0x20,
    SPD_PKT_SAMPLE_DATA = 0x21,
    SPD_PKT_TICK_RATE = 0x30,
    SPD_PKT_TITLE = 0x40,
    SPD_PKT_AUTHOR = 0x41,
    SPD_PKT_COMMENT = 0x43,
    SPD_PKT_VOICE_COUNT = 0x45,
};

// SPU RAM layout
static constexpr uint32_t SPU_RAM_BASE = 0x1010;   // first usable address (after capture buffers)
static constexpr uint32_t SPU_RAM_SIZE = 0x80000;  // 512KB

struct RegWrite {
    uint16_t offset;
    uint16_t value;
};

struct StreamEvent {
    enum Type { REG_WRITES, WAIT, END_PATTERN, LOOP_POINT, TICK_RATE };
    Type type;
    std::vector<RegWrite> writes;  // includes both real reg writes and macro invokes
    uint32_t waitTicks;
    uint32_t tickRate;
};

// Virtual register addresses within register write packets.
// The player checks the offset and dispatches accordingly.

// Macro invocation: offset = 0xF000 | macroIndex, value = voice number.
#define MACRO_INVOKE_BASE 0xF000

// Inline wait: offset = 0xEFFF, value = tick count.
// Collapses a wait into the preceding register write packet.
#define INLINE_WAIT_ADDR 0xEFFF

// A macro captures voice-0-relative register writes that are constant
// for a given instrument/zone combination (ADSR + sample start).
struct MacroDef {
    std::vector<RegWrite> writes;  // offsets are voice-0-relative
};

// Key for deduplicating macros: the set of register values they write
struct MacroKey {
    uint16_t adsrLo;
    uint16_t adsrHi;
    uint16_t sampleStart;  // in 8-byte units
    bool operator<(const MacroKey& o) const {
        if (adsrLo != o.adsrLo) return adsrLo < o.adsrLo;
        if (adsrHi != o.adsrHi) return adsrHi < o.adsrHi;
        return sampleStart < o.sampleStart;
    }
};

using FilePtr = PCSX::IO<PCSX::File>;

static void writeSampleDir(FilePtr& f, const std::vector<SpuSample>& samples);
static void writeSamplePackets(FilePtr& f, const std::vector<SpuSample>& samples);
static void writeMacroDefs(FilePtr& f, const std::vector<MacroDef>& macroDefs);
static void writeStreamPackets(FilePtr& f, const std::vector<StreamEvent>& stream);

static void writePacket(FilePtr& f, uint8_t type, const uint32_t* payload, uint32_t words) {
    uint32_t header = (words & 0x00FFFFFF) | ((uint32_t)type << 24);
    f->write<uint32_t>(header);
    for (uint32_t i = 0; i < words; i++) {
        f->write<uint32_t>(payload[i]);
    }
}

static void writePacketEmpty(FilePtr& f, uint8_t type) {
    uint32_t header = (uint32_t)type << 24;
    f->write<uint32_t>(header);
}

static void writePacketString(FilePtr& f, uint8_t type, const char* str) {
    size_t len = strlen(str) + 1;
    size_t padded = (len + 3) & ~3;
    uint32_t words = (uint32_t)(padded / 4);
    uint32_t header = (words & 0x00FFFFFF) | ((uint32_t)type << 24);
    f->write<uint32_t>(header);
    std::vector<uint8_t> buf(padded, 0);
    memcpy(buf.data(), str, len);
    f->write(buf.data(), padded);
}

// ============================================================================
// MIDI Note -> Frequency
// ============================================================================

static double midiNoteToFreq(int note) { return 440.0 * pow(2.0, (note - 69) / 12.0); }

// GM-standard velocity curve: attempt to approximate the roughly quadratic
// relationship between velocity and perceived loudness. The MIDI spec doesn't
// mandate a specific curve, but most GM implementations use something close to
// velocity squared. Returns a value in the range [0, 127].
static int velocityCurve(int velocity) {
    // Quadratic: out = vel^2 / 127
    return (velocity * velocity + 63) / 127;  // +63 for rounding
}

// Combine MIDI pan (0-127, CC#10) with SF2 region pan (-0.5 to +0.5).
// Returns effective pan in 0-127 range.
static int combinePan(int midiPan, float sf2Pan) {
    // SF2 pan: -0.5 = hard left, 0 = center, +0.5 = hard right
    // Convert to 0-127 range: center = 64
    int sf2PanMidi = (int)(64.0f + sf2Pan * 128.0f);
    if (sf2PanMidi < 0) sf2PanMidi = 0;
    if (sf2PanMidi > 127) sf2PanMidi = 127;
    // Combine: both offsets from center, sum the deviations
    int combined = 64 + (midiPan - 64) + (sf2PanMidi - 64);
    if (combined < 0) combined = 0;
    if (combined > 127) combined = 127;
    return combined;
}

// Compute left and right volume from velocity, channel state, and optional SF2 region pan.
// sf2Pan is the region's pan value (-0.5 to +0.5), sf2Attenuation is in centibels (0 = none).
static void computeVolumes(int velocity, uint8_t chanVolume, uint8_t chanExpression, int pan, float sf2Pan,
                           float sf2Attenuation, uint16_t& volL, uint16_t& volR) {
    // Apply GM velocity curve
    int vel = velocityCurve(velocity);

    // Apply SF2 initial attenuation (centibels, 0 = full volume, higher = quieter)
    // Convert to a gain multiplier: gain = 10^(-attenuation_cB / 200)
    float attnGain = 1.0f;
    if (sf2Attenuation > 0.0f) {
        attnGain = powf(10.0f, -sf2Attenuation / 200.0f);
        if (attnGain < 0.0f) attnGain = 0.0f;
    }

    int vol = (int)(vel * chanVolume * chanExpression * attnGain) / (127 * 127);

    // Combine MIDI pan with SF2 region pan
    int effectivePan = combinePan(pan, sf2Pan);
    int panL = (effectivePan <= 64) ? 127 : (127 - effectivePan) * 2;
    int panR = (effectivePan >= 64) ? 127 : effectivePan * 2;
    if (panL > 127) panL = 127;
    if (panR > 127) panR = 127;

    volL = (uint16_t)((vol * panL * 0x3FFF) / (127 * 127));
    volR = (uint16_t)((vol * panR * 0x3FFF) / (127 * 127));
}

// Compute SPU pitch register value.
// pitchBend: -8192 to 8191, bendRange: in cents (e.g., 200 = 2 semitones)
// modCents: additional pitch offset in cents from modulation/vibrato LFO
static uint16_t computeSpuPitch(int midiNote, uint32_t sampleRate, int rootKey, int transpose, int tuneCents,
                                int16_t pitchBend = 0, uint16_t bendRangeCents = 200, double modCents = 0.0) {
    // Effective note = midiNote + transpose + tune/100
    double effectiveNote = midiNote + transpose + tuneCents / 100.0;
    // Apply pitch bend: bend range is in cents, bend value is -8192..8191 mapping to -range..+range
    if (pitchBend != 0 && bendRangeCents > 0) {
        double bendSemitones = (pitchBend / 8192.0) * (bendRangeCents / 100.0);
        effectiveNote += bendSemitones;
    }
    // Apply modulation/vibrato offset (in cents -> semitones)
    if (modCents != 0.0) {
        effectiveNote += modCents / 100.0;
    }
    double noteFreq = 440.0 * pow(2.0, (effectiveNote - 69) / 12.0);
    double rootFreq = midiNoteToFreq(rootKey);
    // SPU pitch register: 0x1000 = 44100 Hz playback rate.
    double pitch = (noteFreq / rootFreq) * ((double)sampleRate / 44100.0) * 0x1000;
    if (pitch < 0) pitch = 0;
    if (pitch > 0x3FFF) pitch = 0x3FFF;
    return (uint16_t)pitch;
}

// ============================================================================
// SF2 ADSR -> SPU ADSR
// ============================================================================

// SPU ADSR register layout:
//   ADSR upper (offset +0x0A):
//     bits 0-3:   sustain level (0-15, where 15 = max)
//     bits 4-7:   decay rate (0-15)
//     bits 8-14:  attack rate (0-127)
//     bit  15:    attack mode (0 = linear, 1 = exponential)
//   ADSR lower (offset +0x08):
//     bits 0-4:   release rate (0-31)
//     bit  5:     release mode (0 = linear, 1 = exponential)
//     bits 6-10:  sustain rate (0-31) [note: shifted by 6 in the register]
//     bit  13:    sustain direction (0 = increase, 1 = decrease)
//     bit  14:    sustain mode (0 = linear, 1 = exponential)
//
// SF2 envelope times are in "timecents" where the time in seconds = 2^(tc/1200).
// A value of 0 tc = 1 second. -12000 tc = essentially instant.
// The SPU rates are exponential step counters, not direct time values.
// We map SF2 times to SPU rates using lookup tables derived from psx-spx documentation.

// SPU ADSR timing formulas (from psx-spx documentation and pcsx-redux/src/spu/adsr.cc):
//
// Attack (rate 0-127, exponential mode):
//   At 44100 Hz sample rate, the number of samples to reach full volume is:
//   samples = (1 << (rate >> 2)) * step, where step depends on (rate & 3).
//   Approximate time in seconds: t = 0.000257 * 2^(rate/4) for lower rates,
//   but the relationship inverts (higher rate = faster attack).
//   Empirically from the James Higgs data in adsr.cc:
//     rate 48 -> ~11 frames, rate 80 -> ~2890 frames (at ~60fps -> 0.18s to 48s)
//   The formula: frames ~= 0.00257 * 2^(rate/4), so rate ~= 4 * log2(frames/0.00257)
//   But attack rate is INVERTED: higher value = faster. So we need:
//   rate = 127 - 4 * log2(seconds * samplerate / constant)
//
// Decay (rate 0-15, always exponential decrease):
//   Internal rate = value * 4 before table lookup.
//   time ~= 0.000292 * 2^value seconds (to reach sustain level from peak)
//   So: value = log2(seconds / 0.000292)
//
// Release (rate 0-31, exponential decrease):
//   Internal rate = value * 4 before table lookup.
//   time ~= 0.000446 * 2^value seconds (to reach silence from sustain)
//   So: value = log2(seconds / 0.000446)

// Convert SF2 attack time (seconds) to SPU attack rate (0-127).
// Higher SPU rate = faster attack. The SPU timing approximately follows:
//   time_seconds ~= K * 2^((127 - rate) / 4) where K is a small constant.
// Inverting: rate = 127 - 4 * log2(time / K)
static uint8_t sf2AttackToSpu(float seconds) {
    if (seconds <= 0.0f) return 0x7F;   // instant
    if (seconds >= 10.0f) return 0x00;  // slowest

    // Calibrated against pcsx-redux ADSR tables:
    // rate 127 -> ~0ms, rate 80 -> ~2890 frames (~48s at 60fps)
    // Using K = 0.0005 gives a reasonable fit
    float rate = 127.0f - 4.0f * log2f(seconds / 0.0005f);
    if (rate < 0.0f) rate = 0.0f;
    if (rate > 127.0f) rate = 127.0f;
    return (uint8_t)(rate + 0.5f);
}

// Convert SF2 decay time (seconds) to SPU decay rate (0-15).
// Higher SPU rate = faster decay.
// SPU decay time ~= 0.000292 * 2^(15-value) seconds
static uint8_t sf2DecayToSpu(float seconds) {
    if (seconds <= 0.0f) return 0x0F;
    if (seconds >= 30.0f) return 0x00;

    // value = 15 - log2(seconds / 0.000292)
    float value = 15.0f - log2f(seconds / 0.000292f);
    if (value < 0.0f) value = 0.0f;
    if (value > 15.0f) value = 15.0f;
    return (uint8_t)(value + 0.5f);
}

// Convert SF2 sustain level to SPU sustain level (0-15, where 15 = max volume).
// TSF converts ampenv sustain to a gain value: 1.0 = full volume, 0.0 = silence.
// SPU sustain level: actual volume threshold = (N+1) * 0x800, max is 0x7FFF at N=15(ish).
static uint8_t sf2SustainToSpu(float sustainGain) {
    if (sustainGain >= 1.0f) return 0x0F;
    if (sustainGain <= 0.0f) return 0x00;
    // The SPU sustain levels are roughly linear, so a linear mapping works.
    int level = (int)(sustainGain * 15.0f + 0.5f);
    if (level < 0) level = 0;
    if (level > 0x0F) level = 0x0F;
    return (uint8_t)level;
}

// Convert SF2 release time (seconds) to SPU release rate (0-31).
// Higher SPU rate = faster release.
// SPU release time ~= 0.000446 * 2^(31-value) seconds
static uint8_t sf2ReleaseToSpu(float seconds) {
    if (seconds <= 0.0f) return 0x1F;
    if (seconds >= 30.0f) return 0x00;

    // value = 31 - log2(seconds / 0.000446)
    float value = 31.0f - log2f(seconds / 0.000446f);
    if (value < 0.0f) value = 0.0f;
    if (value > 31.0f) value = 31.0f;
    return (uint8_t)(value + 0.5f);
}

// Extract ADSR from an SF2 region using the amplitude envelope generators.
// Falls back to sensible defaults if the region has no envelope data.
static void sf2RegionToSpuADSR(struct tsf_region* region, bool isDrum, uint16_t& adsrLo, uint16_t& adsrHi) {
    // TSF pre-converts timecents to seconds for attack, hold, decay, release.
    // For ampenv, sustain is converted to a gain value (1.0 = full, 0.0 = silence)
    // via tsf_decibelsToGain(-sustain/10).
    // Hold and decay may still be in timecents if keynumToHold/keynumToDecay are set.

    float attackSec = region->ampenv.attack;
    float decaySec = region->ampenv.decay;
    // If keynumToDecay is set, decay is still in timecents
    if (region->ampenv.keynumToDecay != 0.0f) {
        decaySec = (decaySec < -11950.0f) ? 0.0f : powf(2.0f, decaySec / 1200.0f);
    }
    float sustainGain = region->ampenv.sustain;  // gain: 1.0 = full, 0.0 = silence
    float releaseSec = region->ampenv.release;

    // Clamp to reasonable ranges
    if (attackSec < 0.0f) attackSec = 0.0f;
    if (decaySec < 0.0f) decaySec = 0.0f;
    if (releaseSec < 0.0f) releaseSec = 0.0f;
    if (sustainGain < 0.0f) sustainGain = 0.0f;

    // For drums, force fast release if SF2 doesn't specify one
    if (isDrum && releaseSec > 0.3f) releaseSec = 0.1f;

    uint8_t attackRate = sf2AttackToSpu(attackSec);
    uint8_t decayRate = sf2DecayToSpu(decaySec);
    uint8_t sustainLevel = sf2SustainToSpu(sustainGain);
    uint8_t releaseRate = sf2ReleaseToSpu(releaseSec);

    // SPU sustain rate: controls what happens at sustain level.
    // For most instruments, sustain should hold (rate = 0, direction = increase for hold effect).
    // For drums, sustain should decrease to fade out.
    uint8_t sustainRate = isDrum ? 0x1F : 0x00;
    uint8_t sustainDir = isDrum ? 1 : 0;   // 1 = decrease
    uint8_t sustainMode = isDrum ? 0 : 0;  // 0 = linear

    // Build register values
    // ADSR upper: attack mode (bit 15) | attack rate (bits 8-14) | decay rate (bits 4-7) | sustain level (bits 0-3)
    adsrHi = (uint16_t)((1 << 15) |  // exponential attack for smoother sound
                        ((attackRate & 0x7F) << 8) | ((decayRate & 0x0F) << 4) | (sustainLevel & 0x0F));

    // ADSR lower: sustain mode (bit 14) | sustain dir (bit 13) | sustain rate (bits 6-10) |
    //             release mode (bit 5) | release rate (bits 0-4)
    adsrLo = (uint16_t)(((sustainMode & 1) << 14) | ((sustainDir & 1) << 13) | ((sustainRate & 0x1F) << 6) |
                        (1 << 5) |  // exponential release for natural decay
                        (releaseRate & 0x1F));
}

// ============================================================================
// Conversion Pipeline
// ============================================================================

struct ChannelState {
    int program;
    uint8_t volume;
    uint8_t pan;
    uint8_t expression;
    int16_t pitchBend;        // -8192 to 8191
    bool sustainOn;           // CC#64 state
    uint8_t bankMSB;          // CC#0
    uint8_t bankLSB;          // CC#32
    uint8_t modulation;       // CC#1 modulation wheel (0-127)
    uint8_t reverbSend;       // CC#91 reverb send (0-127, default 40 per GM)
    uint16_t pitchBendRange;  // in semitones * 100 + cents (default 200 = 2 semitones)
    // RPN state machine
    uint8_t rpnMSB;
    uint8_t rpnLSB;

    ChannelState()
        : program(0),
          volume(100),
          pan(64),
          expression(127),
          pitchBend(0),
          sustainOn(false),
          bankMSB(0),
          bankLSB(0),
          modulation(0),
          reverbSend(40),
          pitchBendRange(200),
          rpnMSB(0x7F),
          rpnLSB(0x7F) {}

    void reset() {
        volume = 100;
        pan = 64;
        expression = 127;
        pitchBend = 0;
        sustainOn = false;
        modulation = 0;
        reverbSend = 40;
        rpnMSB = 0x7F;
        rpnLSB = 0x7F;
        // Note: program and bank are NOT reset by CC#121
    }
};

// Find all matching regions for a given preset, note, and velocity.
// SF2 can have overlapping regions for layered sounds (e.g., piano body + hammer).
static std::vector<struct tsf_region*> findRegions(tsf* sf2, int presetIndex, int note, int velocity) {
    std::vector<struct tsf_region*> result;
    if (presetIndex < 0 || presetIndex >= sf2->presetNum) return result;
    struct tsf_preset* preset = &sf2->presets[presetIndex];
    for (int i = 0; i < preset->regionNum; i++) {
        struct tsf_region* r = &preset->regions[i];
        if (note >= r->lokey && note <= r->hikey && velocity >= r->lovel && velocity <= r->hivel) {
            result.push_back(r);
        }
    }
    return result;
}

// Extract a raw sample from TSF's fontSamples and encode to SPU ADPCM
static size_t extractAndEncode(tsf* sf2, struct tsf_region* region, std::vector<SpuSample>& samples,
                               std::map<SampleKey, size_t>& sampleMap, uint32_t& nextSpuAddr,
                               uint32_t maxSpuAddr = SPU_RAM_SIZE) {
    SampleKey key = {region->offset, region->end};
    auto it = sampleMap.find(key);
    if (it != sampleMap.end()) return it->second;

    // Extract raw PCM from fontSamples
    unsigned int sampleCount = region->end - region->offset;
    if (sampleCount == 0) return (size_t)-1;

    std::vector<int16_t> pcm(sampleCount);
    for (unsigned int i = 0; i < sampleCount; i++) {
        float v = sf2->fontSamples[region->offset + i] * 32767.0f;
        if (v > 32767.0f) v = 32767.0f;
        if (v < -32768.0f) v = -32768.0f;
        pcm[i] = (int16_t)v;
    }

    // Handle loop points
    bool hasLoop = (region->loop_mode == TSF_LOOPMODE_CONTINUOUS || region->loop_mode == TSF_LOOPMODE_SUSTAIN);
    size_t loopStart = 0;
    if (hasLoop && region->loop_start >= region->offset && region->loop_end > region->loop_start) {
        loopStart = region->loop_start - region->offset;
    }

    SpuSample sample;
    sample.sampleRate = region->sample_rate;
    sample.rootKey = region->pitch_keycenter;
    sample.transpose = region->transpose;
    sample.tune = region->tune;
    encodeSample(pcm.data(), pcm.size(), hasLoop, loopStart, sample);

    sample.spuAddr = nextSpuAddr;
    nextSpuAddr += sample.adpcmSize;

    if (nextSpuAddr > maxSpuAddr) {
        fmt::print(stderr, "Warning: SPU RAM overflow at {} bytes (max {})\n", nextSpuAddr, maxSpuAddr);
    }

    // Check for pitch ceiling: if this sample would need pitch > 0x3FFF for notes
    // at the top of its key range, warn the user
    {
        int highNote = region->hikey + region->transpose;
        double effectiveNote = highNote + region->tune / 100.0;
        double noteFreq = 440.0 * pow(2.0, (effectiveNote - 69) / 12.0);
        double rootFreq = 440.0 * pow(2.0, ((int)region->pitch_keycenter - 69) / 12.0);
        double maxPitch = (noteFreq / rootFreq) * ((double)region->sample_rate / 44100.0) * 0x1000;
        if (maxPitch > 0x3FFF) {
            fmt::print(stderr,
                       "  Warning: sample {} (root={}, rate={}Hz) hits pitch ceiling at note {} "
                       "(pitch {:.0f} > 16383). High notes will play flat.\n",
                       samples.size(), region->pitch_keycenter, region->sample_rate, region->hikey, maxPitch);
        }
    }

    size_t idx = samples.size();
    fmt::print("  Sample {}: offset={} end={} rate={}Hz rootKey={} transpose={} tune={} cents loop={} size={} bytes\n",
               idx, region->offset, region->end, sample.sampleRate, sample.rootKey, sample.transpose, sample.tune,
               sample.hasLoop ? "yes" : "no", sample.adpcmSize);
    samples.push_back(std::move(sample));
    sampleMap[key] = idx;
    return idx;
}

struct ConvertContext {
    MidiFile midi;
    tsf* sf2;
    std::vector<SpuSample> samples;
    std::map<SampleKey, size_t> sampleMap;  // key -> index in samples
    VoiceAllocator allocator;
    ChannelState channels[16];
    std::vector<StreamEvent> stream;
    unsigned maxVoices;
    unsigned maxLayers;  // max overlapping regions per note (0 = unlimited)

    // SPU RAM tracking
    uint32_t nextSpuAddr;  // next free SPU RAM address in bytes
    uint32_t maxSpuAddr;   // max usable address (SPU_RAM_SIZE minus reverb buffer)

    // Macro system
    std::vector<MacroDef> macroDefs;
    std::map<MacroKey, uint16_t> macroMap;  // key -> macro index

    uint16_t getOrCreateMacro(uint16_t adsrLo, uint16_t adsrHi, uint16_t sampleStart8) {
        MacroKey key = {adsrLo, adsrHi, sampleStart8};
        auto it = macroMap.find(key);
        if (it != macroMap.end()) return it->second;

        uint16_t idx = (uint16_t)macroDefs.size();
        MacroDef macro;
        // Voice-0-relative offsets
        macro.writes.push_back({(uint16_t)SPU_SAMPLE_START(0), sampleStart8});
        macro.writes.push_back({(uint16_t)SPU_ADSR_LO(0), adsrLo});
        macro.writes.push_back({(uint16_t)SPU_ADSR_HI(0), adsrHi});
        macroDefs.push_back(std::move(macro));
        macroMap[key] = idx;
        return idx;
    }

    // Register cache: track last value written to each SPU register offset.
    // Only emit a write if the value has actually changed.
    // SPU register space is 0x200 bytes = 0x100 16-bit registers.
    uint16_t regCache[0x100];
    bool regCacheValid[0x100];

    void initRegCache() { memset(regCacheValid, 0, sizeof(regCacheValid)); }

    // Add a register write to the event only if the value changed.
    // KEY_ON and KEY_OFF are never cached (they're edge-triggered).
    void cachedWrite(StreamEvent& ev, uint16_t offset, uint16_t value) {
        // Never cache key-on/key-off - they're triggers, not state
        if (offset == SPU_KEY_ON_LO || offset == SPU_KEY_ON_HI || offset == SPU_KEY_OFF_LO ||
            offset == SPU_KEY_OFF_HI) {
            ev.writes.push_back({offset, value});
            return;
        }
        uint16_t idx = offset / 2;
        if (idx < 0x100 && regCacheValid[idx] && regCache[idx] == value) return;
        if (idx < 0x100) {
            regCache[idx] = value;
            regCacheValid[idx] = true;
        }
        ev.writes.push_back({offset, value});
    }

    // Reverb
    int reverbPreset;  // index into REVERB_PRESETS, 0 = off

    // Loop point detection
    int32_t loopPointTick;  // -1 = no loop point detected, use start

    // Metadata extracted from MIDI
    std::string trackName;
    std::string copyright;

    void generateStream();
    bool writeSpd(const char* filename, const char* title);
    bool writeSplit(const char* musicFile, const char* sampleFile, const char* title);
};

void ConvertContext::generateStream() {
    allocator.init(maxVoices);
    initRegCache();
    loopPointTick = -1;

    // Initialize all channel states
    for (int i = 0; i < 16; i++) {
        channels[i] = ChannelState();
    }
    // Channel 10 is drums (0-indexed as channel 9)
    channels[MIDI_DRUM_CHANNEL].program = 128;

    // Pre-scan for loop markers (CC#111 and text markers)
    for (auto& mev : midi.events) {
        if (mev.type == MIDI_CONTROL_CHANGE && mev.data1 == MIDI_CC_LOOP_POINT) {
            loopPointTick = (int32_t)mev.absoluteTick;
            break;
        }
        if (mev.type == MIDI_META && mev.data1 == MIDI_META_MARKER) {
            // Check for common loop marker text
            if (mev.textData == "loopStart" || mev.textData == "LoopStart" || mev.textData == "loop") {
                loopPointTick = (int32_t)mev.absoluteTick;
                break;
            }
        }
    }

    // Pre-scan for metadata
    for (auto& mev : midi.events) {
        if (mev.type == MIDI_META) {
            if (mev.data1 == MIDI_META_TRACK_NAME && trackName.empty()) {
                trackName = mev.textData;
            } else if (mev.data1 == MIDI_META_COPYRIGHT && copyright.empty()) {
                copyright = mev.textData;
            }
        }
    }

    uint32_t lastTick = 0;
    bool loopPointEmitted = false;

    // Default MIDI tempo is 120 BPM = 500000 us/beat
    uint32_t currentTempo = 500000;

    // Vibrato LFO state. The LFO runs at ~6 Hz (standard GM vibrato rate).
    // Phase is tracked as a global tick counter; the actual sine lookup converts
    // this to a phase based on the current tick rate (ticks/sec).
    // Modulation depth: CC#1 value 127 = +/- 50 cents (quarter semitone) at full depth.
    // This is a typical GM default; some implementations use more or less.
    static constexpr double VIBRATO_RATE_HZ = 6.0;
    static constexpr double VIBRATO_MAX_CENTS = 50.0;  // max depth at CC#1 = 127
    uint32_t globalTick = 0;                           // absolute tick counter for LFO phase

    auto computeTickRate = [&]() -> uint32_t {
        double ticksPerSec = (double)midi.tpqn * 1000000.0 / (double)currentTempo;
        return (uint32_t)(ticksPerSec * 65536.0);  // 16.16 fixed point
    };

    // Emit initial tick rate
    {
        StreamEvent ev;
        ev.type = StreamEvent::TICK_RATE;
        ev.tickRate = computeTickRate();
        stream.push_back(ev);
    }

    // Emit reverb setup registers if a reverb preset is active
    uint32_t reverbOnMask = 0;  // per-voice reverb enable bitmask
    if (reverbPreset > 0 && reverbPreset < REVERB_PRESET_COUNT) {
        auto& preset = REVERB_PRESETS[reverbPreset];

        StreamEvent ev;
        ev.type = StreamEvent::REG_WRITES;

        // Set reverb work area base address (top of SPU RAM minus buffer size)
        uint16_t mBase = (uint16_t)((SPU_RAM_SIZE - preset.bufferSize) >> 3);
        ev.writes.push_back({(uint16_t)SPU_REVERB_BASE, mBase});

        // Write all 32 reverb configuration registers
        for (int i = 0; i < 32; i++) {
            ev.writes.push_back({(uint16_t)(SPU_REVERB_CFG + i * 2), preset.regs[i]});
        }

        // Set reverb output volumes
        ev.writes.push_back({(uint16_t)SPU_REVERB_OUT_L, preset.outVolL});
        ev.writes.push_back({(uint16_t)SPU_REVERB_OUT_R, preset.outVolR});

        // Enable reverb master via SPUCNT. This is a full register write, so we
        // must set all critical bits: bit 15 = SPU enable, bit 14 = unmute,
        // bit 7 = reverb master enable. Writing just 0x80 would clear SPU enable
        // and unmute, silencing everything.
        ev.writes.push_back({(uint16_t)SPU_SPUCNT, 0xC080});

        // Set main volume (ensure it's set)
        ev.writes.push_back({(uint16_t)SPU_MAIN_VOL_L, 0x3FFF});
        ev.writes.push_back({(uint16_t)SPU_MAIN_VOL_R, 0x3FFF});

        stream.push_back(ev);
    }

    // If no loop marker found, emit loop point at start
    if (loopPointTick < 0) {
        StreamEvent ev;
        ev.type = StreamEvent::LOOP_POINT;
        stream.push_back(ev);
        loopPointEmitted = true;
    }

    // Tick-level accumulation
    StreamEvent tickRegs;
    tickRegs.type = StreamEvent::REG_WRITES;
    uint32_t tickKeyOn = 0;
    uint32_t tickKeyOff = 0;

    auto flushTick = [&](uint32_t waitTicks) {
        bool hasContent = tickKeyOff || !tickRegs.writes.empty() || tickKeyOn || waitTicks;
        if (!hasContent) return;

        StreamEvent ev;
        ev.type = StreamEvent::REG_WRITES;

        // Key-off first
        if (tickKeyOff) {
            if (tickKeyOff & 0xFFFF) ev.writes.push_back({SPU_KEY_OFF_LO, (uint16_t)(tickKeyOff & 0xFFFF)});
            if (tickKeyOff >> 16) ev.writes.push_back({SPU_KEY_OFF_HI, (uint16_t)(tickKeyOff >> 16)});
            tickKeyOff = 0;
        }

        // Register writes
        for (auto& w : tickRegs.writes) {
            ev.writes.push_back(w);
        }
        tickRegs.writes.clear();

        // Key-on after setup
        if (tickKeyOn) {
            if (tickKeyOn & 0xFFFF) ev.writes.push_back({SPU_KEY_ON_LO, (uint16_t)(tickKeyOn & 0xFFFF)});
            if (tickKeyOn >> 16) ev.writes.push_back({SPU_KEY_ON_HI, (uint16_t)(tickKeyOn >> 16)});
            tickKeyOn = 0;
        }

        // Inline wait at the end
        if (waitTicks > 0) {
            while (waitTicks > 0xFFFF) {
                ev.writes.push_back({INLINE_WAIT_ADDR, 0xFFFF});
                waitTicks -= 0xFFFF;
            }
            ev.writes.push_back({INLINE_WAIT_ADDR, (uint16_t)waitTicks});
        }

        if (!ev.writes.empty()) stream.push_back(ev);
    };

    // Helper: update volume registers for all active voices on a channel
    auto updateChannelVolumes = [&](uint8_t ch) {
        auto& chanState = channels[ch];
        for (unsigned v = 0; v < maxVoices; v++) {
            auto& slot = allocator.voices[v];
            if (slot.active && slot.midiChannel == ch) {
                uint16_t volL, volR;
                computeVolumes(slot.velocity, chanState.volume, chanState.expression, chanState.pan, slot.sf2Pan,
                               slot.sf2Attenuation, volL, volR);
                cachedWrite(tickRegs, (uint16_t)SPU_VOL_LEFT(v), volL);
                cachedWrite(tickRegs, (uint16_t)SPU_VOL_RIGHT(v), volR);
            }
        }
    };

    // Compute the vibrato LFO offset in cents for a given tick
    auto vibratoOffset = [&](uint8_t ch) -> double {
        auto& chanState = channels[ch];
        if (chanState.modulation == 0) return 0.0;
        // Convert tick to seconds using current tempo
        double ticksPerSec = (double)midi.tpqn * 1000000.0 / (double)currentTempo;
        double timeSec = globalTick / ticksPerSec;
        // LFO phase at VIBRATO_RATE_HZ
        double phase = timeSec * VIBRATO_RATE_HZ * 2.0 * std::numbers::pi_v<double>;
        double depth = (chanState.modulation / 127.0) * VIBRATO_MAX_CENTS;
        return sin(phase) * depth;
    };

    // Helper: update pitch registers for all active voices on a channel (for pitch bend + vibrato)
    auto updateChannelPitch = [&](uint8_t ch) {
        auto& chanState = channels[ch];
        double modCents = vibratoOffset(ch);
        for (unsigned v = 0; v < maxVoices; v++) {
            auto& slot = allocator.voices[v];
            if (slot.active && slot.midiChannel == ch) {
                uint16_t pitch =
                    computeSpuPitch(slot.baseMidiNote, slot.sampleRate, slot.rootKey, slot.transpose, slot.tuneCents,
                                    chanState.pitchBend, chanState.pitchBendRange, modCents);
                cachedWrite(tickRegs, (uint16_t)SPU_PITCH(v), pitch);
            }
        }
    };

    // Per-tick voice update: runs vibrato LFO on channels that have modulation active.
    // Only emits writes when the pitch value actually changes (register cache handles this).
    auto perTickUpdate = [&]() {
        for (int ch = 0; ch < 16; ch++) {
            if (channels[ch].modulation > 0) {
                updateChannelPitch((uint8_t)ch);
            }
        }
    };

    // Process all MIDI events
    for (size_t i = 0; i < midi.events.size(); i++) {
        auto& mev = midi.events[i];

        // Flush and emit wait if time has advanced
        if (mev.absoluteTick > lastTick) {
            uint32_t waitTicks = mev.absoluteTick - lastTick;

            // If any channel has modulation active, we need to split long waits
            // into smaller segments to update the vibrato LFO periodically.
            // Update rate: ~100 Hz (every ~10ms) for smooth vibrato.
            bool hasModulation = false;
            for (int ch = 0; ch < 16; ch++) {
                if (channels[ch].modulation > 0) {
                    hasModulation = true;
                    break;
                }
            }

            if (hasModulation) {
                double ticksPerSec = (double)midi.tpqn * 1000000.0 / (double)currentTempo;
                uint32_t updateInterval = (uint32_t)(ticksPerSec / 100.0);  // ~100 Hz
                if (updateInterval < 1) updateInterval = 1;

                uint32_t remaining = waitTicks;
                while (remaining > 0) {
                    uint32_t step = (remaining > updateInterval) ? updateInterval : remaining;
                    globalTick = lastTick + (waitTicks - remaining) + step;
                    perTickUpdate();
                    flushTick(step);
                    remaining -= step;
                }
            } else {
                globalTick = mev.absoluteTick;
                flushTick(waitTicks);
            }
            lastTick = mev.absoluteTick;
        }

        // Check if we need to emit the loop point at this tick
        if (!loopPointEmitted && loopPointTick >= 0 && (int32_t)mev.absoluteTick >= loopPointTick) {
            StreamEvent ev;
            ev.type = StreamEvent::LOOP_POINT;
            stream.push_back(ev);
            loopPointEmitted = true;
        }

        if (mev.type == MIDI_META && mev.data1 == MIDI_META_TEMPO) {
            currentTempo = mev.tempo;
            StreamEvent ev;
            ev.type = StreamEvent::TICK_RATE;
            ev.tickRate = computeTickRate();
            stream.push_back(ev);
            continue;
        }

        // Skip other meta events in the main loop (already pre-scanned)
        if (mev.type == MIDI_META) continue;

        if (mev.type == MIDI_PROGRAM_CHANGE) {
            channels[mev.channel].program = mev.data1;
            if (mev.channel == MIDI_DRUM_CHANNEL) channels[mev.channel].program = 128;
            continue;
        }

        if (mev.type == MIDI_CONTROL_CHANGE) {
            auto& chanState = channels[mev.channel];
            switch (mev.data1) {
                case MIDI_CC_VOLUME:
                    chanState.volume = mev.data2;
                    updateChannelVolumes(mev.channel);
                    break;
                case MIDI_CC_PAN:
                    chanState.pan = mev.data2;
                    updateChannelVolumes(mev.channel);
                    break;
                case MIDI_CC_EXPRESSION:
                    chanState.expression = mev.data2;
                    updateChannelVolumes(mev.channel);
                    break;

                case MIDI_CC_MODULATION:
                    chanState.modulation = mev.data2;
                    break;

                case MIDI_CC_REVERB_SEND:
                    chanState.reverbSend = mev.data2;
                    break;

                case MIDI_CC_BANK_MSB:
                    chanState.bankMSB = mev.data2;
                    break;
                case MIDI_CC_BANK_LSB:
                    chanState.bankLSB = mev.data2;
                    break;

                case MIDI_CC_SUSTAIN:
                    if (mev.data2 >= 64) {
                        // Sustain on
                        chanState.sustainOn = true;
                    } else {
                        // Sustain off: release all held voices on this channel
                        chanState.sustainOn = false;
                        uint32_t releasedMask = allocator.releaseSustainedVoices(mev.channel);
                        tickKeyOff |= releasedMask;
                    }
                    break;

                case MIDI_CC_RPN_MSB:
                    chanState.rpnMSB = mev.data2;
                    break;
                case MIDI_CC_RPN_LSB:
                    chanState.rpnLSB = mev.data2;
                    break;
                case MIDI_CC_DATA_ENTRY_MSB:
                    // RPN 0,0 = pitch bend range
                    if (chanState.rpnMSB == 0 && chanState.rpnLSB == 0) {
                        // MSB = semitones, keep existing LSB (cents)
                        chanState.pitchBendRange = (uint16_t)(mev.data2 * 100 + (chanState.pitchBendRange % 100));
                    }
                    break;
                case MIDI_CC_DATA_ENTRY_LSB:
                    if (chanState.rpnMSB == 0 && chanState.rpnLSB == 0) {
                        // LSB = cents
                        chanState.pitchBendRange = (uint16_t)((chanState.pitchBendRange / 100) * 100 + mev.data2);
                    }
                    break;

                case MIDI_CC_ALL_SOUND_OFF:
                case MIDI_CC_ALL_NOTES_OFF:
                    // Kill all active voices on this channel
                    for (unsigned v = 0; v < maxVoices; v++) {
                        if (allocator.voices[v].active && allocator.voices[v].midiChannel == mev.channel) {
                            tickKeyOff |= (1 << v);
                            allocator.release((int)v);
                        }
                    }
                    if (mev.data1 == MIDI_CC_ALL_SOUND_OFF) {
                        chanState.sustainOn = false;
                    }
                    break;

                case MIDI_CC_RESET_ALL:
                    chanState.reset();
                    updateChannelVolumes(mev.channel);
                    updateChannelPitch(mev.channel);
                    break;

                case MIDI_CC_LOOP_POINT:
                    // Already handled in pre-scan
                    break;

                default:
                    break;
            }
            continue;
        }

        if (mev.type == MIDI_PITCH_BEND) {
            int bend = ((int)mev.data2 << 7 | mev.data1) - 8192;
            channels[mev.channel].pitchBend = (int16_t)bend;
            // Update pitch of all active voices on this channel
            updateChannelPitch(mev.channel);
            continue;
        }

        if (mev.type == MIDI_NOTE_ON) {
            uint8_t note = mev.data1;
            uint8_t velocity = mev.data2;
            uint8_t ch = mev.channel;
            auto& chanState = channels[ch];
            bool isDrum = (ch == MIDI_DRUM_CHANNEL);

            // Find the SF2 preset and all matching regions for this note
            int bank = isDrum ? 128 : (int)chanState.bankMSB;
            int prog = isDrum ? 0 : chanState.program;
            int presetIndex = tsf_get_presetindex(sf2, bank, prog);
            if (presetIndex < 0) {
                if (!isDrum) presetIndex = tsf_get_presetindex(sf2, 0, prog);
                if (presetIndex < 0) continue;
            }

            auto regions = findRegions(sf2, presetIndex, note, velocity);
            if (regions.empty()) continue;

            // Cap the number of layers per note to conserve voices
            if (maxLayers > 0 && regions.size() > maxLayers) {
                regions.resize(maxLayers);
            }

            // Handle exclusive groups: kill all voices in matching groups before allocating.
            // Check all regions since different layers may belong to different groups.
            for (auto* region : regions) {
                if (region->group != 0) {
                    uint32_t killedMask = allocator.killExclusiveGroup((int)region->group);
                    tickKeyOff |= killedMask;
                }
            }

            double modCents = vibratoOffset(ch);

            // Trigger a voice for each matching region (layered sounds)
            for (auto* region : regions) {
                size_t sampleIdx = extractAndEncode(sf2, region, samples, sampleMap, nextSpuAddr, maxSpuAddr);
                if (sampleIdx == (size_t)-1) continue;

                auto& sample = samples[sampleIdx];

                int voice = allocator.allocate(ch, note, velocity, mev.absoluteTick);

                auto& slot = allocator.voices[voice];
                slot.baseMidiNote = note;
                slot.sampleRate = sample.sampleRate;
                slot.rootKey = sample.rootKey;
                slot.transpose = sample.transpose;
                slot.tuneCents = sample.tune;
                slot.exclusiveGroup = (int)region->group;
                slot.sf2Pan = region->pan;
                slot.sf2Attenuation = region->attenuation;

                uint16_t volL, volR;
                computeVolumes(velocity, chanState.volume, chanState.expression, chanState.pan, region->pan,
                               region->attenuation, volL, volR);

                // Apply pitch keytrack: default is 100 (cents per key), meaning standard tuning.
                // Non-100 values scale the pitch deviation from the root key.
                int tuneCents = sample.tune;
                int transpose = sample.transpose;
                if (region->pitch_keytrack != 100) {
                    // Recompute effective transposition with keytrack scaling
                    // Standard: each semitone = 100 cents. With keytrack K:
                    // effective cents from root = (note - rootKey) * K
                    // We achieve this by adjusting the tune offset
                    double standardCents = (note - (int)sample.rootKey) * 100.0;
                    double trackedCents = (note - (int)sample.rootKey) * region->pitch_keytrack;
                    double correction = trackedCents - standardCents;
                    tuneCents += (int)correction;
                    // Update the voice slot too for pitch bend recalculation
                    slot.tuneCents = tuneCents;
                }

                uint16_t pitch = computeSpuPitch(note, sample.sampleRate, sample.rootKey, transpose, tuneCents,
                                                 chanState.pitchBend, chanState.pitchBendRange, modCents);

                uint16_t adsrLo, adsrHi;
                sf2RegionToSpuADSR(region, isDrum, adsrLo, adsrHi);

                uint16_t sampleStart8 = (uint16_t)(sample.spuAddr >> 3);
                uint16_t ssIdx = SPU_SAMPLE_START(voice) / 2;
                uint16_t alIdx = SPU_ADSR_LO(voice) / 2;
                uint16_t ahIdx = SPU_ADSR_HI(voice) / 2;
                bool needMacro = false;
                if (ssIdx < 0x100 && (!regCacheValid[ssIdx] || regCache[ssIdx] != sampleStart8)) needMacro = true;
                if (alIdx < 0x100 && (!regCacheValid[alIdx] || regCache[alIdx] != adsrLo)) needMacro = true;
                if (ahIdx < 0x100 && (!regCacheValid[ahIdx] || regCache[ahIdx] != adsrHi)) needMacro = true;

                if (needMacro) {
                    uint16_t macroIdx = getOrCreateMacro(adsrLo, adsrHi, sampleStart8);
                    tickRegs.writes.push_back({(uint16_t)(MACRO_INVOKE_BASE | macroIdx), (uint16_t)voice});
                    if (ssIdx < 0x100) {
                        regCache[ssIdx] = sampleStart8;
                        regCacheValid[ssIdx] = true;
                    }
                    if (alIdx < 0x100) {
                        regCache[alIdx] = adsrLo;
                        regCacheValid[alIdx] = true;
                    }
                    if (ahIdx < 0x100) {
                        regCache[ahIdx] = adsrHi;
                        regCacheValid[ahIdx] = true;
                    }
                }

                cachedWrite(tickRegs, (uint16_t)SPU_VOL_LEFT(voice), volL);
                cachedWrite(tickRegs, (uint16_t)SPU_VOL_RIGHT(voice), volR);
                cachedWrite(tickRegs, (uint16_t)SPU_PITCH(voice), pitch);

                tickKeyOn |= (1 << voice);

                // Update reverb enable mask for this voice based on channel CC#91
                if (reverbPreset > 0 && chanState.reverbSend > 0) {
                    reverbOnMask |= (1 << voice);
                } else {
                    reverbOnMask &= ~(1 << voice);
                }
            }

            // Emit updated reverb on/off bitmask if reverb is active
            if (reverbPreset > 0) {
                cachedWrite(tickRegs, (uint16_t)SPU_REVERB_LO, (uint16_t)(reverbOnMask & 0xFFFF));
                if (maxVoices > 16) {
                    cachedWrite(tickRegs, (uint16_t)SPU_REVERB_HI, (uint16_t)(reverbOnMask >> 16));
                }
            }
            continue;
        }

        if (mev.type == MIDI_NOTE_OFF) {
            // Release ALL voices matching this channel+note (there may be multiple from layers)
            for (unsigned v = 0; v < maxVoices; v++) {
                auto& slot = allocator.voices[v];
                if (slot.active && !slot.sustainHeld && slot.midiChannel == mev.channel && slot.midiNote == mev.data1) {
                    if (channels[mev.channel].sustainOn) {
                        allocator.holdSustain((int)v);
                    } else {
                        tickKeyOff |= (1 << v);
                        allocator.release((int)v);
                    }
                }
            }
            continue;
        }
    }

    // Flush any remaining events from the last tick
    flushTick(0);

    // If loop point was never emitted (loopPointTick past end of song), emit at end
    if (!loopPointEmitted) {
        StreamEvent ev;
        ev.type = StreamEvent::LOOP_POINT;
        stream.push_back(ev);
    }

    // End of pattern
    {
        StreamEvent ev;
        ev.type = StreamEvent::END_PATTERN;
        stream.push_back(ev);
    }
}

bool ConvertContext::writeSpd(const char* filename, const char* title) {
    FilePtr f(new PCSX::PosixFile(filename, PCSX::FileOps::TRUNCATE));
    if (f->failed()) return false;

    // Magic header
    static const uint8_t magic[16] = {'P', 'S', 'X', 'S', 'P', 'U', 'D', 'U', 'M', 'P', 'v', '1', 'r', '1', '\0', '\0'};
    f->write(magic, 16);

    // Metadata
    if (title) writePacketString(f, SPD_PKT_TITLE, title);
    if (!copyright.empty()) writePacketString(f, SPD_PKT_AUTHOR, copyright.c_str());
    writePacketString(f, SPD_PKT_COMMENT, "Generated by midi2spd");

    // Voice count
    {
        uint32_t vc = maxVoices;
        writePacket(f, SPD_PKT_VOICE_COUNT, &vc, 1);
    }

    // Tick rate (initial - will also be in stream but good to have in header)
    {
        double ticksPerSec = (double)midi.tpqn * 1000000.0 / 500000.0;
        uint32_t tickRate = (uint32_t)(ticksPerSec * 65536.0);
        writePacket(f, SPD_PKT_TICK_RATE, &tickRate, 1);
    }

    // Sample data: base address + contiguous ADPCM blob
    if (!samples.empty()) {
        uint32_t totalAdpcm = 0;
        for (auto& s : samples) totalAdpcm += s.adpcmSize;

        uint32_t baseAddr8 = SPU_RAM_BASE >> 3;
        uint32_t totalWords = 1 + (totalAdpcm + 3) / 4;
        f->write<uint32_t>((totalWords & 0x00FFFFFF) | (SPD_PKT_SAMPLE_DATA << 24));
        f->write<uint32_t>(baseAddr8);
        for (auto& s : samples) {
            f->write(s.adpcmData.data(), s.adpcmData.size());
        }
        // Pad to 4-byte alignment
        size_t pad = (4 - (totalAdpcm % 4)) % 4;
        for (size_t i = 0; i < pad; i++) f->write<uint8_t>(0);

        // Sample directory
        writeSampleDir(f, samples);
    }

    // Macro definitions
    writeMacroDefs(f, macroDefs);

    // Order table: single order, looping
    {
        uint32_t orderPayload[3] = {1, 0, 0};
        writePacket(f, SPD_PKT_ORDER_TABLE, orderPayload, 3);
    }

    // Pattern header: offset to be filled in
    auto patternHdrPos = f->wSeek(0, SEEK_CUR);
    {
        uint32_t offset = 0;
        writePacket(f, SPD_PKT_PATTERN_HDR, &offset, 1);
    }

    // Record where pattern data starts and fix the pattern header
    auto patternDataStart = f->wSeek(0, SEEK_CUR);
    {
        f->wSeek(patternHdrPos + 4, SEEK_SET);  // skip the packet header
        f->write<uint32_t>((uint32_t)patternDataStart);
        f->wSeek(patternDataStart, SEEK_SET);
    }

    // Write pattern data from stream
    writeStreamPackets(f, stream);

    f->close();
    return true;
}

static void writeMagic(FilePtr& f) {
    static const uint8_t magic[16] = {'P', 'S', 'X', 'S', 'P', 'U', 'D', 'U', 'M', 'P', 'v', '1', 'r', '1', '\0', '\0'};
    f->write(magic, 16);
}

static void writeSampleDir(FilePtr& f, const std::vector<SpuSample>& samples) {
    uint32_t dirPayload = 1 + samples.size() * 2;
    f->write<uint32_t>((dirPayload & 0x00FFFFFF) | (SPD_PKT_SAMPLE_DIR << 24));
    f->write<uint32_t>((uint32_t)samples.size());
    for (auto& s : samples) {
        f->write<uint32_t>(((s.spuAddr >> 3) << 16) | (s.adpcmSize >> 3));
        f->write<uint32_t>((((s.spuAddr + s.loopStartByte) >> 3) << 16) | (s.hasLoop ? 1 : 0));
    }
}

static void writeSamplePackets(FilePtr& f, const std::vector<SpuSample>& samples) {
    if (samples.empty()) return;

    uint32_t totalAdpcm = 0;
    for (auto& s : samples) totalAdpcm += s.adpcmSize;

    uint32_t baseAddr8 = SPU_RAM_BASE >> 3;
    uint32_t totalWords = 1 + (totalAdpcm + 3) / 4;
    f->write<uint32_t>((totalWords & 0x00FFFFFF) | (SPD_PKT_SAMPLE_DATA << 24));
    f->write<uint32_t>(baseAddr8);
    for (auto& s : samples) {
        f->write(s.adpcmData.data(), s.adpcmData.size());
    }
    size_t pad = (4 - (totalAdpcm % 4)) % 4;
    for (size_t i = 0; i < pad; i++) f->write<uint8_t>(0);

    writeSampleDir(f, samples);
}

static void writeMacroDefs(FilePtr& f, const std::vector<MacroDef>& macroDefs) {
    for (size_t i = 0; i < macroDefs.size(); i++) {
        auto& macro = macroDefs[i];
        std::vector<uint32_t> payload;
        payload.push_back((uint32_t)i);
        for (auto& w : macro.writes) {
            payload.push_back(((uint32_t)w.offset << 16) | w.value);
        }
        writePacket(f, SPD_PKT_MACRO_DEF, payload.data(), (uint32_t)payload.size());
    }
}

static void writeStreamPackets(FilePtr& f, const std::vector<StreamEvent>& stream) {
    for (auto& ev : stream) {
        switch (ev.type) {
            case StreamEvent::REG_WRITES: {
                std::vector<uint32_t> payload;
                for (auto& w : ev.writes) {
                    payload.push_back(((uint32_t)w.offset << 16) | w.value);
                }
                writePacket(f, SPD_PKT_REG_WRITE, payload.data(), (uint32_t)payload.size());
                break;
            }
            case StreamEvent::WAIT: {
                uint32_t ticks = ev.waitTicks;
                writePacket(f, SPD_PKT_WAIT, &ticks, 1);
                break;
            }
            case StreamEvent::END_PATTERN:
                writePacketEmpty(f, SPD_PKT_END_PATTERN);
                break;
            case StreamEvent::LOOP_POINT:
                writePacketEmpty(f, SPD_PKT_LOOP_POINT);
                break;
            case StreamEvent::TICK_RATE: {
                uint32_t rate = ev.tickRate;
                writePacket(f, SPD_PKT_TICK_RATE, &rate, 1);
                break;
            }
        }
    }
}

bool ConvertContext::writeSplit(const char* musicFile, const char* sampleFile, const char* title) {
    // Write sample file: magic + sample data + sample directory
    {
        FilePtr f(new PCSX::PosixFile(sampleFile, PCSX::FileOps::TRUNCATE));
        if (f->failed()) return false;
        writeMagic(f);
        writeSamplePackets(f, samples);
        f->close();
    }

    // Write music file: magic + metadata + tick rate + voice count + order + patterns (no samples)
    {
        FilePtr f(new PCSX::PosixFile(musicFile, PCSX::FileOps::TRUNCATE));
        if (f->failed()) return false;
        writeMagic(f);

        // Metadata
        if (title) writePacketString(f, SPD_PKT_TITLE, title);
        if (!copyright.empty()) writePacketString(f, SPD_PKT_AUTHOR, copyright.c_str());
        writePacketString(f, SPD_PKT_COMMENT, "Generated by midi2spd");

        // Voice count
        uint32_t vc = maxVoices;
        writePacket(f, SPD_PKT_VOICE_COUNT, &vc, 1);

        // Tick rate
        double ticksPerSec = (double)midi.tpqn * 1000000.0 / 500000.0;
        uint32_t tickRate = (uint32_t)(ticksPerSec * 65536.0);
        writePacket(f, SPD_PKT_TICK_RATE, &tickRate, 1);

        // Sample directory (kept in music file for SFX API - no sample data though)
        if (!samples.empty()) {
            writeSampleDir(f, samples);
        }

        // Macro definitions
        writeMacroDefs(f, macroDefs);

        // Order table
        uint32_t orderPayload[3] = {1, 0, 0};
        writePacket(f, SPD_PKT_ORDER_TABLE, orderPayload, 3);

        // Pattern header
        auto patternHdrPos = f->wSeek(0, SEEK_CUR);
        uint32_t offset = 0;
        writePacket(f, SPD_PKT_PATTERN_HDR, &offset, 1);

        auto patternDataStart = f->wSeek(0, SEEK_CUR);
        f->wSeek(patternHdrPos + 4, SEEK_SET);
        f->write<uint32_t>((uint32_t)patternDataStart);
        f->wSeek(patternDataStart, SEEK_SET);

        // Pattern data
        writeStreamPackets(f, stream);

        f->close();
    }

    return true;
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char** argv) {
    CommandLine::args args(argc, argv);
    const auto output = args.get<std::string>("o");
    const auto soundfont = args.get<std::string>("s");
    const auto maxVoicesOpt = args.get<unsigned>("v");
    const auto sampleOutput = args.get<std::string>("i");
    const auto reverbOpt = args.get<std::string>("r");
    const auto maxLayersOpt = args.get<unsigned>("l");

    fmt::print(R"(
midi2spd - MIDI to SPUDUMP converter
Part of PCSX-Redux - https://github.com/grumpycoders/pcsx-redux

)");

    const auto inputs = args.positional();
    const bool asksForHelp = args.get<bool>("h").value_or(false);
    const bool hasOutput = output.has_value();
    const bool hasSoundfont = soundfont.has_value();
    const bool oneInput = inputs.size() == 1;

    if (asksForHelp || !oneInput || !hasOutput || !hasSoundfont) {
        fmt::print(R"(
Usage: {} input.mid -s soundfont.sf2 -o output.spd [-i output.smp] [-v maxvoices] [-r reverb] [-h]
  input.mid          mandatory: the input MIDI file.
  -s soundfont.sf2   mandatory: the SoundFont instrument bank.
  -o output.spd      mandatory: the output SPUDUMP file.
  -i output.smp      optional: separate sample data file. When specified,
                     output.spd contains only music data and output.smp
                     contains only sample data. The sample file can be
                     freed after uploading to SPU RAM via SPD_LoadEx().
  -v maxvoices       optional: max SPU voices for music (default 16, max 24).
  -r reverb          optional: reverb preset (default: hall).
                     Available: off, room, studio, hall, space.
  -l maxlayers       optional: max overlapping SF2 regions per note (default 0 = unlimited).
                     Setting to 1 disables layered instruments. Useful when voice
                     count is limited and layers cause excessive voice stealing.
  -h                 display this help and exit.
)",
                   argv[0]);
        return asksForHelp ? 0 : -1;
    }

    unsigned maxVoices = maxVoicesOpt.value_or(16);
    if (maxVoices > 24) maxVoices = 24;

    // Read input MIDI file
    FilePtr midiFile(new PCSX::PosixFile(std::string(inputs[0]).c_str()));
    if (midiFile->failed()) {
        fmt::print(stderr, "Error: unable to open MIDI file: {}\n", inputs[0]);
        return -1;
    }
    midiFile->rSeek(0, SEEK_END);
    size_t midiSize = midiFile->rSeek(0, SEEK_CUR);
    midiFile->rSeek(0, SEEK_SET);
    auto midiSlice = midiFile->read(midiSize);
    const uint8_t* midiData = (const uint8_t*)midiSlice.data();

    // Read SoundFont file
    FilePtr sf2File(new PCSX::PosixFile(soundfont.value().c_str()));
    if (sf2File->failed()) {
        fmt::print(stderr, "Error: unable to open SoundFont: {}\n", soundfont.value());
        return -1;
    }
    sf2File->rSeek(0, SEEK_END);
    size_t sf2Size = sf2File->rSeek(0, SEEK_CUR);
    sf2File->rSeek(0, SEEK_SET);
    auto sf2Slice = sf2File->read(sf2Size);
    const uint8_t* sf2Data = (const uint8_t*)sf2Slice.data();

    // Parse MIDI
    ConvertContext ctx;
    if (!ctx.midi.parse(midiData, midiSize)) {
        fmt::print(stderr, "Error: failed to parse MIDI file\n");
        return -1;
    }
    fmt::print("MIDI: format {}, {} tracks, {} tpqn, {} events\n", ctx.midi.format, ctx.midi.trackCount, ctx.midi.tpqn,
               ctx.midi.events.size());

    // Load SoundFont
    ctx.sf2 = tsf_load_memory(sf2Data, (int)sf2Size);
    if (!ctx.sf2) {
        fmt::print(stderr, "Error: failed to load SoundFont\n");
        return -1;
    }
    fmt::print("SoundFont: {} presets\n", tsf_get_presetcount(ctx.sf2));

    ctx.maxVoices = maxVoices;
    ctx.maxLayers = maxLayersOpt.value_or(0);
    ctx.nextSpuAddr = 0x1010;
    ctx.loopPointTick = -1;

    // Select reverb preset
    ctx.reverbPreset = REVERB_DEFAULT_PRESET;  // hall by default
    if (reverbOpt.has_value()) {
        std::string rv = reverbOpt.value();
        ctx.reverbPreset = -1;
        for (int i = 0; i < REVERB_PRESET_COUNT; i++) {
            if (rv == REVERB_PRESETS[i].name) {
                ctx.reverbPreset = i;
                break;
            }
        }
        if (ctx.reverbPreset < 0) {
            fmt::print(stderr, "Error: unknown reverb preset '{}'. Available:", rv);
            for (int i = 0; i < REVERB_PRESET_COUNT; i++) fmt::print(stderr, " {}", REVERB_PRESETS[i].name);
            fmt::print(stderr, "\n");
            tsf_close(ctx.sf2);
            return -1;
        }
    }

    // Compute max SPU address: total RAM minus reverb buffer at top
    if (ctx.reverbPreset > 0 && ctx.reverbPreset < REVERB_PRESET_COUNT) {
        ctx.maxSpuAddr = SPU_RAM_SIZE - REVERB_PRESETS[ctx.reverbPreset].bufferSize;
        fmt::print("Reverb: {} (buffer: {} bytes, usable sample RAM: {} bytes)\n",
                   REVERB_PRESETS[ctx.reverbPreset].name, REVERB_PRESETS[ctx.reverbPreset].bufferSize,
                   ctx.maxSpuAddr - SPU_RAM_BASE);
    } else {
        ctx.maxSpuAddr = SPU_RAM_SIZE;
        fmt::print("Reverb: off\n");
    }

    // Generate the stream (this also builds the sample bank on-demand)
    fmt::print("Converting...\n");
    ctx.generateStream();

    fmt::print("Samples: {}, SPU RAM used: {} / {} bytes ({:.1f}%)\n", ctx.samples.size(), ctx.nextSpuAddr,
               ctx.maxSpuAddr, ctx.nextSpuAddr * 100.0 / ctx.maxSpuAddr);
    fmt::print("Macros: {}\n", ctx.macroDefs.size());
    fmt::print("Peak voices: {} / {}\n", ctx.allocator.peakVoices, maxVoices);
    fmt::print("Voice steals: {}\n", ctx.allocator.voiceSteals);
    fmt::print("Stream events: {}\n", ctx.stream.size());
    if (ctx.loopPointTick >= 0) {
        fmt::print("Loop point: tick {}\n", ctx.loopPointTick);
    }

    // Write output - use track name from MIDI if available
    std::string titleStr = ctx.trackName.empty() ? std::string(inputs[0]) : ctx.trackName;
    if (sampleOutput.has_value()) {
        // Split mode: separate sample and music files
        if (!ctx.writeSplit(output.value().c_str(), sampleOutput.value().c_str(), titleStr.c_str())) {
            fmt::print(stderr, "Error: failed to write output files\n");
            tsf_close(ctx.sf2);
            return -1;
        }
        fmt::print("Wrote: {} (music) + {} (samples)\n", output.value(), sampleOutput.value());
    } else {
        // Combined mode: everything in one file
        if (!ctx.writeSpd(output.value().c_str(), titleStr.c_str())) {
            fmt::print(stderr, "Error: failed to write output file\n");
            tsf_close(ctx.sf2);
            return -1;
        }
        fmt::print("Wrote: {}\n", output.value());
    }

    tsf_close(ctx.sf2);
    return 0;
}
