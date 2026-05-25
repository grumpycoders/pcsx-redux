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
            p += 12;
            while (p + 8 <= end) {
                uint32_t chunkSize = p[4] | (p[5] << 8) | (p[6] << 16) | (p[7] << 24);
                if (memcmp(p, "data", 4) == 0) {
                    p += 8;
                    end = p + chunkSize;
                    break;
                }
                p += 8 + ((chunkSize + 1) & ~1);
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
                if (p + 1 >= end) break;
                uint8_t metaType = *p++;
                uint32_t metaLen = readVLQ(p, end);
                if (p + metaLen > end) break;
                if (metaType == MIDI_META_TEMPO && metaLen == 3) {
                    MidiEvent ev = {};
                    ev.absoluteTick = absTick;
                    ev.type = MIDI_META;
                    ev.data1 = MIDI_META_TEMPO;
                    ev.tempo = (p[0] << 16) | (p[1] << 8) | p[2];
                    events.push_back(ev);
                } else if (metaType == MIDI_META_MARKER || metaType == MIDI_META_TEXT ||
                           metaType == MIDI_META_TRACK_NAME || metaType == MIDI_META_COPYRIGHT) {
                    MidiEvent ev = {};
                    ev.absoluteTick = absTick;
                    ev.type = MIDI_META;
                    ev.data1 = metaType;
                    ev.textData = std::string((const char*)p, metaLen);
                    events.push_back(ev);
                } else if (metaType == MIDI_META_END_OF_TRACK) {
                    p += metaLen;
                    break;
                }
                p += metaLen;
            } else if (status >= MIDI_SYSTEM) {
                uint32_t sysLen = readVLQ(p, end);
                p += sysLen;
            } else if (type == MIDI_NOTE_OFF || type == MIDI_NOTE_ON || type == MIDI_POLY_PRESSURE ||
                       type == MIDI_CONTROL_CHANGE || type == MIDI_PITCH_BEND) {
                if (p + 2 > end) break;
                MidiEvent ev = {};
                ev.absoluteTick = absTick;
                ev.type = type;
                ev.channel = channel;
                ev.data1 = p[0];
                ev.data2 = p[1];
                if (type == MIDI_NOTE_ON && ev.data2 == 0) {
                    ev.type = MIDI_NOTE_OFF;
                }
                events.push_back(ev);
                p += 2;
            } else if (type == MIDI_PROGRAM_CHANGE || type == MIDI_CHANNEL_PRESSURE) {
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
    uint32_t spuAddr;       // SPU RAM address in bytes (used for size tracking)
    uint32_t adpcmSize;     // size in bytes
    uint32_t sampleRate;    // original sample rate
    uint32_t rootKey;       // MIDI note of natural pitch (pitch_keycenter)
    int32_t transpose;      // semitone offset (SF2 coarseTune)
    int32_t tune;           // fine tuning in cents (SF2 fineTune + pitchCorrection)
    bool hasLoop;
    uint32_t loopStartByte;
    std::vector<uint8_t> adpcmData;
};

// Key for deduplicating SF2 samples
struct SampleKey {
    unsigned int offset;
    unsigned int end;
    bool operator<(const SampleKey& o) const {
        if (offset != o.offset) return offset < o.offset;
        return end < o.end;
    }
};

static bool encodeSample(const int16_t* pcm, size_t sampleCount, bool loop, size_t loopStart, SpuSample& out) {
    PCSX::ADPCM::Encoder encoder;
    encoder.reset();

    size_t paddedCount = ((sampleCount + 27) / 28) * 28;
    std::vector<int16_t> padded(paddedCount, 0);
    memcpy(padded.data(), pcm, sampleCount * sizeof(int16_t));

    size_t totalBlocks = paddedCount / 28;
    out.adpcmData.resize(totalBlocks * 16 + 16);

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
// MIDI Note -> Frequency
// ============================================================================

static double midiNoteToFreq(int note) { return 440.0 * pow(2.0, (note - 69) / 12.0); }

// ============================================================================
// SF2 ADSR -> SPU ADSR
// ============================================================================

static uint8_t sf2AttackToSpu(float seconds) {
    if (seconds <= 0.0f) return 0x7F;
    if (seconds >= 10.0f) return 0x00;
    float rate = 127.0f - 4.0f * log2f(seconds / 0.0005f);
    if (rate < 0.0f) rate = 0.0f;
    if (rate > 127.0f) rate = 127.0f;
    return (uint8_t)(rate + 0.5f);
}

static uint8_t sf2DecayToSpu(float seconds) {
    if (seconds <= 0.0f) return 0x0F;
    if (seconds >= 30.0f) return 0x00;
    float value = 15.0f - log2f(seconds / 0.000292f);
    if (value < 0.0f) value = 0.0f;
    if (value > 15.0f) value = 15.0f;
    return (uint8_t)(value + 0.5f);
}

static uint8_t sf2SustainToSpu(float sustainGain) {
    if (sustainGain >= 1.0f) return 0x0F;
    if (sustainGain <= 0.0f) return 0x00;
    int level = (int)(sustainGain * 15.0f + 0.5f);
    if (level < 0) level = 0;
    if (level > 0x0F) level = 0x0F;
    return (uint8_t)level;
}

static uint8_t sf2ReleaseToSpu(float seconds) {
    if (seconds <= 0.0f) return 0x1F;
    if (seconds >= 30.0f) return 0x00;
    float value = 31.0f - log2f(seconds / 0.000446f);
    if (value < 0.0f) value = 0.0f;
    if (value > 31.0f) value = 31.0f;
    return (uint8_t)(value + 0.5f);
}

static void sf2RegionToSpuADSR(struct tsf_region* region, bool isDrum, uint16_t& adsrLo, uint16_t& adsrHi) {
    float attackSec = region->ampenv.attack;
    float decaySec = region->ampenv.decay;
    if (region->ampenv.keynumToDecay != 0.0f) {
        decaySec = (decaySec < -11950.0f) ? 0.0f : powf(2.0f, decaySec / 1200.0f);
    }
    float sustainGain = region->ampenv.sustain;
    float releaseSec = region->ampenv.release;

    if (attackSec < 0.0f) attackSec = 0.0f;
    if (decaySec < 0.0f) decaySec = 0.0f;
    if (releaseSec < 0.0f) releaseSec = 0.0f;
    if (sustainGain < 0.0f) sustainGain = 0.0f;

    if (isDrum && releaseSec > 0.3f) releaseSec = 0.1f;

    uint8_t attackRate = sf2AttackToSpu(attackSec);
    uint8_t decayRate = sf2DecayToSpu(decaySec);
    uint8_t sustainLevel = sf2SustainToSpu(sustainGain);
    uint8_t releaseRate = sf2ReleaseToSpu(releaseSec);

    uint8_t sustainRate = isDrum ? 0x1F : 0x00;
    uint8_t sustainDir = isDrum ? 1 : 0;
    uint8_t sustainMode = isDrum ? 0 : 0;

    adsrHi = (uint16_t)((1 << 15) |
                         ((attackRate & 0x7F) << 8) |
                         ((decayRate & 0x0F) << 4) |
                         (sustainLevel & 0x0F));

    adsrLo = (uint16_t)(((sustainMode & 1) << 14) |
                         ((sustainDir & 1) << 13) |
                         ((sustainRate & 0x1F) << 6) |
                         (1 << 5) |
                         (releaseRate & 0x1F));
}

// ============================================================================
// SF2 Region Helpers
// ============================================================================

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

// SPU RAM layout
static constexpr uint32_t SPU_RAM_BASE = 0x1010;
static constexpr uint32_t SPU_RAM_SIZE = 0x80000;

static size_t extractAndEncode(tsf* sf2, struct tsf_region* region, std::vector<SpuSample>& samples,
                               std::map<SampleKey, size_t>& sampleMap, uint32_t& nextSpuAddr,
                               uint32_t maxSpuAddr = SPU_RAM_SIZE) {
    SampleKey key = {region->offset, region->end};
    auto it = sampleMap.find(key);
    if (it != sampleMap.end()) return it->second;

    unsigned int sampleCount = region->end - region->offset;
    if (sampleCount == 0) return (size_t)-1;

    std::vector<int16_t> pcm(sampleCount);
    for (unsigned int i = 0; i < sampleCount; i++) {
        float v = sf2->fontSamples[region->offset + i] * 32767.0f;
        if (v > 32767.0f) v = 32767.0f;
        if (v < -32768.0f) v = -32768.0f;
        pcm[i] = (int16_t)v;
    }

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

    size_t idx = samples.size();
    fmt::print("  Sample {}: offset={} end={} rate={}Hz rootKey={} transpose={} tune={} cents loop={} size={} bytes\n",
               idx, region->offset, region->end, sample.sampleRate, sample.rootKey, sample.transpose, sample.tune,
               sample.hasLoop ? "yes" : "no", sample.adpcmSize);
    samples.push_back(std::move(sample));
    sampleMap[key] = idx;
    return idx;
}

// ============================================================================
// PSM Event Types
// ============================================================================

enum PsmEventType : uint8_t {
    PSM_NOTE_ON = 0x00,
    PSM_NOTE_OFF = 0x01,
    PSM_PITCH_BEND = 0x02,
    PSM_CC_VOLUME = 0x03,
    PSM_CC_PAN = 0x04,
    PSM_CC_EXPRESSION = 0x05,
    PSM_CC_SUSTAIN = 0x06,
    PSM_CC_MODULATION = 0x07,
    PSM_CC_REVERB = 0x08,
    PSM_PROGRAM_CHANGE = 0x09,
    PSM_TEMPO_CHANGE = 0x0A,
    PSM_LOOP_POINT = 0x0B,
    PSM_END = 0x0C,
    PSM_LONG_WAIT = 0xFF,
};

struct PsmEvent {
    uint16_t deltaTick;
    uint8_t type;
    uint8_t channel;
    uint32_t data;
};

// ============================================================================
// VAB Format Structures (Sony SDK compatible)
// ============================================================================

#pragma pack(push, 1)

struct VabHdr {
    char magic[4];         // "pBAV"
    uint32_t version;      // format version
    uint32_t id;           // bank ID
    uint32_t fileSize;     // total file size in bytes
    uint16_t reserved0;    // system reserved
    uint16_t numPrograms;  // number of programs (max 128)
    uint16_t numTones;     // total number of tones
    uint16_t numVags;      // number of VAG samples (max 254)
    uint8_t masterVol;     // master volume (0-127)
    uint8_t masterPan;     // master pan (0-127, 64 = center)
    uint8_t attr1;         // user-defined
    uint8_t attr2;         // user-defined
    uint32_t reserved1;    // system reserved
};

struct ProgAtr {
    uint8_t tones;         // number of tones in this program (0-16)
    uint8_t mvol;          // program volume (0-127)
    uint8_t prior;         // priority (0-127)
    uint8_t mode;          // mode flags
    uint8_t mpan;          // program pan (0-127, 64 = center)
    uint8_t reserved0;
    int16_t attr;          // user-defined attribute
    uint32_t reserved1;
    uint32_t reserved2;
};

struct VagAtr {
    uint8_t prior;         // priority (0-127)
    uint8_t mode;          // mode flags
    uint8_t vol;           // tone volume (0-127)
    uint8_t pan;           // tone pan (0-127, 64 = center)
    uint8_t center;        // center note (root key, MIDI note number)
    uint8_t shift;         // pitch fine tune (signed cents, as two's complement uint8)
    uint8_t min;           // minimum key range
    uint8_t max;           // maximum key range
    uint8_t vibW;          // vibrato width
    uint8_t vibT;          // vibrato time/frequency
    uint8_t porW;          // portamento width
    uint8_t porT;          // portamento time
    uint8_t pbmin;         // pitch bend min (semitones)
    uint8_t pbmax;         // pitch bend max (semitones)
    uint8_t reserved0;
    uint8_t reserved1;
    uint16_t adsr1;        // SPU ADSR register (voice +0x08)
    uint16_t adsr2;        // SPU ADSR register (voice +0x0A)
    int16_t prog;          // program index this tone belongs to
    int16_t vag;           // VAG index (0-based, -1 = unused)
    int16_t reserved2[4];  // reserved (reserved2[0] = sampleRate >> 4 for player)
};

#pragma pack(pop)

static_assert(sizeof(VabHdr) == 32, "VabHdr must be 32 bytes");
static_assert(sizeof(ProgAtr) == 16, "ProgAtr must be 16 bytes");
static_assert(sizeof(VagAtr) == 32, "VagAtr must be 32 bytes");

// ============================================================================
// Channel State (minimal - player handles volumes/pitch/sustain)
// ============================================================================

struct ChannelState {
    int program;
    uint8_t bankMSB;
    uint8_t bankLSB;

    ChannelState() : program(0), bankMSB(0), bankLSB(0) {}
};

// ============================================================================
// Conversion Context
// ============================================================================

using FilePtr = PCSX::IO<PCSX::File>;

struct ProgramBuildInfo {
    uint8_t toneCount = 0;
    // Map from region index within the tsf_preset to tone index within this program
    std::map<int, uint8_t> regionToTone;
};

struct ConvertContext {
    MidiFile midi;
    tsf* sf2;

    // Sample management
    std::vector<SpuSample> samples;
    std::map<SampleKey, size_t> sampleMap;
    uint32_t nextSpuAddr;

    // Channel state
    ChannelState channels[16];

    // VAB building
    ProgramBuildInfo programBuild[128];
    int numPrograms;
    std::map<int, uint8_t> presetToProgram;  // tsf preset index -> VAB program index
    ProgAtr progAtrs[128];
    VagAtr vagAtrs[128 * 16];  // max possible (compacted on write)

    // PSM events
    std::vector<PsmEvent> psmEvents;
    uint32_t lastTick;

    // Options
    unsigned maxLayers;

    // Metadata and loop
    std::string trackName;
    std::string copyright;
    int32_t loopPointTick;

    // Polyphony tracking
    int activeVoices;
    int peakPolyphony;

    // ---- Methods ----
    void generate();
    bool writeVab(const char* filename);
    bool writeVabSplit(const char* vhFile, const char* vbFile);
    bool writePsm(const char* filename);

    void emitEvent(uint8_t type, uint8_t channel, uint32_t data, uint32_t absTick);
    uint8_t getOrAssignProgram(int presetIndex);
    uint8_t getOrAssignTone(uint8_t programIdx, int presetIndex, struct tsf_region* region);
};

void ConvertContext::emitEvent(uint8_t type, uint8_t channel, uint32_t data, uint32_t absTick) {
    uint32_t delta = absTick - lastTick;
    lastTick = absTick;

    // Consume excess delta with LONG_WAIT events (max deltaTick is 65535)
    while (delta > 65535) {
        uint32_t consume = delta - 65535;  // leave up to 65535 for the final event
        if (consume > 0xFFFFFFFF) consume = 0xFFFFFFFF;
        PsmEvent wait = {};
        wait.deltaTick = 0;
        wait.type = PSM_LONG_WAIT;
        wait.channel = 0;
        wait.data = consume;
        psmEvents.push_back(wait);
        delta -= consume;
    }

    PsmEvent ev = {};
    ev.deltaTick = (uint16_t)delta;
    ev.type = type;
    ev.channel = channel;
    ev.data = data;
    psmEvents.push_back(ev);
}

uint8_t ConvertContext::getOrAssignProgram(int presetIndex) {
    auto it = presetToProgram.find(presetIndex);
    if (it != presetToProgram.end()) return it->second;

    if (numPrograms >= 128) {
        fmt::print(stderr, "Warning: exceeded 128 VAB programs, reusing program 127\n");
        return 127;
    }

    uint8_t idx = (uint8_t)numPrograms++;
    presetToProgram[presetIndex] = idx;

    // Initialize ProgAtr with sensible defaults
    ProgAtr& pa = progAtrs[idx];
    memset(&pa, 0, sizeof(ProgAtr));
    pa.tones = 0;
    pa.mvol = 127;
    pa.prior = 127;
    pa.mode = 0;
    pa.mpan = 64;

    return idx;
}

uint8_t ConvertContext::getOrAssignTone(uint8_t programIdx, int presetIndex, struct tsf_region* region) {
    // Compute region index within the tsf_preset
    struct tsf_preset* preset = &sf2->presets[presetIndex];
    int regionIdx = (int)(region - &preset->regions[0]);

    auto& build = programBuild[programIdx];
    auto it = build.regionToTone.find(regionIdx);
    if (it != build.regionToTone.end()) return it->second;

    if (build.toneCount >= 16) {
        fmt::print(stderr, "Warning: program {} exceeded 16 tones, reusing tone 15\n", programIdx);
        return 15;
    }

    uint8_t toneIdx = build.toneCount++;
    build.regionToTone[regionIdx] = toneIdx;

    // Update ProgAtr tone count
    progAtrs[programIdx].tones = build.toneCount;

    // Extract and encode the sample
    size_t sampleIdx = extractAndEncode(sf2, region, samples, sampleMap, nextSpuAddr);

    // Fill in the VagAtr entry
    VagAtr& va = vagAtrs[programIdx * 16 + toneIdx];
    memset(&va, 0, sizeof(VagAtr));

    va.prior = 127;
    va.mode = 0;

    // Apply SF2 attenuation to tone volume
    float attnGain = 1.0f;
    if (region->attenuation > 0.0f) {
        attnGain = powf(10.0f, -region->attenuation / 200.0f);
        if (attnGain < 0.0f) attnGain = 0.0f;
        if (attnGain > 1.0f) attnGain = 1.0f;
    }
    va.vol = (uint8_t)(attnGain * 127.0f + 0.5f);

    // Map SF2 pan (-0.5 to +0.5) to VAB pan (0-127, 64 = center)
    int pan = (int)(64.0f + region->pan * 128.0f);
    if (pan < 0) pan = 0;
    if (pan > 127) pan = 127;
    va.pan = (uint8_t)pan;

    // Compute adjusted center note: fold sample rate and transpose into center
    // so the player can assume 44100 Hz and just compute freq(note)/freq(center)*0x1000
    SpuSample& sample = samples[sampleIdx];
    double semitonesAdj = 12.0 * log2(44100.0 / (double)sample.sampleRate);
    double adjustedCenter = (double)sample.rootKey - sample.transpose + semitonesAdj;
    int centerNote = (int)round(adjustedCenter);
    int fineTuneCents = (int)round((adjustedCenter - centerNote) * 100.0) + sample.tune;

    // Clamp center to valid MIDI range
    while (centerNote < 0 && fineTuneCents < 12700) { centerNote += 12; fineTuneCents -= 1200; }
    while (centerNote > 127 && fineTuneCents > -12700) { centerNote -= 12; fineTuneCents += 1200; }
    if (centerNote < 0) centerNote = 0;
    if (centerNote > 127) centerNote = 127;

    // Clamp fine tune to int8 range (-128 to +127 cents)
    if (fineTuneCents < -128) fineTuneCents = -128;
    if (fineTuneCents > 127) fineTuneCents = 127;

    va.center = (uint8_t)centerNote;
    va.shift = (uint8_t)(int8_t)fineTuneCents;

    // Key range from SF2 region
    va.min = (uint8_t)region->lokey;
    va.max = (uint8_t)region->hikey;

    // Vibrato/portamento: zero (player handles CC#1 modulation)
    va.vibW = 0;
    va.vibT = 0;
    va.porW = 0;
    va.porT = 0;

    // Pitch bend range: default 2 semitones
    va.pbmin = 2;
    va.pbmax = 2;

    // ADSR
    bool isDrum = false;
    // Check if this program is a drum program by scanning which channels use it
    // (simpler: check if any region in the preset has group != 0, or if bank >= 128)
    int bank = tsf_get_presetindex(sf2, 128, 0);
    if (bank >= 0 && bank == presetIndex) isDrum = true;
    // Also check for drum channel assignment (program >= 128 convention not applicable here,
    // so we rely on the drum bank check)

    sf2RegionToSpuADSR(region, isDrum, va.adsr1, va.adsr2);

    va.prog = (int16_t)programIdx;
    va.vag = (sampleIdx != (size_t)-1) ? (int16_t)sampleIdx : -1;

    // Store sample rate in reserved field for player reference
    // Player can use this for pitch computation if it needs the actual rate
    va.reserved2[0] = (int16_t)(sample.sampleRate >> 4);  // fits in 16 bits for rates up to ~500 kHz

    return toneIdx;
}

void ConvertContext::generate() {
    lastTick = 0;
    loopPointTick = -1;
    activeVoices = 0;
    peakPolyphony = 0;
    numPrograms = 0;
    nextSpuAddr = SPU_RAM_BASE;

    memset(progAtrs, 0, sizeof(progAtrs));
    memset(vagAtrs, 0, sizeof(vagAtrs));

    for (int i = 0; i < 16; i++) {
        channels[i] = ChannelState();
    }
    channels[MIDI_DRUM_CHANNEL].program = 128;

    // Pre-scan for loop markers
    for (auto& mev : midi.events) {
        if (mev.type == MIDI_CONTROL_CHANGE && mev.data1 == MIDI_CC_LOOP_POINT) {
            loopPointTick = (int32_t)mev.absoluteTick;
            break;
        }
        if (mev.type == MIDI_META && mev.data1 == MIDI_META_MARKER) {
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

    // Default MIDI tempo: 120 BPM = 500000 us/beat
    uint32_t currentTempo = 500000;

    auto computeTickRate = [&]() -> uint32_t {
        double ticksPerSec = (double)midi.tpqn * 1000000.0 / (double)currentTempo;
        return (uint32_t)(ticksPerSec * 65536.0);  // 16.16 fixed point
    };

    // Emit initial tick rate as first event
    emitEvent(PSM_TEMPO_CHANGE, 0, computeTickRate(), 0);

    bool loopPointEmitted = false;

    // If no loop marker found, emit loop point at start
    if (loopPointTick < 0) {
        emitEvent(PSM_LOOP_POINT, 0, 0, 0);
        loopPointEmitted = true;
    }

    // Simple polyphony tracking: count active (channel, note) pairs
    // Each NOTE_ON for a layer increments, NOTE_OFF for a note decrements all its layers
    struct ActiveNote {
        uint8_t channel;
        uint8_t note;
        int layers;  // how many PSM NOTE_ONs were emitted for this note
    };
    std::vector<ActiveNote> activeNotes;

    // Process all MIDI events
    for (size_t i = 0; i < midi.events.size(); i++) {
        auto& mev = midi.events[i];

        // Emit loop point if we've reached its tick
        if (!loopPointEmitted && loopPointTick >= 0 && (int32_t)mev.absoluteTick >= loopPointTick) {
            emitEvent(PSM_LOOP_POINT, 0, 0, (uint32_t)loopPointTick);
            loopPointEmitted = true;
        }

        if (mev.type == MIDI_META && mev.data1 == MIDI_META_TEMPO) {
            currentTempo = mev.tempo;
            emitEvent(PSM_TEMPO_CHANGE, 0, computeTickRate(), mev.absoluteTick);
            continue;
        }

        if (mev.type == MIDI_META) continue;

        if (mev.type == MIDI_PROGRAM_CHANGE) {
            channels[mev.channel].program = mev.data1;
            if (mev.channel == MIDI_DRUM_CHANNEL) channels[mev.channel].program = 128;

            // Emit program change (the program index will be resolved at NOTE_ON time,
            // but emit the event for the player's state tracking)
            // We'll use the MIDI program number; the player maps it to VAB program
            // Actually, we should emit the VAB program index. But we may not know it yet
            // if no note has been played with this program. Defer: emit with MIDI program number.
            // The player can use this for display/debugging but relies on NOTE_ON's program field.
            emitEvent(PSM_PROGRAM_CHANGE, mev.channel, mev.data1, mev.absoluteTick);
            continue;
        }

        if (mev.type == MIDI_CONTROL_CHANGE) {
            switch (mev.data1) {
                case MIDI_CC_VOLUME:
                    emitEvent(PSM_CC_VOLUME, mev.channel, mev.data2, mev.absoluteTick);
                    break;
                case MIDI_CC_PAN:
                    emitEvent(PSM_CC_PAN, mev.channel, mev.data2, mev.absoluteTick);
                    break;
                case MIDI_CC_EXPRESSION:
                    emitEvent(PSM_CC_EXPRESSION, mev.channel, mev.data2, mev.absoluteTick);
                    break;
                case MIDI_CC_SUSTAIN:
                    emitEvent(PSM_CC_SUSTAIN, mev.channel, mev.data2, mev.absoluteTick);
                    break;
                case MIDI_CC_MODULATION:
                    emitEvent(PSM_CC_MODULATION, mev.channel, mev.data2, mev.absoluteTick);
                    break;
                case MIDI_CC_REVERB_SEND:
                    emitEvent(PSM_CC_REVERB, mev.channel, mev.data2, mev.absoluteTick);
                    break;
                case MIDI_CC_BANK_MSB:
                    channels[mev.channel].bankMSB = mev.data2;
                    break;
                case MIDI_CC_BANK_LSB:
                    channels[mev.channel].bankLSB = mev.data2;
                    break;
                case MIDI_CC_ALL_SOUND_OFF:
                case MIDI_CC_ALL_NOTES_OFF:
                    // Emit as sustain off + let the player handle it
                    // The player sees NOTE_OFF for each active note, but for panic CCs
                    // we can emit a sustain-off to release held voices
                    emitEvent(PSM_CC_SUSTAIN, mev.channel, 0, mev.absoluteTick);
                    // Also emit NOTE_OFF for all tracked active notes on this channel
                    for (auto it2 = activeNotes.begin(); it2 != activeNotes.end();) {
                        if (it2->channel == mev.channel) {
                            emitEvent(PSM_NOTE_OFF, mev.channel, it2->note, mev.absoluteTick);
                            activeVoices -= it2->layers;
                            it2 = activeNotes.erase(it2);
                        } else {
                            ++it2;
                        }
                    }
                    break;
                case MIDI_CC_RESET_ALL:
                    // Reset channel CCs to defaults
                    emitEvent(PSM_CC_VOLUME, mev.channel, 100, mev.absoluteTick);
                    emitEvent(PSM_CC_PAN, mev.channel, 64, mev.absoluteTick);
                    emitEvent(PSM_CC_EXPRESSION, mev.channel, 127, mev.absoluteTick);
                    emitEvent(PSM_CC_SUSTAIN, mev.channel, 0, mev.absoluteTick);
                    emitEvent(PSM_CC_MODULATION, mev.channel, 0, mev.absoluteTick);
                    emitEvent(PSM_CC_REVERB, mev.channel, 40, mev.absoluteTick);
                    emitEvent(PSM_PITCH_BEND, mev.channel, 0, mev.absoluteTick);
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
            // Pack as signed 16-bit in lower 16 bits of data
            emitEvent(PSM_PITCH_BEND, mev.channel, (uint32_t)(uint16_t)(int16_t)bend, mev.absoluteTick);
            continue;
        }

        if (mev.type == MIDI_NOTE_ON) {
            uint8_t note = mev.data1;
            uint8_t velocity = mev.data2;
            uint8_t ch = mev.channel;
            auto& chanState = channels[ch];
            bool isDrum = (ch == MIDI_DRUM_CHANNEL);

            // Find the SF2 preset
            int bank = isDrum ? 128 : (int)chanState.bankMSB;
            int prog = isDrum ? 0 : chanState.program;
            int presetIndex = tsf_get_presetindex(sf2, bank, prog);
            if (presetIndex < 0) {
                if (!isDrum) presetIndex = tsf_get_presetindex(sf2, 0, prog);
                if (presetIndex < 0) continue;
            }

            auto regions = findRegions(sf2, presetIndex, note, velocity);
            if (regions.empty()) continue;

            if (maxLayers > 0 && regions.size() > maxLayers) {
                regions.resize(maxLayers);
            }

            // Get or assign VAB program
            uint8_t vabProg = getOrAssignProgram(presetIndex);

            int layerCount = 0;
            for (auto* region : regions) {
                // Get or assign tone within the program
                uint8_t toneIdx = getOrAssignTone(vabProg, presetIndex, region);

                // Pack NOTE_ON data: note | velocity | program | toneIndex
                uint32_t data = (uint32_t)note |
                                ((uint32_t)velocity << 8) |
                                ((uint32_t)vabProg << 16) |
                                ((uint32_t)toneIdx << 24);
                emitEvent(PSM_NOTE_ON, ch, data, mev.absoluteTick);
                layerCount++;
            }

            // Track polyphony
            activeVoices += layerCount;
            if (activeVoices > peakPolyphony) peakPolyphony = activeVoices;

            // Record for NOTE_OFF tracking
            activeNotes.push_back({ch, note, layerCount});
            continue;
        }

        if (mev.type == MIDI_NOTE_OFF) {
            emitEvent(PSM_NOTE_OFF, mev.channel, mev.data1, mev.absoluteTick);

            // Update polyphony tracking: release all layers for this (channel, note)
            for (auto it2 = activeNotes.begin(); it2 != activeNotes.end(); ++it2) {
                if (it2->channel == mev.channel && it2->note == mev.data1) {
                    activeVoices -= it2->layers;
                    activeNotes.erase(it2);
                    break;
                }
            }
            continue;
        }
    }

    // Emit loop point if never emitted
    if (!loopPointEmitted) {
        uint32_t endTick = midi.events.empty() ? 0 : midi.events.back().absoluteTick;
        emitEvent(PSM_LOOP_POINT, 0, 0, endTick);
    }

    // End marker
    {
        uint32_t endTick = midi.events.empty() ? 0 : midi.events.back().absoluteTick;
        emitEvent(PSM_END, 0, 0, endTick);
    }
}

bool ConvertContext::writeVab(const char* filename) {
    FilePtr f(new PCSX::PosixFile(filename, PCSX::FileOps::TRUNCATE));
    if (f->failed()) return false;

    // Compute sizes
    uint16_t totalTones = 0;
    for (int i = 0; i < numPrograms; i++) {
        totalTones += progAtrs[i].tones;
    }
    uint16_t numVags = (uint16_t)samples.size();

    uint32_t headerSize = sizeof(VabHdr);
    uint32_t progTableSize = 128 * sizeof(ProgAtr);
    uint32_t toneTableSize = (uint32_t)numPrograms * 16 * sizeof(VagAtr);
    uint32_t vagOffsetTableSize = 256 * sizeof(uint16_t);
    uint32_t vagBodySize = 0;
    for (auto& s : samples) vagBodySize += s.adpcmSize;

    uint32_t totalSize = headerSize + progTableSize + toneTableSize + vagOffsetTableSize + vagBodySize;

    // Write header
    VabHdr hdr = {};
    hdr.magic[0] = 'p';
    hdr.magic[1] = 'B';
    hdr.magic[2] = 'A';
    hdr.magic[3] = 'V';
    hdr.version = 7;  // standard VAB version
    hdr.id = 0;
    hdr.fileSize = totalSize;
    hdr.reserved0 = 0;
    hdr.numPrograms = (uint16_t)numPrograms;
    hdr.numTones = totalTones;
    hdr.numVags = numVags;
    hdr.masterVol = 127;
    hdr.masterPan = 64;
    hdr.attr1 = 0;
    hdr.attr2 = 0;
    hdr.reserved1 = 0;
    f->write(&hdr, sizeof(VabHdr));

    // Write ProgAtr table (always 128 entries)
    for (int i = 0; i < 128; i++) {
        f->write(&progAtrs[i], sizeof(ProgAtr));
    }

    // Write VagAtr table (numPrograms * 16 entries)
    for (int i = 0; i < numPrograms * 16; i++) {
        f->write(&vagAtrs[i], sizeof(VagAtr));
    }

    // Write VAG offset table (256 entries, each is size >> 3)
    for (int i = 0; i < 256; i++) {
        uint16_t entry = 0;
        if (i < (int)samples.size()) {
            entry = (uint16_t)(samples[i].adpcmSize >> 3);
        }
        f->write<uint16_t>(entry);
    }

    // Write concatenated VAG body (headerless ADPCM data)
    for (auto& s : samples) {
        f->write(s.adpcmData.data(), s.adpcmData.size());
    }

    f->close();
    return true;
}

bool ConvertContext::writeVabSplit(const char* vhFile, const char* vbFile) {
    // Write VB file: raw concatenated VAG ADPCM body (disposable after DMA)
    {
        FilePtr f(new PCSX::PosixFile(vbFile, PCSX::FileOps::TRUNCATE));
        if (f->failed()) return false;
        for (auto& s : samples) {
            f->write(s.adpcmData.data(), s.adpcmData.size());
        }
        f->close();
    }

    // Write VH file: header + ProgAtr + VagAtr + VAG offset table (no body)
    {
        FilePtr f(new PCSX::PosixFile(vhFile, PCSX::FileOps::TRUNCATE));
        if (f->failed()) return false;

        uint16_t totalTones = 0;
        for (int i = 0; i < numPrograms; i++) {
            totalTones += progAtrs[i].tones;
        }
        uint16_t numVagsCount = (uint16_t)samples.size();

        uint32_t vhSize = sizeof(VabHdr) + 128 * sizeof(ProgAtr) +
                          (uint32_t)numPrograms * 16 * sizeof(VagAtr) +
                          256 * sizeof(uint16_t);
        uint32_t vbSize = 0;
        for (auto& s : samples) vbSize += s.adpcmSize;

        VabHdr hdr = {};
        hdr.magic[0] = 'p';
        hdr.magic[1] = 'B';
        hdr.magic[2] = 'A';
        hdr.magic[3] = 'V';
        hdr.version = 7;
        hdr.id = 0;
        hdr.fileSize = vhSize + vbSize;  // total logical size
        hdr.reserved0 = 0;
        hdr.numPrograms = (uint16_t)numPrograms;
        hdr.numTones = totalTones;
        hdr.numVags = numVagsCount;
        hdr.masterVol = 127;
        hdr.masterPan = 64;
        hdr.attr1 = 0;
        hdr.attr2 = 0;
        hdr.reserved1 = 0;
        f->write(&hdr, sizeof(VabHdr));

        for (int i = 0; i < 128; i++) {
            f->write(&progAtrs[i], sizeof(ProgAtr));
        }

        for (int i = 0; i < numPrograms * 16; i++) {
            f->write(&vagAtrs[i], sizeof(VagAtr));
        }

        for (int i = 0; i < 256; i++) {
            uint16_t entry = 0;
            if (i < (int)samples.size()) {
                entry = (uint16_t)(samples[i].adpcmSize >> 3);
            }
            f->write<uint16_t>(entry);
        }

        f->close();
    }

    return true;
}

bool ConvertContext::writePsm(const char* filename) {
    FilePtr f(new PCSX::PosixFile(filename, PCSX::FileOps::TRUNCATE));
    if (f->failed()) return false;

    // Find the initial tick rate from the first TEMPO_CHANGE event
    uint32_t initialTickRate = 0;
    for (auto& ev : psmEvents) {
        if (ev.type == PSM_TEMPO_CHANGE) {
            initialTickRate = ev.data;
            break;
        }
    }

    // Write PSM header (16 bytes)
    f->write<uint8_t>('P');
    f->write<uint8_t>('S');
    f->write<uint8_t>('M');
    f->write<uint8_t>(0);
    f->write<uint32_t>(1);  // version
    f->write<uint32_t>(initialTickRate);
    f->write<uint32_t>((uint32_t)psmEvents.size());

    // Write events (8 bytes each)
    for (auto& ev : psmEvents) {
        f->write<uint16_t>(ev.deltaTick);
        f->write<uint8_t>(ev.type);
        f->write<uint8_t>(ev.channel);
        f->write<uint32_t>(ev.data);
    }

    f->close();
    return true;
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char** argv) {
    CommandLine::args args(argc, argv);
    const auto output = args.get<std::string>("o");
    const auto soundfont = args.get<std::string>("s");
    const auto bankOutput = args.get<std::string>("b");
    const auto sampleOutput = args.get<std::string>("i");
    const auto maxLayersOpt = args.get<unsigned>("l");

    fmt::print(R"(
midi2psm - MIDI to PSM+VAB converter
Part of PCSX-Redux - https://github.com/grumpycoders/pcsx-redux

)");

    const auto inputs = args.positional();
    const bool asksForHelp = args.get<bool>("h").value_or(false);
    const bool hasOutput = output.has_value();
    const bool hasSoundfont = soundfont.has_value();
    const bool hasBankOutput = bankOutput.has_value();
    const bool oneInput = inputs.size() == 1;

    if (asksForHelp || !oneInput || !hasOutput || !hasSoundfont || !hasBankOutput) {
        fmt::print(R"(
Usage: {} input.mid -s soundfont.sf2 -o output.psm -b output.vab [-i output.vb] [-l maxlayers] [-h]
  input.mid          mandatory: the input MIDI file.
  -s soundfont.sf2   mandatory: the SoundFont instrument bank.
  -o output.psm      mandatory: the output PSM event stream file.
  -b output.vab      mandatory: the output VAB instrument bank file (VH when -i is used).
  -i output.vb       optional: separate sample body file. When specified,
                     -b writes only the VH (header, programs, tones, offset table)
                     and -i writes the VB (raw sample data). The VB buffer can be
                     freed after uploading to SPU RAM via PSM_LoadBankEx().
  -l maxlayers       optional: max overlapping SF2 regions per note (default 0 = unlimited).
                     Setting to 1 disables layered instruments. Useful when voice
                     count is limited and layers cause excessive voice stealing.
  -h                 display this help and exit.
)",
                   argv[0]);
        return asksForHelp ? 0 : -1;
    }

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

    ctx.maxLayers = maxLayersOpt.value_or(0);

    // Generate PSM events and build VAB
    fmt::print("Converting...\n");
    ctx.generate();

    // Compute total tone count
    uint16_t totalTones = 0;
    for (int i = 0; i < ctx.numPrograms; i++) {
        totalTones += ctx.progAtrs[i].tones;
    }

    fmt::print("Programs: {}\n", ctx.numPrograms);
    fmt::print("Tones: {}\n", totalTones);
    fmt::print("Samples: {}, SPU RAM used: {} / {} bytes ({:.1f}%)\n", ctx.samples.size(), ctx.nextSpuAddr,
               SPU_RAM_SIZE, ctx.nextSpuAddr * 100.0 / SPU_RAM_SIZE);
    fmt::print("PSM events: {}\n", ctx.psmEvents.size());
    fmt::print("Peak polyphony: {}\n", ctx.peakPolyphony);
    if (ctx.loopPointTick >= 0) {
        fmt::print("Loop point: tick {}\n", ctx.loopPointTick);
    }

    // Write VAB file (combined or split)
    if (sampleOutput.has_value()) {
        // Split mode: VH (header only) + VB (sample body, disposable)
        if (!ctx.writeVabSplit(bankOutput.value().c_str(), sampleOutput.value().c_str())) {
            fmt::print(stderr, "Error: failed to write split VAB files\n");
            tsf_close(ctx.sf2);
            return -1;
        }
        fmt::print("Wrote: {} (VH instrument header) + {} (VB sample body)\n",
                   bankOutput.value(), sampleOutput.value());
    } else {
        // Combined mode: single VAB file
        if (!ctx.writeVab(bankOutput.value().c_str())) {
            fmt::print(stderr, "Error: failed to write VAB file\n");
            tsf_close(ctx.sf2);
            return -1;
        }
        fmt::print("Wrote: {} (VAB instrument bank)\n", bankOutput.value());
    }

    // Write PSM file
    if (!ctx.writePsm(output.value().c_str())) {
        fmt::print(stderr, "Error: failed to write PSM file\n");
        tsf_close(ctx.sf2);
        return -1;
    }
    fmt::print("Wrote: {} (PSM event stream)\n", output.value());

    tsf_close(ctx.sf2);
    return 0;
}
