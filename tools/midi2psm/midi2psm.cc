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
#include "supportpsx/midi-converter.h"


using PCSX::MidiConverter::MIDI_CHANNEL_PRESSURE;
using PCSX::MidiConverter::MIDI_CONTROL_CHANGE;
using PCSX::MidiConverter::MIDI_CC_ALL_NOTES_OFF;
using PCSX::MidiConverter::MIDI_CC_ALL_SOUND_OFF;
using PCSX::MidiConverter::MIDI_CC_BANK_LSB;
using PCSX::MidiConverter::MIDI_CC_BANK_MSB;
using PCSX::MidiConverter::MIDI_CC_DATA_ENTRY_LSB;
using PCSX::MidiConverter::MIDI_CC_DATA_ENTRY_MSB;
using PCSX::MidiConverter::MIDI_CC_EXPRESSION;
using PCSX::MidiConverter::MIDI_CC_LOOP_POINT;
using PCSX::MidiConverter::MIDI_CC_MODULATION;
using PCSX::MidiConverter::MIDI_CC_PAN;
using PCSX::MidiConverter::MIDI_CC_RESET_ALL;
using PCSX::MidiConverter::MIDI_CC_REVERB_SEND;
using PCSX::MidiConverter::MIDI_CC_RPN_LSB;
using PCSX::MidiConverter::MIDI_CC_RPN_MSB;
using PCSX::MidiConverter::MIDI_CC_SUSTAIN;
using PCSX::MidiConverter::MIDI_CC_VOLUME;
using PCSX::MidiConverter::MIDI_DRUM_CHANNEL;
using PCSX::MidiConverter::MIDI_META;
using PCSX::MidiConverter::MIDI_META_COPYRIGHT;
using PCSX::MidiConverter::MIDI_META_MARKER;
using PCSX::MidiConverter::MIDI_META_TRACK_NAME;
using PCSX::MidiConverter::MIDI_META_TEMPO;
using PCSX::MidiConverter::MIDI_NOTE_OFF;
using PCSX::MidiConverter::MIDI_NOTE_ON;
using PCSX::MidiConverter::MIDI_PITCH_BEND;
using PCSX::MidiConverter::MIDI_PROGRAM_CHANGE;
using PCSX::MidiConverter::MidiFile;
using PCSX::MidiConverter::SampleKey;
using PCSX::MidiConverter::SPU_RAM_BASE;
using PCSX::MidiConverter::SPU_RAM_SIZE;
using PCSX::MidiConverter::SpuSample;
using PCSX::MidiConverter::extractAndEncode;
using PCSX::MidiConverter::extractMidiMetadata;
using PCSX::MidiConverter::findLoopPointTick;
using PCSX::MidiConverter::findRegions;
using PCSX::MidiConverter::midiNoteToFreq;
using PCSX::MidiConverter::sf2RegionToSpuADSR;

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
