/***************************************************************************
 *   Copyright (C) 2019 PCSX-Redux authors                                 *
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

#pragma once

#include <stdint.h>

#include <atomic>
#include <thread>

#include "core/decode_xa.h"
#include "core/spu.h"
#include "core/sstate.h"
#include "json.hpp"
#include "spu/adsr.h"
#include "spu/noise.h"
#include "spu/reverb.h"
#include "spu/sdlaudio.h"
#include "spu/types.h"
#include "support/settings.h"

namespace PCSX {

namespace SPU {

// Compile-time mode axes for the per-voice synthesis loop. Both are per-voice
// mode flags that the register thread can write while a batch is being mixed.
// They are resolved into template arguments ONCE, at the top of the voice's
// batch, so a mid-batch write now lands on the next batch instead of the next
// sample. That is the one thing in this loop that is not behaviour-preserving
// by construction: a batch is NSSIZE = 45 samples = 1.02ms, against the 16.7ms
// (60Hz) or 33.3ms (30Hz) frame clock that already quantises whatever event -
// player input, an on-screen hit - drove the driver to write the flag.
//
// FModRole - this voice's part in frequency modulation. The values match the
//   Chan::FMod encoding, which registers.cc writes in PAIRS: setting the
//   pitch-mod bit for voice N makes N the Target and N-1 the Source. Hoisting
//   this hoists the ROLE only; the modulation data itself (fmodInput[ns]) stays
//   per-sample.
enum class FModRole { None = 0, Target = 1, Source = 2 };

// SampleSource - where the pre-envelope sample comes from. Note that a Noise
//   voice still runs the ADPCM decode loop: the decoded samples are discarded,
//   but the cursor advance, the IRQ address check and the ENDX latch all hang
//   off it.
enum class SampleSource { Adpcm, Noise };

// Two further per-voice flags were considered as axes and deliberately left as
// runtime branches. Chan::Mute/Chan::Solo are the debugger's mute, not
// something a game drives, and Chan::RVBActive gates a single call; each guards
// one statement, so templating them would double the instantiation matrix twice
// over to remove a pair of well-predicted compares. Adding either is a code-size
// decision, not a correctness one - the same call polys.cc records for its ABR
// axis.

class impl final : public SPUInterface {
  public:
    using json = nlohmann::json;
    bool open() final;
    // SPU functions.
    long init(void) final;
    long shutdown(void) final;
    long close(void) final;
    void wipeChannels();
    void writeRegister(uint32_t, uint16_t) final;
    uint16_t readRegister(uint32_t) final;
    void lockSPURAM() final;
    void unlockSPURAM() final;
    void resetCaptureBuffer() final;
    void writeDMAMem(uint16_t *, int) final;
    void readDMAMem(uint16_t *, int) final;
    virtual void playADPCMchannel(xa_decode_t *) final;

    void save(SaveStates::SPU &) final;
    void load(const SaveStates::SPU &) final;

    virtual void setLua(Lua L) override;

    void playCDDAchannel(int16_t *, int) final;
    void registerCDDAVolume(void (*CDDAVcallback)(uint16_t, uint16_t));

    // Number of channels.
    static const size_t MAXCHAN = 24;

    // The per-voice capture mirrors are 0x200 samples each and the write pointer
    // wraps every 0x200; SPUSTAT bit 11 says which half it is in. Both the SPU
    // thread's own advance and the SPUSTAT read-time reconstruction key off these.
    static constexpr int kCaptureRegionSamples = 0x200;
    static constexpr int kCaptureHalfMarker = kCaptureRegionSamples / 2;  // 0x100
    // Number of characters for a channel tag.
    static constexpr unsigned CHANNEL_TAG = 32;
    // Number of samples for the debugger wave plot.
    static const unsigned DEBUG_SAMPLES = 1024;

    uint32_t getFrameCount() override { return m_audioOut.getFrameCount(); }

    void debug() final;
    bool configure() final;
    json getCfg() final { return settings.serialize(); }
    void setCfg(const json &j) final {
        if (j.count("SPU") && j["SPU"].is_object()) {
            settings.deserialize(j["SPU"]);
        } else {
            settings.reset();
        }
    }
    uint32_t getCurrentFrames() override { return m_audioOut.getCurrentFrames(); }
    void waitForGoal(uint32_t goal) override {
#ifdef __EMSCRIPTEN__
        // This is the emulator's real-time throttle: run ahead of the audio
        // device, then block until it has drained enough frames. It is called
        // from psxcounters, i.e. from inside Execute(), and blocking there is
        // exactly what a browser's main thread may not do - it is a futex wait,
        // and it is the reason this build used to need PROXY_TO_PTHREAD.
        //
        // In a browser the pacing belongs to the frame callback instead: the
        // main loop delivers ~60 calls a second and Execute() unwinds after one
        // emulated frame, so the rate is set by requestAnimationFrame rather
        // than by the audio clock. The caller advances m_audioFrames either way.
        //
        // Known imperfection rather than an oversight: that ties emulation speed
        // to the display refresh, so a PAL title or a 144 Hz monitor will not
        // pace correctly. Fixing that means driving from the audio callback,
        // which is a bigger change than moving the loop.
        (void)goal;
#else
        m_audioOut.waitForGoal(goal);
#endif
    }

  private:
    struct ADSRFlags {
        enum : uint16_t {
            AttackMode = 1 << 15,      // 15 0=Linear, 1=Exponential
            AttackShiftMask = 0x7c00,  // 14-10 0..1Fh = Fast..Slow
            AttackStepMask = 0x300,    // 9-8 0..3 = "+7,+6,+5,+4"
            DecayShiftMask = 0xf0,     // 7-4 0..0Fh = Fast..Slow
            SustainLevelMask = 0xf,    // 3-0 0..0Fh  ;Level=(N+1)*800h
            // Flags for the upper 16 bits of the register, shifted right by 16 bits.
            SustainMode = 1 << 15,       // 31 0=Linear, 1=Exponential
            SustainDirection = 1 << 14,  // 30  0=Increase, 1=Decrease (until Key OFF flag)
            SustainShiftMask = 0x1f00,   // 28-24 0..1Fh = Fast..Slow
            SustainStepMask = 0xc0,      // 23-22 0..3 = "+7,+6,+5,+4" or "-8,-7,-6,-5") (inc/dec)
            ReleaseMode = 1 << 5,        // 21 0=Linear, 1=Exponential
            ReleaseShiftMask = 0x1f      // 20-16 0..1Fh = Fast..Slow
        };
    };

    struct ControlFlags {
        enum : uint16_t {
            CDAudioEnable = 1 << 0,         // 0 0=Off, 1=On (for CD-DA and XA-ADPCM)
            ExternalAudioEnable = 1 << 1,   // 1 0=Off, 1=On
            CDReverbEnable = 1 << 2,        // 20=Off, 1=On (for CD-DA and XA-ADPCM)
            ExternalReverbEnable = 1 << 3,  // 3 0=Off, 1=On
            RAMTransferModeMask = 0x0030,   // 5-4 0=Stop, 1=ManualWrite, 2=DMAwrite, 3=DMAread
            IRQEnable = 1 << 6,             // 6 0=Disabled/Acknowledge, 1=Enabled; only when Bit15=1
            ReverbMasterEnable = 1 << 7,    // 7 0=Disabled, 1=Enabled
            NoiseStepMask = 0x0300,         // 9-8 0..03h = Step "4,5,6,7"
            NoiseShiftMask = 0x3c00,        // 13-10 0..0Fh = Low .. High Frequency
            Mute = 1 << 14,                 // 14 0=Mute, 1=Unmute
            Enable = 1 << 15                // 15 0=Off, 1=On
        };
    };

    struct StatusFlags {
        enum : uint16_t {
            SPUModeMask = 0x3f,        // 5-0 Current SPU Mode(same as SPUCNT.Bit5 - 0, but, applied a bit delayed)
            IRQFlag = 1 << 6,          // 6 IRQ9 Flag (0=No, 1=Interrupt Request)
            DMARWRequest = 1 << 7,     // 7 Data Transfer DMA Read/Write Request seems to be same as SPUCNT.Bit5
            DMAWriteRequest = 1 << 8,  // 8 Data Transfer DMA Write Request (0=No, 1=Yes)
            DMAReadRequest = 1 << 9,   // 9 Data Transfer DMA Read Request (0=No, 1=Yes)
            DMABusy = 1 << 10,         // 10 Data Transfer Busy Flag (0=Ready, 1=Busy)
            CBIndex = 1 << 11,         // 11 Writing to First/Second half of Capture Buffers (0=First, 1=Second)
            // 15-12 Unknown/Unused (seems to be usually zero)
        };
    };

    // Sound buffer sizes.
    // 400 ms complete sound buffer.
    static const size_t SOUNDSIZE = 70560;
    // 137 ms test buffer. If less than this is buffered, a new upload happens.
    static const size_t TESTSIZE = 24192;

    // Roughly 1 ms of data.
    static const size_t NSSIZE = 45;

    // SPU.
    void MainThread();
    // Reads the voice's two mode flags once and calls the matching
    // synthesizeVoice instantiation. This is the only place the runtime flags
    // are turned into compile-time axes.
    void synthesizeChannel(int ch, SPUCHAN *voice, int32_t &capVoice1Index, int32_t &capVoice3Index);
    template <FModRole Role, SampleSource Src>
    void synthesizeVoice(int ch, SPUCHAN *voice, int32_t &capVoice1Index, int32_t &capVoice3Index);
    // Decodes the next ADPCM block for a voice, together with the IRQ check and the
    // loop/stop flag handling that hang off the block boundary. Returns false when the
    // voice has run past the end of its sample and must stop being synthesized.
    bool decodeNextBlock(int ch, SPUCHAN *voice);
    void triggerIrq();
    void walkSilentVoice(int ch, SPUCHAN *voice);
    void captureVoiceSilence(int ch, int32_t &capVoice1Index, int32_t &capVoice3Index, int fromSample);
    void captureVoiceSample(int ch, int32_t &capVoice1Index, int32_t &capVoice3Index, int sample);
    void writeCaptureBufferCD(int numbSamples);
    void SetupStreams();
    void RemoveStreams();
    void SetupThread();
    void RemoveThread();
    void StartSound(SPUCHAN *voice);
    // Read-time reconstruction. A CPU read of ENVX or of SPUSTAT bit 11 asks what
    // the SPU is doing at the reader's own cycle, which is a time the SPU thread
    // has not reached: it runs asynchronously in NSSIZE batches paced by sink free
    // space. Answering from the live value hands back wherever that thread happened
    // to be. Both quantities are pure functions of elapsed samples, so evaluate them
    // against the reader's cycle instead and the thread's position stops being an
    // input. The mixer is untouched and keeps using its own live envelope.
    uint16_t reconstructEnvelope(int ch, uint64_t cycle);
    // Samples elapsed at a CPU cycle, on the hardware 768 cycles/sample ratio.
    uint64_t cycleToSample(uint64_t cycle) const;
    // Installs a new 16.16 pitch step, clamping zero, and notifies the interpolator.
    void setPitchStep(SPUCHAN *voice, int32_t step);
    void VoiceChangeFrequency(SPUCHAN *voice);
    void FModChangeFrequency(SPUCHAN *voice, int ns);

    // Registers.
    void SoundOn(int start, int end, uint16_t val);
    void SoundOff(int start, int end, uint16_t val);
    void FModOn(int start, int end, uint16_t val);
    void NoiseOn(int start, int end, uint16_t val);
    void SetPitch(int ch, uint16_t val);
    void ReverbOn(int start, int end, uint16_t val);

    // XA.
    void FeedXA(xa_decode_t *xap);

    int spuIsOpen;

    // PSX buffer and addresses.
    uint16_t regArea[10000];
    // Note that SPU ram is a uint16_t, so total size is 512KB.
    uint16_t spuMem[256 * 1024];
    // Byte-addressable view of spuMem; the base for every sound-RAM pointer and
    // for the offset math that stores/restores those pointers (e.g. savestates).
    uint8_t *spuRamBase;
    uint8_t *irqAddress = 0;
    uint8_t *spuBuffer;
    uint8_t *mixIrqAddress = 0;

    struct CaptureBuffer {
        static const int CB_SIZE = 1024 * 16;
        // These buffers have to be large enough to allow the CD-XA to stream in enough data.
        uint16_t CDCapLeft[CB_SIZE] = {0};
        uint16_t CDCapRight[CB_SIZE] = {0};

        int32_t startIndex = 0;
        int32_t endIndex = 0;
        int32_t currIndex = 0;
    };
    std::mutex cbMtx;

    // The temporary capture buffer for CD audio left/right.
    CaptureBuffer captureBuffer;
    // The capture buffer index for voice 1 and voice 3.
    int32_t capBufVoiceIndex = 0;

    // User settings.
    SettingsType settings;

    // Main info struct for each channel.

    SPUCHAN s_chan[MAXCHAN + 1];  // channel + 1 infos (1 is security for fmod handling)
    ReverbUnit m_reverb;          // global reverb unit: work state + Pete/Neill reverb DSP

    NoiseGenerator m_noise;  // global noise generator: LFSR + shift/step clock

    // ENDX (1F801D9C/1D9E): one bit per voice, set when the voice consumes an
    // ADPCM block carrying the end flag, cleared on key-on. Read-only.
    std::atomic<uint32_t> spuEndx = 0;

    // Storage for the PSX register values.
    // Both the register path and the mixer thread read-modify-write these, so every
    // update is an atomic RMW.
    std::atomic<uint16_t> spuCtrl = 0;
    std::atomic<uint16_t> spuStat = 0;
    uint16_t spuIrq = 0;
    // Address into SPU memory.
    uint32_t spuAddr = 0xffffffff;
    // Thread handling.
    std::atomic<int> endThread = 0;
    std::atomic<int> threadEnded = 0;
    int bSpuInit = 0;

    std::thread hMainThread;
    // Flags for faster testing of whether a new channel starts.
    uint32_t newChannelMask = 0;

    // Per-voice envelope reconstruction state, owned by the CPU thread. Not
    // serialized: it is rebuilt from the next key-on, and a savestate that resumed
    // without it would only lose the walk cache, not correctness.
    //
    // KEY-ON IS APPLIED ON THE SPU THREAD - SoundOn only sets Chan::New, and
    // AdsrEnvelope::keyOn() runs from StartSound inside synthesizeVoice, i.e.
    // wherever the batch loop next notices the flag, up to NSSIZE samples later.
    // So the cycle the envelope started at is not recoverable after the fact and
    // has to be stamped here, at the register write, where the CPU still owns it.
    struct EnvelopeCheckpoint {
        uint64_t keyOnCycle = 0;   // CPU cycle of the KEY ON write
        uint64_t keyOffCycle = 0;  // CPU cycle of the KEY OFF write, 0 while none
        bool keyedOn = false;
        // Walk cache. Reads arrive in increasing cycle order (the guest polls), so
        // stepping forward from the last answer makes each read O(1) amortised
        // instead of O(samples since key-on).
        uint64_t cachedSample = 0;
        int32_t cachedState = 0;
        int32_t cachedVol = 0;
        int32_t cachedFraction = 0;
        bool cachedOn = true;
    };
    EnvelopeCheckpoint m_envelopeCheckpoint[MAXCHAN];

    void (*cddavCallback)(uint16_t, uint16_t) = 0;

    // These were local variables before, but the timer procedure requires them to be global.

    int SSumR[NSSIZE];
    int SSumL[NSSIZE];
    int fmodInput[NSSIZE];
    // The shared noise level for each sample of the batch. The LFSR is one per SPU and
    // steps once per output sample, but voices are mixed channel-major, so MainThread
    // steps it NSSIZE times up front and noise voices read their sample's level here.
    int noiseLevel[NSSIZE];
    int iCycle = 0;
    int16_t *pS;

    // Secure start counter.
    int secureStart = 0;

    // XA
    xa_decode_t *xapGlobal = 0;

    int iLeftXAVol = 32767;
    int iRightXAVol = 32767;

    int gauss_ptr = 0;
    int gauss_window[8] = {0, 0, 0, 0, 0, 0, 0, 0};

    int &gvall0() { return gauss_window[gauss_ptr]; }
    int &gvall(int pos) { return gauss_window[(gauss_ptr + pos) & 3]; }
    int &gvalr0() { return gauss_window[4 + gauss_ptr]; }
    int &gvalr(int pos) { return gauss_window[4 + ((gauss_ptr + pos) & 3)]; }

    SDLAudio m_audioOut = {settings};
    xa_decode_t m_cdda;

    // Debug window.
    unsigned m_selectedChannel = 0;
    std::chrono::time_point<std::chrono::steady_clock> m_lastUpdated;
    enum { EMPTY = 0, DATA, NOISE, FMOD1, FMOD2, IRQ, MUTED } m_channelDebugTypes[MAXCHAN][DEBUG_SAMPLES];
    float m_channelDebugData[MAXCHAN][DEBUG_SAMPLES];
    char m_channelTag[MAXCHAN][CHANNEL_TAG] = {};
    unsigned m_currentDebugSample = 0;
};

}  // namespace SPU

}  // namespace PCSX
