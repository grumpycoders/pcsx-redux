/***************************************************************************
 *   Copyright (C) 2026 PCSX-Redux authors                                 *
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
#include <chrono>
#include <thread>

#include "spu/adsr.h"
#include "spu/externals.h"
#include "spu/interface.h"

namespace {
// The ADSR step returns the full 15-bit (0..0x7fff) envelope volume; the
// enveloped sample is `sample * envelope >> 15`, exactly as the hardware applies
// it (a signed arithmetic shift, SAR 15).
constexpr int kAdsrEnvelopeShift = 15;
// Per-voice volume is a 0..0x3fff level with 0x4000 as unity.
constexpr int kVoiceVolumeUnity = 0x4000;
// The capture area mirrors are 0x200 samples each; voice 1 lands at +0x400 and
// voice 3 at +0x600 (half-word sample indices into spuMem). The write pointer
// wraps every 0x200 samples and bit 11 of SPUSTAT tracks which half it is in.
constexpr int kCaptureRegionSamples = 0x200;
constexpr int kCaptureHalfMarker = kCaptureRegionSamples / 2;  // 0x100
constexpr int kCaptureVoice1Offset = 0x400;
constexpr int kCaptureVoice3Offset = 0x600;
// The post-ADSR sample is clamped to +/- this before it lands in the capture mirror.
constexpr int kCaptureSampleClamp = 0xffff;
// The final stereo mix is clamped to this symmetric signed-16-bit range.
constexpr int kMixSampleClamp = 32767;
}  // namespace

// Called by the main thread to set up a new sound on a channel.
inline void PCSX::SPU::impl::StartSound(SPUCHAN *pChannel) {
    pChannel->adsr.keyOn();
    m_reverb.start(pChannel, spuCtrl, settings.get<Reverb>());

    // Rewind the decode cursor to the sample start and clear the IIR history.
    pChannel->adpcm.keyOn();
    // EXPERIMENTAL key-on startup latency.
    pChannel->adpcm.setStartupDelay(settings.get<KeyOnDelay>().value);

    // Force a block decode on the first sample.
    pChannel->adpcm.emptyBuffer();

    // Initialize the channel flags.
    pChannel->data.get<Chan::New>().value = false;
    pChannel->data.get<Chan::Stop>().value = false;
    pChannel->data.get<Chan::On>().value = true;

    pChannel->interp.keyOn(settings.get<Interpolation>());
}

////////////////////////////////////////////////////////////////////////
// Helpers.
////////////////////////////////////////////////////////////////////////

// Both frequency paths end the same way: install the new 16.16 pitch step, and tell the
// interpolator the frequency moved so simple mode recomputes. The zero clamp matters - a
// zero step never advances the pitch counter, so the voice would sit on one sample forever.
inline void PCSX::SPU::impl::setPitchStep(SPUCHAN *pChannel, int32_t step) {
    pChannel->interp.setStep(step);
    pChannel->interp.onFrequencyChanged(settings.get<Interpolation>());
}

inline void PCSX::SPU::impl::VoiceChangeFrequency(SPUCHAN *pChannel) {
    auto &actFreq = pChannel->data.get<Chan::ActFreq>().value;
    // Take the new frequency and recompute the pitch step.
    pChannel->data.get<Chan::UsedFreq>().value = actFreq;
    setPitchStep(pChannel, pChannel->data.get<Chan::RawPitch>().value << 4);
}

////////////////////////////////////////////////////////////////////////

inline void PCSX::SPU::impl::FModChangeFrequency(SPUCHAN *pChannel, int ns) {
    int NP = pChannel->data.get<Chan::RawPitch>().value;

    NP = ((32768L + iFMod[ns]) * NP) / 32768L;
    NP = std::clamp(NP, 0x1, 0x3fff);
    // Calculate the frequency.
    NP = (44100L * NP) / (4096L);

    pChannel->data.get<Chan::ActFreq>().value = NP;
    pChannel->data.get<Chan::UsedFreq>().value = NP;
    setPitchStep(pChannel, ((NP / 10) << 16) / 4410);

    iFMod[ns] = 0;
}

////////////////////////////////////////////////////////////////////////
// Voice 1 and voice 3 mirror their post-ADSR / pre-volume output into the
// capture area (voice 1 at +0x400, voice 3 at +0x600, half-word sample indices
// into spuMem). These helpers fold the per-voice dispatch and the shared write
// cursor bookkeeping; ch selects the voice (1 or 3), other channels and the
// capture-disabled case are no-ops. The cursors are per-batch state shared
// across channels, so they are passed by reference.
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::captureVoiceSilence(int ch, int32_t &capVoice1Index, int32_t &capVoice3Index, int fromSample) {
    if (pMixIrq && ch == 1) {
        std::unique_lock<std::mutex> lock(cbMtx);
        for (int c = fromSample; c < NSSIZE; c++) {
            spuMem[capVoice1Index + kCaptureVoice1Offset] = 0;
            capVoice1Index = (capVoice1Index + 1) % kCaptureRegionSamples;
        }
    } else if (pMixIrq && ch == 3) {
        std::unique_lock<std::mutex> lock(cbMtx);
        for (int c = fromSample; c < NSSIZE; c++) {
            spuMem[capVoice3Index + kCaptureVoice3Offset] = 0;
            capVoice3Index = (capVoice3Index + 1) % kCaptureRegionSamples;
        }
    }
}

void PCSX::SPU::impl::captureVoiceSample(int ch, int32_t &capVoice1Index, int32_t &capVoice3Index, int sample) {
    if (pMixIrq && ch == 1) {
        std::unique_lock<std::mutex> lock(cbMtx);
        spuMem[capVoice1Index + kCaptureVoice1Offset] = sample;
        capVoice1Index = (capVoice1Index + 1) % kCaptureRegionSamples;
    } else if (pMixIrq && ch == 3) {
        std::unique_lock<std::mutex> lock(cbMtx);
        spuMem[capVoice3Index + kCaptureVoice3Offset] = sample;
        capVoice3Index = (capVoice3Index + 1) % kCaptureRegionSamples;
    }
}

////////////////////////////////////////////////////////////////////////
// Synthesize one channel's contribution to this NSSIZE-sample batch: start a
// pending voice, advance and decode its ADPCM stream, interpolate, apply the
// ADSR envelope, mirror voices 1 and 3 into the capture buffer, and either
// accumulate into the stereo mix or, for an FMod source, into iFMod. Returns
// early when the voice is idle or stops mid-batch. The two capture write
// cursors are shared across the batch, so they are passed by reference.
//
// The body is templated on the two mode axes declared in interface.h and
// synthesizeChannel below is the dispatcher that resolves them. Both live in
// this translation unit and MainThread only ever calls the dispatcher, so no
// explicit instantiations are needed.
////////////////////////////////////////////////////////////////////////

// Everything that happens at an ADPCM block boundary: decode the next 16-byte block into
// the voice's 28-sample buffer, then the two things that hang off that boundary - the IRQ
// address check, and the loop/stop flag that decides where the cursor goes next. Split out
// of synthesizeChannel because it is the only part of the pitch loop that is not per-sample.
// Returns false when the cursor is already parked at kStopped, i.e. the voice ended on a
// previous pass and the caller must stop synthesizing it.
bool PCSX::SPU::impl::decodeNextBlock(int ch, SPUCHAN *pChannel) {
    // Current decode position.
    uint8_t *cursor = pChannel->adpcm.curr();
    if (cursor == AdpcmDecoder::kStopped) return false;

    auto &irqDone = pChannel->data.get<Chan::IrqDone>().value;
    auto &ignoreLoop = pChannel->data.get<Chan::IgnoreLoop>().value;


    // The decoder owns the predictor/shift parse and the s_1/s_2 IIR history; it hands back
    // the address just past the block and the flag byte.
    const auto decoded = pChannel->adpcm.decodeBlock(cursor);
    cursor = decoded.blockEnd;
    const int blockFlags = decoded.flags;

    bool irqWait = false;
    if (spuCtrl & ControlFlags::IRQEnable) {
        const bool addrReached = pSpuIrq > cursor - 16 && pSpuIrq <= cursor;
        // Special case: IRQ on the looping address, when the stop/loop flag is set.
        const bool loopAddrReached = (blockFlags & 1) && pSpuIrq > pChannel->adpcm.loop() - 16 &&
                                     pSpuIrq <= pChannel->adpcm.loop();
        if (addrReached || loopAddrReached) {
            // Debug flag.
            irqDone = 1;
            // Notify the main emulator.
            scheduleInterrupt();
            // Option: wait after the IRQ for the main emulator.
            if (settings.get<SPUIRQWait>()) {
                iSpuAsyncWait = 1;
                irqWait = true;
            }
        }
    }

    // Latch the loop address.
    if ((blockFlags & 4) && !ignoreLoop) pChannel->adpcm.setLoop(cursor - 16);

    // Stop/loop flag: this is the last block of the sample.
    if (blockFlags & 1) {
        // ENDX latches on the end flag.
        spuEndx |= 1u << ch;

        // Only loop when the flag byte is exactly 3 (loop-end + repeat) and a loop address was
        // latched. Requiring exactly 3 avoids loop hang-ups (e.g. DQ4), and the null-loop guard
        // avoids following an address that was never set.
        cursor = (blockFlags != 3 || pChannel->adpcm.loop() == nullptr) ? AdpcmDecoder::kStopped
                                                                       : pChannel->adpcm.loop();
    }

    // Store the cursor for the next cycle.
    pChannel->adpcm.setCurr(cursor);

    // Special wait for the "SPU IRQ - wait for CPU action" option.
    if (irqWait) {
        using namespace std::chrono_literals;
        const auto watchUntil = std::chrono::steady_clock::now() + 2500ms;
        while (iSpuAsyncWait && !bEndThread && std::chrono::steady_clock::now() < watchUntil) {
            std::this_thread::sleep_for(1ms);
        }
    }

    return true;
}

template <PCSX::SPU::FModRole Role, PCSX::SPU::SampleSource Src>
void PCSX::SPU::impl::synthesizeVoice(int ch, SPUCHAN *pChannel, int32_t &capVoice1Index, int32_t &capVoice3Index) {
    // Being the frequency-modulator SOURCE decides three things at once: the
    // voice bypasses the resampler, it skips the volume and reverb stage, and
    // its output goes to iFMod rather than the stereo mix.
    constexpr bool kIsFModSource = Role == FModRole::Source;

    // The mixing state still lives in the savestate protobuf, so bind it once here
    // instead of spelling the accessor out at every use. These are all references:
    // the register path writes several of them from another thread while we mix, so
    // copying would silently change when a mid-batch write takes effect. FMod and
    // Noise are no longer among them; they are the template arguments now.
    auto &isNew = pChannel->data.get<Chan::New>().value;
    auto &on = pChannel->data.get<Chan::On>().value;
    auto &stop = pChannel->data.get<Chan::Stop>().value;
    auto &sval = pChannel->data.get<Chan::sval>().value;
    auto &mute = pChannel->data.get<Chan::Mute>().value;
    auto &solo = pChannel->data.get<Chan::Solo>().value;
    auto &rvbActive = pChannel->data.get<Chan::RVBActive>().value;
    auto &actFreq = pChannel->data.get<Chan::ActFreq>().value;
    auto &usedFreq = pChannel->data.get<Chan::UsedFreq>().value;

    if (isNew) {
        // Start the new sound.
        StartSound(pChannel);
        // Clear the new-channel bit.
        dwNewChannel &= ~(1 << ch);
    }

    if (!on) {
        // Although the voice is silent, its capture mirror keeps filling.
        captureVoiceSilence(ch, capVoice1Index, capVoice3Index, 0);
        // The channel is not playing.
        return;
    }

    // A new PSX frequency was programmed.
    if (actFreq != usedFreq) VoiceChangeFrequency(pChannel);

    // Collect 1 ms of this channel's audio.
    for (int ns = 0; ns < NSSIZE; ns++)
    {
        int rawSample;
        m_noise.step();

        // EXPERIMENTAL key-on startup latency: emit silence and freeze decode/pitch/ADSR
        // for the first few samples after KEY_ON, matching the hardware capture's leading silence.
        if (pChannel->adpcm.startupDelayActive()) {
            pChannel->adpcm.tickStartupDelay();
            sval = 0;
            captureVoiceSample(ch, capVoice1Index, capVoice3Index, 0);
            continue;
        }

        if constexpr (Role == FModRole::Target) {
            // Modulated by the voice below us.
            if (iFMod[ns]) FModChangeFrequency(pChannel, ns);
        }

        // A noise voice still walks its ADPCM stream. The decoded samples are
        // thrown away below, but the cursor advance, the IRQ address check and
        // the ENDX latch all hang off the block boundary.
        while (pChannel->interp.owesSample()) {
            if (pChannel->adpcm.bufferExhausted() && !decodeNextBlock(ch, pChannel)) {
                // The voice ran off the end of its sample on a previous pass. It is silent
                // now, but its capture mirror still fills: ns samples are already done this
                // batch, so write silence for the remaining NSSIZE-ns.
                on = false;
                pChannel->adsr.ex().get<exVolume>().value = 0;
                pChannel->adsr.ex().get<exEnvelopeVol>().value = 0;
                captureVoiceSilence(ch, capVoice1Index, capVoice3Index, ns);
                // Done with this channel.
                return;
            }

            rawSample = pChannel->adpcm.takeSample();

            // Store the value for interpolation.
            pChannel->interp.storeVal(rawSample, settings.get<Interpolation>(), kIsFModSource,
                                      (spuCtrl & ControlFlags::Mute) != 0);

            pChannel->interp.tookSample();
        }

        if constexpr (Src == SampleSource::Noise) {
            // Get the noise value.
            rawSample = m_noise.getVal();
            pChannel->interp.parkExternalSample(rawSample, settings.get<Interpolation>());
        } else {
            rawSample = pChannel->interp.getVal(settings.get<Interpolation>(), kIsFModSource);
        }

        // Apply the ADSR envelope (hardware: sample*env>>15).
        int32_t mixedSample = (pChannel->adsr.step(stop, on) * rawSample) >> kAdsrEnvelopeShift;
        sval = mixedSample;

        // The capture mirror holds the voice 1/3 sample after ADSR but before volume.
        mixedSample = std::clamp(mixedSample, -kCaptureSampleClamp, kCaptureSampleClamp);
        captureVoiceSample(ch, capVoice1Index, capVoice3Index, mixedSample);

        if constexpr (Role == FModRole::Source) {
            // Hand the sample to the voice above us to modulate with.
            iFMod[ns] = sval;
        } else {
            // Left/right sound volume (PSX volume goes from 0 to 0x3fff).
            if (mute && !solo) {
                // Debug mute.
                sval = 0;
            } else {
                SSumL[ns] += (sval * pChannel->volume.left()) / kVoiceVolumeUnity;
                SSumR[ns] += (sval * pChannel->volume.right()) / kVoiceVolumeUnity;
            }

            // Store for reverb.
            if (rvbActive) m_reverb.store(pChannel, ns, settings.get<Reverb>());
        }

        pChannel->interp.advance();
    }
}

// Read the voice's two mode flags and pick the matching instantiation. This is
// the only place the runtime flags become compile-time axes; everything below it
// sees them as template arguments. Anything other than 1 or 2 in the FMod field
// means the voice is not part of a modulation pair, which is exactly what the
// per-sample equality tests this replaced did with it.
void PCSX::SPU::impl::synthesizeChannel(int ch, SPUCHAN *pChannel, int32_t &capVoice1Index, int32_t &capVoice3Index) {
    const bool noise = pChannel->data.get<Chan::Noise>().value;

    switch (pChannel->data.get<Chan::FMod>().value) {
        case static_cast<int>(FModRole::Target):
            if (noise) {
                synthesizeVoice<FModRole::Target, SampleSource::Noise>(ch, pChannel, capVoice1Index, capVoice3Index);
            } else {
                synthesizeVoice<FModRole::Target, SampleSource::Adpcm>(ch, pChannel, capVoice1Index, capVoice3Index);
            }
            break;
        case static_cast<int>(FModRole::Source):
            if (noise) {
                synthesizeVoice<FModRole::Source, SampleSource::Noise>(ch, pChannel, capVoice1Index, capVoice3Index);
            } else {
                synthesizeVoice<FModRole::Source, SampleSource::Adpcm>(ch, pChannel, capVoice1Index, capVoice3Index);
            }
            break;
        default:
            if (noise) {
                synthesizeVoice<FModRole::None, SampleSource::Noise>(ch, pChannel, capVoice1Index, capVoice3Index);
            } else {
                synthesizeVoice<FModRole::None, SampleSource::Adpcm>(ch, pChannel, capVoice1Index, capVoice3Index);
            }
            break;
    }
}

////////////////////////////////////////////////////////////////////////
// Main SPU job handler. This is where the sound processing happens.
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::MainThread() {
    int ns, ch;
    int32_t tmpCapVoice1Index = 0;
    int32_t tmpCapVoice3Index = 0;

    // Run until we are shutting down.
    while (!bEndThread)
    {
        int volumeDivisor = 4 - settings.get<Volume>();
        //--------------------------------------------------//
        // At the start of each pass, check whether there is enough free space in the audio output
        // buffer to fill in new data, or whether there is a new channel to start. If neither, wait
        // until free space is available or a new channel gets started.

        // Should a new channel start immediately, that is, is at least one bit in 0..MAXCHANNEL
        // set?
        if (dwNewChannel)
        {
            // Set iSecureStart.
            iSecureStart++;
            if (iSecureStart > 5)
                // If it has been set 5 times in a row, meaning a new sample has been started on 5
                // tries in a row, reset it to give the sound update a chance.
                iSecureStart = 0;
        } else
            // 0: no new channel should start.
            iSecureStart = 0;

        // No new start, no thread end, and still enough data in the sound buffer?
        while (!iSecureStart && !bEndThread &&
               (m_audioOut.getBytesBuffered() > TESTSIZE))
        {
            // Reset iSecureStart.
            iSecureStart = 0;

            using namespace std::chrono_literals;
            std::this_thread::sleep_for(5ms);

            // If a new channel kicks in, or the sound buffer runs low, leave the loop.
            if (dwNewChannel)
                iSecureStart =
                    1;
        }

        tmpCapVoice1Index = capBufVoiceIndex;
        tmpCapVoice3Index = capBufVoiceIndex;

        // Collect 1 ms of sound from every channel into the mix accumulators.
        for (ch = 0; ch < MAXCHAN; ch++) {
            synthesizeChannel(ch, &s_chan[ch], tmpCapVoice1Index, tmpCapVoice3Index);
        }

        // Write from our temporary capture buffer to the actual SPU RAM.
        writeCaptureBufferCD(NSSIZE);

        // Advance the persistent capture write pointer by one batch and reflect
        // which half of the 0x200-sample capture buffer it now points at in
        // SPUSTAT bit 11 (0=first half 0x000-0x0ff, 1=second half 0x100-0x1ff).
        // Hardware toggles this bit as the 44.1kHz capture pointer crosses the
        // half boundary; guests sync capture reads on its edge.
        capBufVoiceIndex = (capBufVoiceIndex + NSSIZE) % kCaptureRegionSamples;
        if (capBufVoiceIndex & kCaptureHalfMarker)
            spuStat |= StatusFlags::CBIndex;
        else
            spuStat &= ~StatusFlags::CBIndex;

        //---------------------------------------------------//
        // Another 1 ms of sound data is now available.
        //---------------------------------------------------//

        ///////////////////////////////////////////////////////
        // Mix all channels, including reverb, into one buffer.

        for (ns = 0; ns < NSSIZE; ns++) {
            SSumL[ns] += m_reverb.mixLeft(ns, spuMem, spuCtrl, settings.get<Reverb>());
            *pS++ = std::clamp(SSumL[ns] / volumeDivisor, -kMixSampleClamp, kMixSampleClamp);
            SSumL[ns] = 0;

            SSumR[ns] += m_reverb.mixRight(settings.get<Reverb>());
            *pS++ = std::clamp(SSumR[ns] / volumeDivisor, -kMixSampleClamp, kMixSampleClamp);
            SSumR[ns] = 0;
        }

        //////////////////////////////////////////////////////
        // Special IRQ handling in the decode buffers (0x0000-0x1000).
        //
        // The decode buffers are located in SPU memory as follows, with decoded data being 16 bits
        // per sample:
        // 0x0000-0x03ff  CD audio left
        // 0x0400-0x07ff  CD audio right
        // 0x0800-0x0bff  Voice 1
        // 0x0c00-0x0fff  Voice 3
        //
        // The assumption is that even if voices 1 and 3 are off, or no CD audio is playing, the
        // internal play positions keep moving and wrap after 0x400 bytes. Therefore a single
        // pointer from spuMem+0 to spuMem+0x3ff suffices, increased by 2 bytes on each sample. If
        // that pointer, or one of the 0x400 offsets of it, hits the SPU IRQ address, an IRQ is
        // generated. The "wait for CPU" option is hard to implement here in some of Peops' timer
        // modes, so it is ignored in this path. Note also that the channel 0-3 IRQ debug display
        // is reused for these IRQs, as that is the simplest way to display them in debug mode.

        // pMixIrq is only set if the config option is active.
        if (pMixIrq)
        {
            for (ns = 0; ns < NSSIZE; ns++) {
                if ((spuCtrl & ControlFlags::IRQEnable) && pSpuIrq && pSpuIrq < spuRamBase + 0x1000) {
                    for (ch = 0; ch < 4; ch++) {
                        if (pSpuIrq >= pMixIrq + (ch * 0x400) && pSpuIrq < pMixIrq + (ch * 0x400) + 2) {
                            scheduleInterrupt();
                            s_chan[ch].data.get<PCSX::SPU::Chan::IrqDone>().value = 1;
                        }
                    }
                }
                pMixIrq += 2;
                if (pMixIrq > spuRamBase + 0x3ff) pMixIrq = spuRamBase;
            }
        }

        m_reverb.init(settings.get<Reverb>(), NSSIZE);

        //////////////////////////////////////////////////////
        // Feed the sound. The target update rate is around 1/60 sec (16.666 ms).

        if (iCycle++ > 16) {
            bool done = false;
            while (!done) {
                done =
                    m_audioOut.feedStreamData(reinterpret_cast<MiniAudio::Frame *>(pSpuBuffer),
                                              (((uint8_t *)pS) - ((uint8_t *)pSpuBuffer)) / sizeof(MiniAudio::Frame));
                if (bEndThread) {
                    bThreadEnded = 1;
                    return;
                }
            }
            pS = (int16_t *)pSpuBuffer;
            iCycle = 0;
        }
    }

    bThreadEnded = 1;
}

void PCSX::SPU::impl::writeCaptureBufferCD(int numbSamples) {
    if (pMixIrq) {
        std::unique_lock<std::mutex> lock(cbMtx);
        for (int n = 0; n < numbSamples; n++) {
            if (captureBuffer.startIndex == captureBuffer.endIndex) {
                // If there are no samples left in the temp buffer,
                // we still HAVE to keep writing to the capture buffer.
                spuMem[captureBuffer.currIndex] = 0;
                spuMem[captureBuffer.currIndex + 0x200] = 0;
            } else {
                spuMem[captureBuffer.currIndex] = captureBuffer.CDCapLeft[captureBuffer.startIndex];
                spuMem[captureBuffer.currIndex + 0x200] = captureBuffer.CDCapRight[captureBuffer.startIndex];
                captureBuffer.startIndex = (captureBuffer.startIndex + 1) % CaptureBuffer::CB_SIZE;
            }
            captureBuffer.currIndex = (captureBuffer.currIndex + 1) % 0x200;
        }
        // capBufVoiceIndex, tmpCapVoice1Index, tmpCapVoice3Index and captureBuffer.currIndex are
        // expected to track each other and end up equal.
    }
}

////////////////////////////////////////////////////////////////////////

// Called once every 'cycle' cycles.
void PCSX::SPU::impl::async(uint32_t cycle) {
    if (iSpuAsyncWait) {
        iSpuAsyncWait++;
        if (iSpuAsyncWait <= 64) return;
        iSpuAsyncWait = 0;
    }
}

////////////////////////////////////////////////////////////////////////
// XA audio.
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::playADPCMchannel(xa_decode_t *xap) {
    // Nothing to do when XA streaming is disabled.
    if (!settings.get<Streaming>()) return;
    if (!xap) return;
    // Nothing to do without an XA frequency.
    if (!xap->freq) return;

    // Call the main XA feeder.
    FeedXA(xap);
}

////////////////////////////////////////////////////////////////////////
// Init and exit.
////////////////////////////////////////////////////////////////////////

// Called first by the main emulator.
long PCSX::SPU::impl::init(void) {
    spuRamBase = (uint8_t *)spuMem;

    wipeChannels();
    return 0;
}

void PCSX::SPU::impl::wipeChannels() {
    for (unsigned i = 0; i < MAXCHAN; i++) {
        s_chan[i].adsr.reset();
        s_chan[i].adpcm.reset();
        s_chan[i].volume.reset();
        s_chan[i].data.reset();
    }
    m_reverb.reset();
}

// Initialization of certain buffers and of the mixing thread.
void PCSX::SPU::impl::SetupThread() {
    // Initialize the mixing buffers.
    memset(SSumR, 0, NSSIZE * sizeof(int));
    memset(SSumL, 0, NSSIZE * sizeof(int));
    memset(iFMod, 0, NSSIZE * sizeof(int));

    // Set up the sound buffer pointer.
    pS = (int16_t *)pSpuBuffer;

    // Initialize the thread variables.
    bEndThread = 0;
    bThreadEnded = 0;
    // Flag that initialization is complete.
    bSpuInit = 1;

    hMainThread = std::thread([this]() { MainThread(); });
}

// Kill the mixing thread.
void PCSX::SPU::impl::RemoveThread() {
    // Raise the flag to end the thread.
    bEndThread = 1;

    using namespace std::chrono_literals;
    // Wait until the thread has ended.
    while (!bThreadEnded) {
        std::this_thread::sleep_for(5ms);
    }
    std::this_thread::sleep_for(5ms);

    hMainThread.join();

    // No more SPU is running.
    bThreadEnded = 0;
    bSpuInit = 0;
}

// Initialize most of the SPU buffers.
void PCSX::SPU::impl::SetupStreams() {
    int i;

    // Allocate the mixing buffer.
    pSpuBuffer = (uint8_t *)malloc(32768);

    if (settings.get<Reverb>() == 1)
        i = 88200 * 2;
    else
        i = NSSIZE * 2;

    // Allocate the reverb buffer.
    m_reverb.sRVBStart = (int *)malloc(i * 4);
    memset(m_reverb.sRVBStart, 0, i * 4);
    m_reverb.sRVBEnd = m_reverb.sRVBStart + i;
    m_reverb.sRVBPlay = m_reverb.sRVBStart;

    // Loop over the sound channels.
    for (i = 0; i < MAXCHAN; i++)
    {
        // No per-channel mutex synchronization is used here: it is not needed, and would only slow
        // things down.
        // Initialize the sustain level.
        s_chan[i].adsr.ex().get<exSustainLevel>().value = 0xf << 27;
        s_chan[i].data.get<PCSX::SPU::Chan::Mute>().value = false;
        s_chan[i].data.get<PCSX::SPU::Chan::Solo>().value = false;
        s_chan[i].data.get<PCSX::SPU::Chan::IrqDone>().value = 0;
        s_chan[i].adpcm.setLoop(spuRamBase);
        s_chan[i].adpcm.setStart(spuRamBase);
        s_chan[i].adpcm.setCurr(spuRamBase);
    }
}

// Free most of the SPU buffers.
void PCSX::SPU::impl::RemoveStreams(void) {
    // Free the mixing buffer.
    free(pSpuBuffer);
    pSpuBuffer = NULL;
    // Free the reverb buffer.
    free(m_reverb.sRVBStart);
    m_reverb.sRVBStart = 0;
}

// Called by the main emulator after init.
bool PCSX::SPU::impl::open() {
    // Guard against a redundant open.
    if (bSPUIsOpen) return true;

    m_reverb.iReverbOff = -1;
    spuIrq = 0;
    spuAddr = 0xffffffff;
    bEndThread = 0;
    bThreadEnded = 0;
    spuRamBase = (uint8_t *)spuMem;
    pMixIrq = 0;
    wipeChannels();
    pSpuIrq = 0;

    // Prepare streaming.
    SetupStreams();

    // Start the thread that feeds data.
    SetupThread();

    bSPUIsOpen = 1;

    m_lastUpdated = std::chrono::steady_clock::now();

    resetCaptureBuffer();

    return true;
}

// Called before shutdown.
long PCSX::SPU::impl::close(void) {
    // Guard against closing when not open.
    if (!bSPUIsOpen) return 0;

    bSPUIsOpen = 0;

    // No more feeding.
    RemoveThread();
    // No more streaming.
    RemoveStreams();

    return 0;
}

// Called by the main emulator on final exit.
long PCSX::SPU::impl::shutdown(void) { return 0; }

////////////////////////////////////////////////////////////////////////
// Callback setup. Called once, and passes a callback that is invoked on an
// SPU IRQ or a CDDA volume change.
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::registerCDDAVolume(void (*CDDAVcallback)(uint16_t, uint16_t)) { cddavCallback = CDDAVcallback; }

////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::playCDDAchannel(int16_t *data, int size) {
    m_cdda.freq = 44100;
    m_cdda.nsamples = size / 4;
    m_cdda.stereo = 1;
    m_cdda.nbits = 16;
    memcpy(m_cdda.pcm, data, size);
    FeedXA(&m_cdda);
}

void PCSX::SPU::impl::setLua(Lua L) {
    L.getfieldtable("PCSX", LUA_GLOBALSINDEX);
    L.getfieldtable("settings");
    L.push("spu");
    settings.pushValue(L);
    L.settable();
    L.pop();
    L.pop();
}
