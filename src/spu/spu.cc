/***************************************************************************
                            spu.c  -  description
                             -------------------
    begin                : Wed May 15 2002
    copyright            : (C) 2002 by Pete Bernert
    email                : BlackDove@addcom.de
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version. See also the license.txt file for *
 *   additional informations.                                              *
 *                                                                         *
 ***************************************************************************/

#include <algorithm>
#include <chrono>
#include <thread>

#include "spu/adsr.h"
#include "spu/externals.h"
#include "spu/interface.h"

namespace {
// One 16-byte ADPCM block decodes to 28 PCM samples; SBPos walks 0..27 and a
// value of 28 means "the decode buffer is exhausted, fetch the next block".
constexpr int kSamplesPerAdpcmBlock = 28;
// The voice pitch counter (Chan::spos) is 16.16 fixed point: 0x10000 == one
// whole source sample consumed.
constexpr int32_t kPitchCounterUnity = 0x10000;
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

////////////////////////////////////////////////////////////////////////
// START SOUND... called by main thread to setup a new sound on a channel
////////////////////////////////////////////////////////////////////////

inline void PCSX::SPU::impl::StartSound(SPUCHAN *pChannel) {
    auto &SB = pChannel->data.get<PCSX::SPU::Chan::SB>().value;
    pChannel->adsr.keyOn();
    m_reverb.start(pChannel, spuCtrl, settings.get<Reverb>());

    pChannel->adpcm.keyOn();  // rewind decode cursor to sample start, clear IIR history
    pChannel->adpcm.setStartupDelay(settings.get<KeyOnDelay>().value);  // EXPERIMENTAL keyon startup latency

    pChannel->data.get<PCSX::SPU::Chan::SBPos>().value = kSamplesPerAdpcmBlock;  // force a block decode on first sample

    pChannel->data.get<PCSX::SPU::Chan::New>().value = false;  // init channel flags
    pChannel->data.get<PCSX::SPU::Chan::Stop>().value = false;
    pChannel->data.get<PCSX::SPU::Chan::On>().value = true;

    pChannel->interp.keyOn(SB.data(), &pChannel->data.get<PCSX::SPU::Chan::spos>().value,
                           settings.get<Interpolation>());
}

////////////////////////////////////////////////////////////////////////
// ALL KIND OF HELPERS
////////////////////////////////////////////////////////////////////////

inline void PCSX::SPU::impl::VoiceChangeFrequency(SPUCHAN *pChannel) {
    auto &SB = pChannel->data.get<PCSX::SPU::Chan::SB>().value;
    pChannel->data.get<PCSX::SPU::Chan::UsedFreq>().value =
        pChannel->data.get<PCSX::SPU::Chan::ActFreq>().value;  // -> take it and calc steps
    pChannel->data.get<PCSX::SPU::Chan::sinc>().value = pChannel->data.get<PCSX::SPU::Chan::RawPitch>().value << 4;
    if (!pChannel->data.get<PCSX::SPU::Chan::sinc>().value) pChannel->data.get<PCSX::SPU::Chan::sinc>().value = 1;
    // -> freq change in simple interpolation mode: set the recompute flag
    pChannel->interp.onFrequencyChanged(SB.data(), settings.get<Interpolation>());
}

////////////////////////////////////////////////////////////////////////

inline void PCSX::SPU::impl::FModChangeFrequency(SPUCHAN *pChannel, int ns) {
    auto &SB = pChannel->data.get<PCSX::SPU::Chan::SB>().value;
    int NP = pChannel->data.get<PCSX::SPU::Chan::RawPitch>().value;

    NP = ((32768L + iFMod[ns]) * NP) / 32768L;

    if (NP > 0x3fff) NP = 0x3fff;
    if (NP < 0x1) NP = 0x1;

    NP = (44100L * NP) / (4096L);  // calc frequency

    pChannel->data.get<PCSX::SPU::Chan::ActFreq>().value = NP;
    pChannel->data.get<PCSX::SPU::Chan::UsedFreq>().value = NP;
    pChannel->data.get<PCSX::SPU::Chan::sinc>().value = (((NP / 10) << 16) / 4410);
    if (!pChannel->data.get<PCSX::SPU::Chan::sinc>().value) pChannel->data.get<PCSX::SPU::Chan::sinc>().value = 1;
    // freq change in simple interpolation mode: set the recompute flag
    pChannel->interp.onFrequencyChanged(SB.data(), settings.get<Interpolation>());

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
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::synthesizeChannel(int ch, SPUCHAN *pChannel, int32_t &capVoice1Index, int32_t &capVoice3Index) {
    if (pChannel->data.get<PCSX::SPU::Chan::New>().value) {
        StartSound(pChannel);        // start new sound
        dwNewChannel &= ~(1 << ch);  // clear new channel bit
    }

    if (!pChannel->data.get<PCSX::SPU::Chan::On>().value) {
        // Although the voice is silent, its capture mirror keeps filling.
        captureVoiceSilence(ch, capVoice1Index, capVoice3Index, 0);
        return;  // channel not playing
    }

    if (pChannel->data.get<PCSX::SPU::Chan::ActFreq>().value !=
        pChannel->data.get<PCSX::SPU::Chan::UsedFreq>().value)  // new psx frequency?
        VoiceChangeFrequency(pChannel);

    int bIRQReturn = 0;
    for (int ns = 0; ns < NSSIZE; ns++)  // collect 1 ms of this channel's audio
    {
        int rawSample;
        m_noise.step();

        // EXPERIMENTAL key-on startup latency: emit silence and freeze decode/pitch/ADSR
        // for the first few samples after KEY_ON, matching the hardware capture's leading silence.
        if (pChannel->adpcm.startupDelayActive()) {
            pChannel->adpcm.tickStartupDelay();
            pChannel->data.get<PCSX::SPU::Chan::sval>().value = 0;
            captureVoiceSample(ch, capVoice1Index, capVoice3Index, 0);
            continue;
        }

        if (pChannel->data.get<PCSX::SPU::Chan::FMod>().value == 1 && iFMod[ns])  // fmod freq channel
            FModChangeFrequency(pChannel, ns);

        while (pChannel->data.get<PCSX::SPU::Chan::spos>().value >= kPitchCounterUnity) {
            if (pChannel->data.get<PCSX::SPU::Chan::SBPos>().value == kSamplesPerAdpcmBlock) {
                uint8_t *cursor = pChannel->adpcm.curr();  // current decode position

                if (cursor == AdpcmDecoder::kStopped)  // voice stopped on a previous pass?
                {
                    pChannel->data.get<PCSX::SPU::Chan::On>().value = false;  // turn everything off
                    pChannel->adsr.ex().get<exVolume>().value = 0;
                    pChannel->adsr.ex().get<exEnvelopeVol>().value = 0;
                    // The voice is silent now, but its capture mirror still fills: ns samples are
                    // already done this batch, so write silence for the remaining NSSIZE-ns.
                    captureVoiceSilence(ch, capVoice1Index, capVoice3Index, ns);
                    return;  // done with this channel
                }

                pChannel->data.get<PCSX::SPU::Chan::SBPos>().value = 0;

                // Decode the 16-byte ADPCM block at the cursor into the 28-sample buffer. The decoder
                // owns the predictor/shift parse and the s_1/s_2 IIR history; it hands back the address
                // just past the block and the flag byte.
                auto decoded =
                    pChannel->adpcm.decodeBlock(cursor, pChannel->data.get<PCSX::SPU::Chan::SB>().value.data());
                cursor = decoded.blockEnd;
                int blockFlags = decoded.flags;

                //////////////////////////////////////////// irq check

                if ((spuCtrl & ControlFlags::IRQEnable))  // some callback and irq active?
                {
                    if ((pSpuIrq > cursor - 16 &&  // irq address reached?
                         pSpuIrq <= cursor) ||
                        ((blockFlags & 1) &&  // special: irq on looping addr, when stop/loop flag is set
                         (pSpuIrq > pChannel->adpcm.loop() - 16 && pSpuIrq <= pChannel->adpcm.loop()))) {
                        pChannel->data.get<PCSX::SPU::Chan::IrqDone>().value = 1;  // -> debug flag
                        scheduleInterrupt();                                       // -> call main emu

                        if (settings.get<SPUIRQWait>())  // -> option: wait after irq for main emu
                        {
                            iSpuAsyncWait = 1;
                            bIRQReturn = 1;
                        }
                    }
                }

                //////////////////////////////////////////// flag handler

                if ((blockFlags & 4) && (!pChannel->data.get<PCSX::SPU::Chan::IgnoreLoop>().value))
                    pChannel->adpcm.setLoop(cursor - 16);  // latch the loop (repeat) address

                if (blockFlags & 1)  // stop/loop flag: this is the last block of the sample
                {
                    // Only loop when the flag byte is exactly 3 (loop-end + repeat) and a loop
                    // address was latched. Requiring exactly 3 avoids loop hang-ups (e.g. DQ4),
                    // and the null-loop guard avoids following an address that was never set.
                    if (blockFlags != 3 || pChannel->adpcm.loop() == nullptr) {
                        cursor = AdpcmDecoder::kStopped;
                    } else {
                        cursor = pChannel->adpcm.loop();
                    }
                }

                pChannel->adpcm.setCurr(cursor);  // store cursor for next cycle

                ////////////////////////////////////////////

                if (bIRQReturn)  // special return for "spu irq - wait for cpu action"
                {
                    using namespace std::chrono_literals;
                    bIRQReturn = 0;
                    auto dwWatchTime = std::chrono::steady_clock::now() + 2500ms;

                    while (iSpuAsyncWait && !bEndThread && std::chrono::steady_clock::now() < dwWatchTime) {
                        std::this_thread::sleep_for(1ms);
                    }
                }

                ////////////////////////////////////////////
            }

            rawSample = pChannel->data.get<PCSX::SPU::Chan::SB>()
                            .value[pChannel->data.get<PCSX::SPU::Chan::SBPos>().value++]
                            .value;  // get sample data

            pChannel->interp.storeVal(pChannel->data.get<PCSX::SPU::Chan::SB>().value.data(), rawSample,
                                      settings.get<Interpolation>(), pChannel->data.get<PCSX::SPU::Chan::FMod>().value,
                                      (spuCtrl & ControlFlags::Mute) != 0);  // store val for interpolation

            pChannel->data.get<PCSX::SPU::Chan::spos>().value -= kPitchCounterUnity;
        }

        if (pChannel->data.get<PCSX::SPU::Chan::Noise>().value)
            rawSample = m_noise.getVal(pChannel->data.get<PCSX::SPU::Chan::SB>().value.data(),
                                       settings.get<Interpolation>());  // get noise val
        else
            rawSample = pChannel->interp.getVal(pChannel->data.get<PCSX::SPU::Chan::SB>().value.data(),
                                                pChannel->data.get<PCSX::SPU::Chan::spos>().value,
                                                pChannel->data.get<PCSX::SPU::Chan::sinc>().value,
                                                settings.get<Interpolation>(),
                                                pChannel->data.get<PCSX::SPU::Chan::FMod>().value);  // get sample

        int32_t mixedSample = (pChannel->adsr.step(pChannel->data.get<PCSX::SPU::Chan::Stop>().value,
                                                   pChannel->data.get<PCSX::SPU::Chan::On>().value) *
                               rawSample) >>
                              kAdsrEnvelopeShift;  // apply the ADSR envelope (hardware: sample*env>>15)
        pChannel->data.get<PCSX::SPU::Chan::sval>().value = mixedSample;

        // The capture mirror holds the voice 1/3 sample after ADSR but before volume.
        mixedSample = std::clamp(mixedSample, -kCaptureSampleClamp, kCaptureSampleClamp);
        captureVoiceSample(ch, capVoice1Index, capVoice3Index, mixedSample);

        if (pChannel->data.get<PCSX::SPU::Chan::FMod>().value == 2)  // fmod freq channel
            iFMod[ns] = pChannel->data.get<PCSX::SPU::Chan::sval>().value;  // store sample for the next channel's fmod
        else                                                               // no fmod freq channel
        {
            // left/right sound volume (psx volume goes from 0 ... 0x3fff)
            if (pChannel->data.get<PCSX::SPU::Chan::Mute>().value &&
                !pChannel->data.get<PCSX::SPU::Chan::Solo>().value)
                pChannel->data.get<PCSX::SPU::Chan::sval>().value = 0;  // debug mute
            else {
                SSumL[ns] +=
                    (pChannel->data.get<PCSX::SPU::Chan::sval>().value * pChannel->volume.left()) / kVoiceVolumeUnity;
                SSumR[ns] +=
                    (pChannel->data.get<PCSX::SPU::Chan::sval>().value * pChannel->volume.right()) / kVoiceVolumeUnity;
            }

            if (pChannel->data.get<PCSX::SPU::Chan::RVBActive>().value) m_reverb.store(pChannel, ns, settings.get<Reverb>());  // store for reverb
        }

        pChannel->data.get<PCSX::SPU::Chan::spos>().value += pChannel->data.get<PCSX::SPU::Chan::sinc>().value;
    }
}

////////////////////////////////////////////////////////////////////////
// MAIN SPU FUNCTION
// here is the main job handler... thread, timer or direct func call
// basically the whole sound processing is done in this fat func!
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::MainThread() {
    int ns, ch;
    int32_t tmpCapVoice1Index = 0;
    int32_t tmpCapVoice3Index = 0;

    while (!bEndThread)  // until we are shutting down
    {
        int volumeDivisor = 4 - settings.get<Volume>();
        //--------------------------------------------------//
        // ok, at the beginning we are looking if there is
        // enuff free place in the dsound/oss buffer to
        // fill in new data, or if there is a new channel to start.
        // if not, we wait (thread) or return (timer/spuasync)
        // until enuff free place is available/a new channel gets
        // started

        if (dwNewChannel)    // new channel should start immedately?
        {                    // (at least one bit 0 ... MAXCHANNEL is set?)
            iSecureStart++;  // -> set iSecure
            if (iSecureStart > 5)
                iSecureStart = 0;  //    (if it is set 5 times - that means on 5 tries a new samples has been started -
                                   //    in a row, we will reset it, to give the sound update a chance)
        } else
            iSecureStart = 0;  // 0: no new channel should start

        while (!iSecureStart && !bEndThread &&              // no new start? no thread end?
               (m_audioOut.getBytesBuffered() > TESTSIZE))  // and still enuff data in sound buffer?
        {
            iSecureStart = 0;  // reset secure

            using namespace std::chrono_literals;
            std::this_thread::sleep_for(5ms);

            if (dwNewChannel)
                iSecureStart =
                    1;  // if a new channel kicks in (or, of course, sound buffer runs low), we will leave the loop
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
        //- here we have another 1 ms of sound data
        //---------------------------------------------------//

        ///////////////////////////////////////////////////////
        // mix all channels (including reverb) into one buffer

        for (ns = 0; ns < NSSIZE; ns++) {
            SSumL[ns] += m_reverb.mixLeft(ns, spuMem, spuCtrl, settings.get<Reverb>());
            *pS++ = std::clamp(SSumL[ns] / volumeDivisor, -kMixSampleClamp, kMixSampleClamp);
            SSumL[ns] = 0;

            SSumR[ns] += m_reverb.mixRight(settings.get<Reverb>());
            *pS++ = std::clamp(SSumR[ns] / volumeDivisor, -kMixSampleClamp, kMixSampleClamp);
            SSumR[ns] = 0;
        }

        //////////////////////////////////////////////////////
        // special irq handling in the decode buffers (0x0000-0x1000)
        // we know:
        // the decode buffers are located in spu memory in the following way:
        // 0x0000-0x03ff  CD audio left
        // 0x0400-0x07ff  CD audio right
        // 0x0800-0x0bff  Voice 1
        // 0x0c00-0x0fff  Voice 3
        // and decoded data is 16 bit for one sample
        // we assume:
        // even if voices 1/3 are off or no cd audio is playing, the internal
        // play positions will move on and wrap after 0x400 bytes.
        // Therefore: we just need a pointer from spumem+0 to spumem+3ff, and
        // increase this pointer on each sample by 2 bytes. If this pointer
        // (or 0x400 offsets of this pointer) hits the spuirq address, we generate
        // an IRQ. Only problem: the "wait for cpu" option is kinda hard to do here
        // in some of Peops timer modes. So: we ignore this option here (for now).
        // Also note: we abuse the channel 0-3 irq debug display for those irqs
        // (since that's the easiest way to display such irqs in debug mode :))

        if (pMixIrq)  // pMixIRQ will only be set, if the config option is active
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
        // feed the sound
        // wanna have around 1/60 sec (16.666 ms) updates

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

    // end of big main loop...

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
        // Update the capture buffer voice index, which in the end, should be the same as
        // tmpCapVoice1Index, tmpCapVoice3Index and captureBuffer.currIndex.
        // Unless I'm missing something in Pete's code.
        /* capBufVoiceIndex = (capBufVoiceIndex + NSSIZE) % 0x200;
        if ((tmpCapVoice1Index != tmpCapVoice3Index) || (tmpCapVoice3Index != captureBuffer.currIndex) ||
            (captureBuffer.currIndex != capBufVoiceIndex))
            g_system->log(LogClass::SPU, "Capture buffer indices are not the same.\n");*/
    }
}

////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////
// SPU ASYNC... even newer epsxe func
//  1 time every 'cycle' cycles... harhar
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::async(uint32_t cycle) {
    if (iSpuAsyncWait) {
        iSpuAsyncWait++;
        if (iSpuAsyncWait <= 64) return;
        iSpuAsyncWait = 0;
    }
}

////////////////////////////////////////////////////////////////////////
// XA AUDIO
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::playADPCMchannel(xa_decode_t *xap) {
    if (!settings.get<Streaming>()) return;  // no XA? bye
    if (!xap) return;
    if (!xap->freq) return;  // no xa freq ? bye

    FeedXA(xap);  // call main XA feeder
}

////////////////////////////////////////////////////////////////////////
// INIT/EXIT STUFF
////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////
// SPUINIT: this func will be called first by the main emu
////////////////////////////////////////////////////////////////////////

long PCSX::SPU::impl::init(void) {
    spuRamBase = (uint8_t *)spuMem;  // just small setup

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

////////////////////////////////////////////////////////////////////////
// SETUPTIMER: init of certain buffers and threads/timers
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::SetupThread() {
    memset(SSumR, 0, NSSIZE * sizeof(int));  // init some mixing buffers
    memset(SSumL, 0, NSSIZE * sizeof(int));
    memset(iFMod, 0, NSSIZE * sizeof(int));

    pS = (int16_t *)pSpuBuffer;  // setup soundbuffer pointer

    bEndThread = 0;  // init thread vars
    bThreadEnded = 0;
    bSpuInit = 1;  // flag: we are inited

    hMainThread = std::thread([this]() { MainThread(); });
}

////////////////////////////////////////////////////////////////////////
// REMOVETIMER: kill threads/timers
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::RemoveThread() {
    bEndThread = 1;  // raise flag to end thread

    using namespace std::chrono_literals;
    while (!bThreadEnded) {
        std::this_thread::sleep_for(5ms);
    }  // -> wait till thread has ended
    std::this_thread::sleep_for(5ms);

    hMainThread.join();

    bThreadEnded = 0;  // no more spu is running
    bSpuInit = 0;
}

////////////////////////////////////////////////////////////////////////
// SETUPSTREAMS: init most of the spu buffers
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::SetupStreams() {
    int i;

    pSpuBuffer = (uint8_t *)malloc(32768);  // alloc mixing buffer

    if (settings.get<Reverb>() == 1)
        i = 88200 * 2;
    else
        i = NSSIZE * 2;

    m_reverb.sRVBStart = (int *)malloc(i * 4);  // alloc reverb buffer
    memset(m_reverb.sRVBStart, 0, i * 4);
    m_reverb.sRVBEnd = m_reverb.sRVBStart + i;
    m_reverb.sRVBPlay = m_reverb.sRVBStart;

    for (i = 0; i < MAXCHAN; i++)  // loop sound channels
    {
        // we don't use mutex sync... not needed, would only
        // slow us down:
        //   s_chan[i].hMutex=CreateMutex(NULL,FALSE,NULL);
        s_chan[i].adsr.ex().get<exSustainLevel>().value = 0xf << 27;  // -> init sustain
        s_chan[i].data.get<PCSX::SPU::Chan::Mute>().value = false;
        s_chan[i].data.get<PCSX::SPU::Chan::Solo>().value = false;
        s_chan[i].data.get<PCSX::SPU::Chan::IrqDone>().value = 0;
        s_chan[i].adpcm.setLoop(spuRamBase);
        s_chan[i].adpcm.setStart(spuRamBase);
        s_chan[i].adpcm.setCurr(spuRamBase);
    }
}

////////////////////////////////////////////////////////////////////////
// REMOVESTREAMS: free most buffer
////////////////////////////////////////////////////////////////////////

void PCSX::SPU::impl::RemoveStreams(void) {
    free(pSpuBuffer);  // free mixing buffer
    pSpuBuffer = NULL;
    free(m_reverb.sRVBStart);  // free reverb buffer
    m_reverb.sRVBStart = 0;
}

////////////////////////////////////////////////////////////////////////
// SPUOPEN: called by main emu after init
////////////////////////////////////////////////////////////////////////

bool PCSX::SPU::impl::open() {
    if (bSPUIsOpen) return true;  // security for some stupid main emus

    m_reverb.iReverbOff = -1;
    spuIrq = 0;
    spuAddr = 0xffffffff;
    bEndThread = 0;
    bThreadEnded = 0;
    spuRamBase = (uint8_t *)spuMem;
    pMixIrq = 0;
    wipeChannels();
    pSpuIrq = 0;

    //    ReadConfig();  // read user stuff

    SetupStreams();  // prepare streaming

    SetupThread();  // timer for feeding data

    bSPUIsOpen = 1;

    m_lastUpdated = std::chrono::steady_clock::now();

    resetCaptureBuffer();

    return true;
}

////////////////////////////////////////////////////////////////////////
// SPUCLOSE: called before shutdown
////////////////////////////////////////////////////////////////////////

long PCSX::SPU::impl::close(void) {
    if (!bSPUIsOpen) return 0;  // some security

    bSPUIsOpen = 0;  // no more open

    RemoveThread();   // no more feeding
    RemoveStreams();  // no more streaming

    return 0;
}

////////////////////////////////////////////////////////////////////////
// SPUSHUTDOWN: called by main emu on final exit
////////////////////////////////////////////////////////////////////////

long PCSX::SPU::impl::shutdown(void) { return 0; }

////////////////////////////////////////////////////////////////////////
// SETUP CALLBACKS
// this functions will be called once,
// passes a callback that should be called on SPU-IRQ/cdda volume change
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
