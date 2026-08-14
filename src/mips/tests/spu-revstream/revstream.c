/*
 * Free-running reverb stimulus for the I2S digital-audio tap.
 *
 * The work-area capture in tests/spu/spu-reverb.c reads SPU RAM after a fixed
 * number of sync windows, which makes the result a snapshot whose contents move
 * with the key-on phase. This one is the opposite shape: program the room
 * preset, key one voice on exactly once, unmute the final mix, and then never
 * touch the SPU again. Everything after that point is the SPU running free, so
 * the only quantity that varies between runs is where the analyzer's window
 * lands - which cross-correlation can recover.
 *
 * The single key-on is the whole point. A sequencer that retriggers notes from
 * CPU code reintroduces run-to-run timing drift at every note boundary, and
 * that drift is indistinguishable from a reverb difference once it is in the
 * stream.
 */

#include "common/hardware/dma.h"
#include "common/hardware/hwregs.h"
#include "common/hardware/spu.h"
#include "common/syscalls/syscalls.h"

#include <stdint.h>

#define SPU_DELAY (*(volatile uint32_t *)0xbf801014)

#define SPU_UPLOAD_ADDR 0x1080u
// Reverb preset under test. Room is the default; -DREVSTREAM_HALL selects Hall,
// which exists to test a fix against geometry it was not derived from - roughly
// 4x Room's delays, a 44KB work area against 9KB, and different vIIR/vWALL.
// Both tables are transcribed from psx-spx "SPU Reverb Examples".
#ifdef REVSTREAM_PROBE
#define SPU_REVERB_SIZE 0x26c0u
#define SPU_REVERB_PRESET kReverbProbePreset
#elif defined(REVSTREAM_HALL)
#define SPU_REVERB_SIZE 0xade0u
#define SPU_REVERB_PRESET kReverbHallPreset
#else
#define SPU_REVERB_SIZE 0x26c0u
#define SPU_REVERB_PRESET kReverbRoomPreset
#endif
#define SPU_REVERB_BASE (0x80000u - SPU_REVERB_SIZE)
#define SPU_REVERB_BASE_REG (SPU_REVERB_BASE >> 3)

/* Sustained sine, loop flags set so the voice never runs off the end. Same
   bytes as tests/spu/spu.c kAdpcmSine - keep them identical so a capture here
   is comparable with the dry per-voice goldens. */

#ifdef REVSTREAM_PN
/* Aperiodic broadband stimulus, for alignment and impulse-response work.
   The tone stimulus repeats every 28 samples, so cross-correlating two captures
   can only ever resolve alignment MODULO 28 - which is why a confident, rock
   steady offset can sit alongside a fit that does not converge. The ambiguity is
   in the signal, not the correlator.
   Blocks of 28 samples filled from an LFSR. Predictor 0 means no ADPCM filter,
   so each nibble decodes as (n << 12) >> shift and the sequence passes through
   scaled rather than shaped. Autocorrelation is then one sharp peak with its
   nearest repeat a full loop away, so alignment is unique.

   THE LOOP MUST BE LONGER THAN THE REVERB'S IMPULSE RESPONSE, and the first
   version of this was not. Measured 2026-08-14 by subtracting an aligned dry
   capture from a wet one (bit-exact, both runs deterministic): the Room preset
   has a PURE input-to-output delay of 1414 samples and a total impulse span of
   1845 samples at 44.1kHz. The original 64 blocks gave a 1792-sample loop -
   SHORTER than the response it was built to identify - so every system
   identification run on it was circularly aliased, and a full-length fit
   reproduced the steady state bit-exactly while predicting the onset 9x worse
   than assuming no reverb at all. That exactness was basis completeness: a
   period-P input supplies exactly P independent equations no matter how long
   the capture is.

   512 blocks = 14336 samples, ~7.8x the measured Room span. Hall's delays are
   ~4x Room's, so re-measure the span before trusting a fit on that preset. */
#define PN_BLOCKS 512
#define PN_BYTES (PN_BLOCKS * 16)
static uint8_t s_pn[PN_BYTES] __attribute__((aligned(4)));
static void pn_build(void) {
    uint16_t lfsr = 0xACE1u;
    for (unsigned b = 0; b < PN_BLOCKS; b++) {
        uint8_t *blkp = s_pn + b * 16;
        blkp[0] = 0x01;                                  /* shift 1, predictor 0 */
        blkp[1] = (b == PN_BLOCKS - 1) ? 0x03 : 0x00;    /* loop+repeat on the last */
        for (unsigned i = 0; i < 14; i++) {
            uint8_t lo, hi;
            lfsr = (uint16_t)((lfsr >> 1) ^ (-(int16_t)(lfsr & 1u) & 0xB400u));
            lo = (uint8_t)(lfsr & 0x0Fu);
            lfsr = (uint16_t)((lfsr >> 1) ^ (-(int16_t)(lfsr & 1u) & 0xB400u));
            hi = (uint8_t)(lfsr & 0x0Fu);
            blkp[2 + i] = (uint8_t)(lo | (hi << 4));
        }
    }
}
#endif

static const uint8_t kAdpcmSine[64] __attribute__((aligned(4))) = {
    0x00, 0x06, 0x10, 0x43, 0x76, 0x77, 0x77, 0x46, 0x13, 0xe0, 0xbc, 0x89, 0x88, 0x88, 0xb9, 0xec,
    0x00, 0x00, 0x10, 0x43, 0x76, 0x77, 0x77, 0x46, 0x13, 0xe0, 0xbc, 0x89, 0x88, 0x88, 0xb9, 0xec,
    0x00, 0x00, 0x10, 0x43, 0x76, 0x77, 0x77, 0x46, 0x13, 0xe0, 0xbc, 0x89, 0x88, 0x88, 0xb9, 0xec,
    0x00, 0x03, 0x10, 0x43, 0x76, 0x77, 0x77, 0x46, 0x13, 0xe0, 0xbc, 0x89, 0x88, 0x88, 0xb9, 0xec,
};

static const uint16_t kReverbProbePreset[32] = {
    // A DELIBERATELY DEGENERATE register set. These are not a room; they are a
    // measurement fixture. The reverb registers are freely writable, so rather
    // than testing against another documented preset we collapse the network:
    //
    //   vWALL = 0, vIIR = 7FFF  ->  [mLSAME] = (Lin + 0 - old)*~1 + old ~= Lin,
    //                               so the same/diff stage stops recursing and
    //                               becomes a straight copy of the decimated input
    //   vAPF1 = vAPF2 = 0       ->  Lout = Lout*0 + [tap], i.e. each all-pass
    //                               degenerates to a pure delay
    //   vCOMB2..4 = 0           ->  the early-echo stage is ONE tap
    //
    // What survives is a single delayed, scaled copy of the input. The output
    // therefore has a closed form, its cross-correlation against the input must
    // be a SINGLE peak, and the lag and amplitude of that peak are checkable
    // numbers rather than a 28-phase fold scored modulo rotation.
    //
    // dAPF1  dAPF2  vIIR   vCOMB1 vCOMB2 vCOMB3 vCOMB4 vWALL
    0x0020, 0x0010, 0x7fff, 0x4000, 0x0000, 0x0000, 0x0000, 0x0000,
    // vAPF1  vAPF2  mLSAME mRSAME mLCOMB1 mRCOMB1 mLCOMB2 mRCOMB2
    0x0000, 0x0000, 0x0400, 0x0200, 0x0380, 0x0180, 0x0300, 0x0140,
    // dLSAME dRSAME mLDIFF mRDIFF mLCOMB3 mRCOMB3 mLCOMB4 mRCOMB4
    0x03f0, 0x01f0, 0x0470, 0x0270, 0x02c0, 0x0120, 0x0280, 0x0100,
    // dLDIFF dRDIFF mLAPF1 mRAPF1 mLAPF2 mRAPF2 vLIN   vRIN
    0x0460, 0x0260, 0x0100, 0x00c0, 0x0080, 0x0060, 0x7fff, 0x7fff,
};

static const uint16_t kReverbHallPreset[32] = {
    0x01a5, 0x0139, 0x6000, 0x5000, 0x4c00, 0xb800, 0xbc00, 0xc000,
    0x6000, 0x5c00, 0x15ba, 0x11bb, 0x14c2, 0x10bd, 0x11bc, 0x0dc1,
    0x11c0, 0x0dc3, 0x0dc0, 0x09c1, 0x0bc4, 0x07c1, 0x0a00, 0x06cd,
    0x09c2, 0x05c1, 0x05c0, 0x041a, 0x0274, 0x013a, 0x8000, 0x8000,
};

static const uint16_t kReverbRoomPreset[32] = {
    0x007d, 0x005b, 0x6d80, 0x54b8, 0xbed0, 0x0000, 0x0000, 0xba80,
    0x5800, 0x5300, 0x04d6, 0x0333, 0x03f0, 0x0227, 0x0374, 0x01ef,
    0x0334, 0x01b5, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x01b4, 0x0136, 0x00b8, 0x005c, 0x8000, 0x8000,
};

#ifndef BURST_TOTAL_BLOCKS
#define BURST_TOTAL_BLOCKS 512
#endif
#define BURST_UPLOAD_BYTES (BURST_TOTAL_BLOCKS * 16)
#if BURST_UPLOAD_BYTES > 128
static uint8_t s_upload[BURST_UPLOAD_BYTES] __attribute__((aligned(4)));
#else
static uint8_t s_upload[128] __attribute__((aligned(4)));
#endif
static uint8_t s_zeros[0x800] __attribute__((aligned(4)));

static void spu_dma_read(uint32_t spuByteAddr, void *dst, uint32_t bytes) {
    const uint16_t tsa = (uint16_t)(spuByteAddr >> 3);
    SPU_RAM_DTA = tsa;
    for (int i = 0; i < 0xF01 && (SPU_RAM_DTA & 0xffff) != tsa; i++);
    SPU_CTRL = (SPU_CTRL & ~0x0030) | 0x0030;
    for (volatile int i = 0; i < 60; i++);
    for (int i = 0; i < 0xF01 && (SPU_STATUS & 0x30) != 0x0030; i++);
    SPU_DELAY = (SPU_DELAY & 0xf0ffffff) | 0x20000000;
    uint32_t blocks = (bytes >> 6) + ((bytes & 0x3f) ? 1 : 0);
    DMA_CTRL[DMA_SPU].MADR = (uint32_t)dst & 0x1fffffff;
    DMA_CTRL[DMA_SPU].BCR = (blocks << 16) | 0x10;
    DMA_CTRL[DMA_SPU].CHCR = 0x01000200;
    while ((DMA_CTRL[DMA_SPU].CHCR & 0x01000000) != 0) __asm__ volatile("");
    SPU_CTRL = (SPU_CTRL & ~0x0030);
    for (volatile int i = 0; i < 60; i++);
}

static void spu_dma_write(uint32_t spuByteAddr, const void *src, uint32_t bytes) {
    const uint16_t tsa = (uint16_t)(spuByteAddr >> 3);

    SPU_RAM_DTA = tsa;
    for (int i = 0; i < 0xF01 && (SPU_RAM_DTA & 0xffff) != tsa; i++);
    SPU_CTRL = (SPU_CTRL & ~0x0030) | 0x0020;
    for (volatile int i = 0; i < 60; i++);
    for (int i = 0; i < 0xF01 && (SPU_STATUS & 0x30) != 0x0020; i++);
    SPU_DELAY = (SPU_DELAY & 0xf0ffffff) | 0x20000000;

    uint32_t blocks = (bytes >> 6) + ((bytes & 0x3f) ? 1 : 0);
    DMA_CTRL[DMA_SPU].MADR = (uint32_t)src & 0x1fffffff;
    DMA_CTRL[DMA_SPU].BCR = (blocks << 16) | 0x10;
    DMA_CTRL[DMA_SPU].CHCR = 0x01000201;
    while ((DMA_CTRL[DMA_SPU].CHCR & 0x01000000) != 0) __asm__ volatile("");

    SPU_CTRL = (SPU_CTRL & ~0x0030);
    for (volatile int i = 0; i < 60; i++);
}

static void spu_reset_quiet(void) {
    DPCR |= 0x000b0000;
    SPU_CTRL = 0;
    SPU_VOL_MAIN_LEFT = 0;
    SPU_VOL_MAIN_RIGHT = 0;
    SPU_REVERB_LEFT = 0;
    SPU_REVERB_RIGHT = 0;
    SPU_KEY_OFF_LOW = 0xffff;
    SPU_KEY_OFF_HIGH = 0xffff;
    SPU_PITCH_MOD_LOW = 0;
    SPU_PITCH_MOD_HIGH = 0;
    SPU_NOISE_EN_LOW = 0;
    SPU_NOISE_EN_HIGH = 0;
    SPU_REVERB_EN_LOW = 0;
    SPU_REVERB_EN_HIGH = 0;
    SPU_REVERB_ADDR = 0xffff;
    SPU_RAM_DTC = 4;
    SPU_CTRL = 0x8000;
}

int main(void) {
    ramsyscall_printf("REVSTREAM: start\n");

    spu_reset_quiet();

#ifdef REVSTREAM_BURST
    for (int i = 0; i < BURST_UPLOAD_BYTES; i++) s_upload[i] = 0;
    for (int i = 0; i < 64; i++) s_upload[i] = kAdpcmSine[i];
    s_upload[3 * 16 + 1] = 0x00;
    s_upload[(BURST_TOTAL_BLOCKS - 1) * 16 + 1] = 0x03;
#define BURST_TAIL_BYTES 64
    /* Upload 0xaa filler past the sample so SPU RAM content matches the
       steady-tone path. Redux boots SPU RAM clean; silicon retains whatever the
       previous run left.

       DO NOT read this as the explanation for the burst silence - that
       hypothesis is REFUTED on hardware. A BLOCKS=4 burst build plus this exact
       0xaa tail (SPU RAM content then identical to the tone) captured SILENT on
       SCPH-1001 on 2026-08-01, one of six captures in the elimination trail.
       Block count, DMA chunk size, this filler, the post-upload printf and the
       diagnostic loop are each individually eliminated as causes. The burst
       silence cause is UNKNOWN. This is hygiene, not a fix. */
    static uint8_t s_tail[BURST_TAIL_BYTES] __attribute__((aligned(4)));
    for (int i = 0; i < BURST_TAIL_BYTES; i++) s_tail[i] = 0xaa;
    for (unsigned off = 0; off < BURST_UPLOAD_BYTES; off += 0x800) {
        unsigned chunk = BURST_UPLOAD_BYTES - off;
        if (chunk > 0x800) chunk = 0x800;
        spu_dma_write(SPU_UPLOAD_ADDR + off, s_upload + off, chunk);
    }
    spu_dma_write(SPU_UPLOAD_ADDR + BURST_UPLOAD_BYTES, s_tail, BURST_TAIL_BYTES);
#else
#ifdef REVSTREAM_PN
    pn_build();
    /* Chunked at 0x800 like the burst path - the single-shot transfer was fine
       at 1KB but this stimulus is 8KB and nothing has established that a
       transfer that size lands intact on silicon. */
    for (unsigned off = 0; off < PN_BYTES; off += 0x800) {
        unsigned chunk = PN_BYTES - off;
        if (chunk > 0x800) chunk = 0x800;
        spu_dma_write(SPU_UPLOAD_ADDR + off, s_pn + off, chunk);
    }
#else
    for (int i = 0; i < 64; i++) s_upload[i] = kAdpcmSine[i];
    for (int i = 64; i < 128; i++) s_upload[i] = 0xaa;
    spu_dma_write(SPU_UPLOAD_ADDR, s_upload, 128);
#endif
#endif
    {
        /* Read the sample back out of SPU RAM and checksum it.

           *** THIS VERIFIER DOES NOT WORK ON HARDWARE. DO NOT TRUST ITS OUTPUT
           ON SILICON. *** It reads plausible values under Redux and garbage on a
           real SCPH-1001. Measured 2026-08-01 by pointing it at the TONE path,
           whose sample is unquestionably in SPU RAM (it produces 16088 of
           audio): silicon read back sum=e0ec7c76 b0=ffff, Redux read
           sum=fa862e09 b0=0006. The b0=ffff is the verifier failing, not an
           empty SPU RAM.

           This already caused one full retraction: an earlier session read
           b0=ffff on the burst path, concluded "the upload never lands on
           silicon", and invalidated five chunks of live ADPCM hypotheses on the
           strength of it. All of them are live again. The read transfer mode
           (CHCR 0x01000200 / SPU_CTRL 0x0030) or some required handshake
           differs on hardware and has never been worked out.

           Kept because it is valid under Redux. Anything it prints over
           --follow from the farm is noise. */
        static uint8_t s_verify[128] __attribute__((aligned(4)));
        for (int i = 0; i < 128; i++) s_verify[i] = 0x5a;
        spu_dma_read(SPU_UPLOAD_ADDR, s_verify, 128);
        uint32_t sum = 0;
        for (int i = 0; i < 128; i++) sum = sum * 31u + s_verify[i];
        ramsyscall_printf("REVSTREAM: readback sum=%08x b0=%02x%02x b1=%02x b3f=%02x\n",
                          sum, s_verify[0], s_verify[1], s_verify[17], s_verify[3 * 16 + 1]);
    }


    /* Reverb writes stay disabled while the work area is cleared, otherwise the
       SPU races the DMA and the first seconds of tail are whatever was in RAM. */
    SPU_CTRL = 0x8000 | 0x4000;
    for (unsigned i = 0; i < sizeof(s_zeros); i++) s_zeros[i] = 0;
    for (unsigned off = 0; off < SPU_REVERB_SIZE; off += sizeof(s_zeros)) {
        unsigned chunk = SPU_REVERB_SIZE - off;
        if (chunk > sizeof(s_zeros)) chunk = sizeof(s_zeros);
        spu_dma_write(SPU_REVERB_BASE + off, s_zeros, chunk);
    }

    SPU_REVERB_ADDR = SPU_REVERB_BASE_REG;
    {
        volatile uint16_t *regs = (volatile uint16_t *)SPU_REVERB;
        for (unsigned i = 0; i < 32; i++) regs[i] = SPU_REVERB_PRESET[i];
    }

    SPU_VOICES[1].volumeLeft = 0x3fff;
    SPU_VOICES[1].volumeRight = 0x3fff;
#ifdef REVSTREAM_DRY
    /* Negative control: identical in every respect except that the voice never
       reaches the reverb unit. If a capture of this is indistinguishable from
       the reverb build, the reverb build was never observing reverb. */
    SPU_REVERB_EN_LOW = 0;
#else
    SPU_REVERB_EN_LOW = 1u << 1;
#endif
    SPU_REVERB_EN_HIGH = 0;

    /* Unlike the work-area test, the final mix is what is being observed here,
       so main and reverb output volumes come up. */
    SPU_VOL_MAIN_LEFT = 0x3fff;
    SPU_VOL_MAIN_RIGHT = 0x3fff;
    SPU_REVERB_LEFT = 0x3fff;
    SPU_REVERB_RIGHT = 0x3fff;

#ifdef REVSTREAM_DRY
    SPU_CTRL = 0x8000 | 0x4000;
#else
    SPU_CTRL = 0x8000 | 0x4000 | 0x0080;
#endif

    SPU_VOICES[1].sampleRate = 0x1000;
    SPU_VOICES[1].sampleStartAddr = SPU_UPLOAD_ADDR >> 3;
    SPU_VOICES[1].sampleRepeatAddr = SPU_UPLOAD_ADDR >> 3;
    SPU_VOICES[1].adsrLo = 0x000f;
    SPU_VOICES[1].adsrHi = 0x1fc0;
    SPU_KEY_OFF_LOW = 0;
    SPU_KEY_OFF_HIGH = 0;

    /* Align to the same capture-half edge the dry tests use, then the one and
       only key-on. Nothing below this line touches the SPU.

       THIS DOES NOT PIN THE REVERB'S TICK PHASE UNDER REDUX, and a capture is
       worthless if you assume it does. The reverb decimates to 22.05kHz, so
       key-on landing on an odd rather than even output sample puts the whole
       reverb on the other phase - a different signal, ~5% of amplitude apart,
       reachable by no alignment shift. Measured 2026-08-14: six captures of one
       identical image split 5-to-1 into two bit-exact classes, the outlier
       carrying an odd (45-sample) offset. Redux runs the SPU on a free-running
       std::thread (see src/spu/spu.cc, hMainThread), and this wait only aligns
       against the SPU's own capture grid, not against where that thread began.
       Each class is internally bit-exact, so a bad draw has NO tell - it reads
       as a clean 6x accuracy regression.

       Until this is pinned: capture every wet run THREE times and require two
       to agree bit-exactly. That pair is the measurement. */
    while (!(SPU_STATUS & 0x0800));
    while ((SPU_STATUS & 0x0800));
    SPU_KEY_ON_LOW = 1u << 1;

#ifdef REVSTREAM_DRY
    ramsyscall_printf("REVSTREAM(DRY): keyon, free-running\n");
#else
    ramsyscall_printf("REVSTREAM: keyon, free-running\n");
#endif

    while (1) __asm__ volatile("");
    return 0;
}
