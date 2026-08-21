// ==========================================================================
// Exercise the two compile-time mode axes of the synthesis loop: the noise
// sample source, and the frequency-modulation source/target pair.
//
// There are NO hardware goldens for either configuration. Nothing else in this
// suite has ever driven noise or FM, which is exactly why the census has zero
// power over those paths - a sweep of ~40 PSF tracks across six commercial
// games measured both flags as never once set. So these tests PRINT their raw
// voice-1 capture instead of asserting against a golden, and two builds are
// differenced against each other offline.
//
// A capture printed here is emulator output, not a hardware measurement. It is
// good for "build A agrees with build B" and for nothing else; do not promote
// one to a .test.pcm golden without a capture from real silicon.
// ==========================================================================

CESTER_BODY(
    static void spu_print_capture(const char *name) {
        // One line per capture, so a diff points at the test rather than a sample.
        ramsyscall_printf("MODEAXES %s", name);
        for (int i = 0; i < 512; i++) ramsyscall_printf(" %04x", s_capture[i]);
        ramsyscall_printf("\n");
    }

    // Voice 1 takes its pre-envelope sample from the SPU-wide noise generator
    // rather than its own ADPCM stream. The stream is still uploaded and the voice
    // is still keyed on, because a noise voice keeps walking it: the decoded
    // samples are discarded, but the cursor advance, the IRQ address check and the
    // ENDX latch all hang off the block boundary.
    static void run_voice1_noise(uint16_t pitch, uint16_t noiseCtrl) {
        spu_reset_quiet();
        for (int i = 0; i < 64; i++) s_upload[i] = kAdpcmSine[i];
        for (int i = 64; i < 128; i++) s_upload[i] = 0xaa;
        spu_write_sync(SPU_UPLOAD_ADDR, s_upload, 128);
        SPU_CTRL = 0x8000 | 0x4000 | noiseCtrl;  // noise shift/step ride in bits 13-8
        SPU_VOL_MAIN_LEFT = 0x3fff;
        SPU_VOL_MAIN_RIGHT = 0x3fff;
        SPU_NOISE_EN_LOW = 1u << 1;

        SPU_KEY_OFF_LOW = 0xffff;
        SPU_KEY_OFF_HIGH = 0xffff;
        spu_busy_wait(800000);
        spu_wait_status_bit11_flip();
        spu_voice1_keyon(SPU_UPLOAD_ADDR, pitch);
        spu_wait_status_bit11_flip();

        spu_read_sync(0x0800, s_capture, 1024);
        SPU_KEY_OFF_LOW = 0xffff;
        SPU_KEY_OFF_HIGH = 0xffff;
        muteSpu();
    }

    // Voice 0 modulates voice 1. Setting the pitch-mod bit for voice 1 makes 1 the
    // target and 0 the source, so a single capture of voice 1 covers BOTH
    // instantiations: the target's pitch only moves because the source wrote
    // iFMod, so a broken source shows up as a target that stopped bending.
    static void run_voice1_fm(uint16_t srcPitch, uint16_t dstPitch) {
        spu_reset_quiet();
        for (int i = 0; i < 64; i++) s_upload[i] = kAdpcmSine[i];
        for (int i = 64; i < 128; i++) s_upload[i] = 0xaa;
        spu_write_sync(SPU_UPLOAD_ADDR, s_upload, 128);
        SPU_CTRL = 0x8000 | 0x4000;
        SPU_VOL_MAIN_LEFT = 0x3fff;
        SPU_VOL_MAIN_RIGHT = 0x3fff;

        SPU_KEY_OFF_LOW = 0xffff;
        SPU_KEY_OFF_HIGH = 0xffff;
        spu_busy_wait(800000);

        SPU_VOICES[0].sampleRate = srcPitch;
        SPU_VOICES[0].sampleStartAddr = SPU_UPLOAD_ADDR >> 3;
        SPU_VOICES[0].sampleRepeatAddr = SPU_UPLOAD_ADDR >> 3;
        SPU_VOICES[0].adsrLo = 0x000f;
        SPU_VOICES[0].adsrHi = 0x1fc0;
        SPU_VOICES[1].sampleRate = dstPitch;
        SPU_VOICES[1].sampleStartAddr = SPU_UPLOAD_ADDR >> 3;
        SPU_VOICES[1].sampleRepeatAddr = SPU_UPLOAD_ADDR >> 3;
        SPU_VOICES[1].adsrLo = 0x000f;
        SPU_VOICES[1].adsrHi = 0x1fc0;
        SPU_PITCH_MOD_LOW = 1u << 1;

        spu_wait_status_bit11_flip();
        SPU_KEY_OFF_LOW = 0;
        SPU_KEY_OFF_HIGH = 0;
        SPU_KEY_ON_LOW = (1u << 0) | (1u << 1);
        spu_wait_status_bit11_flip();

        spu_read_sync(0x0800, s_capture, 1024);
        SPU_KEY_OFF_LOW = 0xffff;
        SPU_KEY_OFF_HIGH = 0xffff;
        muteSpu();
    })

// clang-format off

CESTER_TEST(modeaxes_noise_voice1, spu_tests,
    run_voice1_noise(0x1000, 0x2000);
    spu_print_capture("noise_v1");
    cester_assert_int_eq(0, 0);
)

CESTER_TEST(modeaxes_fmod_pair, spu_tests,
    run_voice1_fm(0x0400, 0x1000);
    spu_print_capture("fm_v1");
    cester_assert_int_eq(0, 0);
)
