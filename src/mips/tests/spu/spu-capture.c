// ==========================================================================
// Validate voice resampling
// ==========================================================================

CESTER_TEST(voice_sample_rates, spu_tests,
    run_voice1_with_sample(kAdpcmSine, 0x0800);
    SPU_ASSERT_GOLDEN(sine_pitch_0800);
    run_voice1_with_sample(kAdpcmSine, 0x2000);
    SPU_ASSERT_GOLDEN(sine_pitch_2000);
    run_voice1_with_sample(kAdpcmSine, 0x3000);
    SPU_ASSERT_GOLDEN(sine_pitch_3000);
)

// Every other rate in the suite (0x0800, 0x1000, 0x2000, 0x3000) is an exact
// binary fraction of unity, so the 16.16 pitch counter's fractional part lands
// on zero every step and the gaussian interpolation index is pinned at 0 - or
// alternates 0/0x80 for 0x0800. The interpolator's rounding is therefore not
// observable anywhere else in the suite. 0x1500 walks the index over the table
// instead: 16 distinct values against the 1 every other rate provides.
//
// The rate cannot be just any non-dyadic value. What has to stay periodic is
// the joint (pitch phase, ADPCM read position) state, and kAdpcmSine loops
// every 112 samples. 0x1500 gives that pair a period of 256 output samples,
// which fits inside the 512-sample capture ring; a rate whose period does not
// fit leaves the golden unable to absorb a phase difference by rotation, and
// the comparison silently becomes a test of absolute key-on phase.
CESTER_TEST(voice_sample_rate_nondyadic, spu_tests,
    run_voice1_with_sample(kAdpcmSine, 0x1500);
    SPU_ASSERT_GOLDEN(sine_pitch_1500);
)

CESTER_TEST(voice_volume_does_not_affect_capture, spu_tests,
    SPU_VOICES[1].volumeLeft = 0x3fff;
    SPU_VOICES[1].volumeRight = 0x3fff;
    run_voice1_with_sample(kAdpcmTriangle, 0x1000);
    SPU_ASSERT_GOLDEN(triangle);
    SPU_VOICES[1].volumeLeft = 0;
    SPU_VOICES[1].volumeRight = 0;
    run_voice1_with_sample(kAdpcmTriangle, 0x1000);
    SPU_ASSERT_GOLDEN(triangle);
)
