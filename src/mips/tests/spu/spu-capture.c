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

// 0x1500 above walks the index, but it cannot be compared: the golden absorbs a
// key-on phase difference by rotating the capture ring, and a rotation by r moves
// the source phase by num*r mod 28, where num/den is the rate in lowest terms and
// 28 is the sample's decoded VALUE period. That reaches every phase only when
// gcd(num, 28) == 1. For 0x1500, num is 21 and the gcd is 7, so a rotation reaches
// 4 of the 28 phases and the comparison silently becomes a test of absolute key-on
// phase - which is exactly what its measured spread against hardware is.
//
// 0x1400 is 5/4: gcd(5, 28) == 1, so every phase is reachable. It walks the index
// over 4 values (0, 64, 128, 192) rather than 0x1500's 16, and that is the price of
// fitting: distinct indices equal den, the joint period is den * 28, and warmup
// depends on where in the run the capture lands - measured between 0 and 344
// samples for one rate in one pass. den = 4 costs 112 samples of the 512-sample
// ring, which survives the worst warmup seen; den = 8 and den = 16 do not, and both
// were measured taking the no-period path.
CESTER_TEST(voice_sample_rate_swept_index, spu_tests,
    run_voice1_with_sample(kAdpcmSine, 0x1400);
    SPU_ASSERT_GOLDEN(sine_pitch_1400);
)

// The same sweep at full resolution. kAdpcmSine7's decoded value period is 7
// rather than 28, so 0x1300 (19/16) walks all sixteen gaussian indices for a
// joint period of 16*7 = 112 - the same ring cost as the four-index capture
// above, four times the coverage, and 400 samples of headroom for the warmup.
// gcd(19, 7) = 1, so every source phase stays reachable by rotation.
CESTER_TEST(voice_sample_rate_swept_index_full, spu_tests,
    run_voice1_with_sample(kAdpcmSine7, 0x1300);
    SPU_ASSERT_GOLDEN(sine7_pitch_1300);
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
