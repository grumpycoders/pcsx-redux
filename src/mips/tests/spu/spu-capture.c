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
