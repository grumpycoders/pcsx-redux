// ==========================================================================
// Validate ADPCM decoding, filtering, loop and carry-over
// ==========================================================================

CESTER_TEST(adpcm_decode_silent, spu_tests,
    run_voice1_with_sample(kAdpcmSilent, 0x1000);
    SPU_ASSERT_GOLDEN(silent);
)

CESTER_TEST(adpcm_decode_sinewave, spu_tests,
    run_voice1_with_sample(kAdpcmSine, 0x1000);
    SPU_ASSERT_GOLDEN(sine);
)

CESTER_TEST(adpcm_decode_sinewave_lowpitch, spu_tests,
    run_voice1_with_sample(kAdpcmSine394Hz, 0x1000);
    SPU_ASSERT_GOLDEN(sine_low);
)

CESTER_TEST(adpcm_decode_sinewave_highpitch, spu_tests,
    run_voice1_with_sample(kAdpcmSine5512Hz, 0x1000);
    SPU_ASSERT_GOLDEN(sine_high);
)

CESTER_TEST(adpcm_decode_tranglewave, spu_tests,
    run_voice1_with_sample(kAdpcmTriangle, 0x1000);
    SPU_ASSERT_GOLDEN(triangle);
)

CESTER_TEST(adpcm_decode_squarewave, spu_tests,
    run_voice1_with_sample(kAdpcmSquare, 0x1000);
    SPU_ASSERT_GOLDEN(square);
)

CESTER_TEST(adpcm_decode_with_loop, spu_tests,
    run_voice1_with_sample(kAdpcmTriangle, 0x1000);
    SPU_ASSERT_GOLDEN(loop_t0);

    SPU_CTRL = 0x8000 | 0x4000;
    SPU_VOL_MAIN_LEFT = 0x3fff; SPU_VOL_MAIN_RIGHT = 0x3fff;
    SPU_KEY_OFF_LOW = 0xffff; SPU_KEY_OFF_HIGH = 0xffff;
    spu_busy_wait(800000);
    spu_wait_status_bit11_flip();

    spu_voice1_keyon(SPU_UPLOAD_ADDR, 0x1000);
    spu_busy_wait(15000000);  // ~440 ms, the 112-sample buffer lasts ~5 ms
    spu_wait_status_bit11_flip();
    spu_read_sync(0x0800, s_capture, 1024);
    SPU_ASSERT_GOLDEN(loop_t1);

    SPU_KEY_OFF_LOW = 0xffff; SPU_KEY_OFF_HIGH = 0xffff;
    muteSpu();
)
