// ============================================================================
// Characterize SPU ADPCM decoder edge cases not covered by the basic waveform
// tests. Goldens are hardware-owned: first run either with SPU_DUMP=true to
// collect .test.pcm files, or without goldens to print OBS lines and scalar
// observations. Once the farm has measured silicon, define
// SPU_ADPCM_EDGE_GOLDENS_AVAILABLE and include the generated files.
// ============================================================================

#ifndef SPU_ADPCM_EDGE_GOLDENS_AVAILABLE
#define SPU_ADPCM_EDGE_GOLDENS_AVAILABLE 0
#endif

#ifndef SPU_ADPCM_EDGE_EXPECTED_REPEAT_LOOP_START
#define SPU_ADPCM_EDGE_EXPECTED_REPEAT_LOOP_START 0x212u
#endif
#ifndef SPU_ADPCM_EDGE_EXPECTED_REPEAT_END_MUTE
#define SPU_ADPCM_EDGE_EXPECTED_REPEAT_END_MUTE 0x210u
#endif
#ifndef SPU_ADPCM_EDGE_EXPECTED_ENDX_END_MUTE
#define SPU_ADPCM_EDGE_EXPECTED_ENDX_END_MUTE 0x1u
#endif
#ifndef SPU_ADPCM_EDGE_EXPECTED_ENVX_END_MUTE
#define SPU_ADPCM_EDGE_EXPECTED_ENVX_END_MUTE 0x0u
#endif
#ifndef SPU_ADPCM_EDGE_EXPECTED_ENDX_END_REPEAT
#define SPU_ADPCM_EDGE_EXPECTED_ENDX_END_REPEAT 0x1u
#endif
#ifndef SPU_ADPCM_EDGE_EXPECTED_ENVX_END_REPEAT
#define SPU_ADPCM_EDGE_EXPECTED_ENVX_END_REPEAT 0x3fffu
#endif

#define SPU_ENDX_LOW HW_U16(0x1f801d9c)

#if SPU_ADPCM_EDGE_GOLDENS_AVAILABLE && !defined(SPU_DUMP)
#define SPU_ADPCM_EDGE_INCBIN(NAME) \
    asm( \
        ".pushsection .rodata\n" \
        ".global " #NAME "\n" \
        ".align 2\n" \
        #NAME ":\n" \
        ".incbin \"" #NAME ".test.pcm\"\n" \
        ".popsection")

CESTER_BODY(
SPU_ADPCM_EDGE_INCBIN(adpcm_edge_predictor_0);
SPU_ADPCM_EDGE_INCBIN(adpcm_edge_predictor_1);
SPU_ADPCM_EDGE_INCBIN(adpcm_edge_predictor_2);
SPU_ADPCM_EDGE_INCBIN(adpcm_edge_predictor_3);
SPU_ADPCM_EDGE_INCBIN(adpcm_edge_predictor_4);
SPU_ADPCM_EDGE_INCBIN(adpcm_edge_shift_00_03);
SPU_ADPCM_EDGE_INCBIN(adpcm_edge_shift_04_07);
SPU_ADPCM_EDGE_INCBIN(adpcm_edge_shift_08_11);
SPU_ADPCM_EDGE_INCBIN(adpcm_edge_shift_12_15);
SPU_ADPCM_EDGE_INCBIN(adpcm_edge_state_carry);
SPU_ADPCM_EDGE_INCBIN(adpcm_edge_saturation_positive);
SPU_ADPCM_EDGE_INCBIN(adpcm_edge_saturation_negative);
SPU_ADPCM_EDGE_INCBIN(adpcm_edge_flag_code2_ignored);
SPU_ADPCM_EDGE_INCBIN(adpcm_edge_flag_loop_start_latch);
SPU_ADPCM_EDGE_INCBIN(adpcm_edge_flag_end_mute);
SPU_ADPCM_EDGE_INCBIN(adpcm_edge_flag_end_repeat);
SPU_ADPCM_EDGE_INCBIN(adpcm_edge_invalid_predictor_5_7);
)

#undef SPU_ADPCM_EDGE_INCBIN
#endif

CESTER_BODY(
static const uint8_t kEdgeZero[14] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t kEdgePositive[14] = {
    0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
    0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
};
static const uint8_t kEdgeNegative[14] = {
    0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,
    0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,
};
static const uint8_t kEdgeAlternating[14] = {
    0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78,
    0x78, 0x78, 0x78, 0x78, 0x78, 0x78, 0x78,
};
static const uint8_t kEdgeRamp[14] = {
    0x10, 0x32, 0x54, 0x76, 0x56, 0x34, 0x12,
    0xe0, 0xcd, 0xab, 0x89, 0xa9, 0xcb, 0xed,
};
static const uint8_t kEdgeMixed[14] = {
    0x17, 0xde, 0x9a, 0xbc, 0x45, 0x23, 0x01,
    0xfe, 0xdc, 0xba, 0x98, 0x89, 0x67, 0x45,
};

static void spu_adpcm_edge_block(uint8_t *sample, int block, uint8_t header,
                                 uint8_t flags, const uint8_t *payload) {
    uint8_t *p = sample + block * 16;
    p[0] = header;
    p[1] = flags;
    for (int i = 0; i < 14; i++) p[2 + i] = payload[i];
}

static uint32_t spu_adpcm_edge_hash_capture(void) {
    uint32_t h = 2166136261u;
    for (int i = 0; i < 512; i++) {
        h ^= (uint16_t)s_capture[i];
        h *= 16777619u;
    }
    return h;
}

static void spu_adpcm_edge_observe(const char *name) {
    int16_t min = (int16_t)s_capture[0];
    int16_t max = (int16_t)s_capture[0];
    for (int i = 1; i < 512; i++) {
        int16_t v = (int16_t)s_capture[i];
        if (v < min) min = v;
        if (v > max) max = v;
    }
    ramsyscall_printf("OBS spu_adpcm_edge golden %s.test.pcm hash=0x%08x first=0x%04x mid=0x%04x last=0x%04x min=0x%04x max=0x%04x\n",
                      name, spu_adpcm_edge_hash_capture(), s_capture[0],
                      s_capture[256], s_capture[511], (uint16_t)min,
                      (uint16_t)max);
}

static void spu_adpcm_edge_expect_u32(const char *name, uint32_t expected,
                                      uint32_t got) {
    if (expected == 0xffffffffu) {
        ramsyscall_printf("OBS spu_adpcm_edge expected %s=0x%08x\n", name, got);
    } else {
        cester_assert_uint_eq(expected, got);
    }
}

static void spu_adpcm_edge_run_capture_keep_on(const uint8_t *sample64,
                                               uint16_t pitch) {
    spu_reset_quiet();
    for (int i = 0; i < 64; i++) s_upload[i] = sample64[i];
    for (int i = 64; i < 128; i++) s_upload[i] = 0xaa;
    spu_write_sync(SPU_UPLOAD_ADDR, s_upload, 128);
    SPU_CTRL = 0x8000 | 0x4000;
    SPU_VOL_MAIN_LEFT = 0x3fff;
    SPU_VOL_MAIN_RIGHT = 0x3fff;

    SPU_KEY_OFF_LOW = 0xffff;
    SPU_KEY_OFF_HIGH = 0xffff;
    spu_busy_wait(800000);

    spu_wait_status_bit11_flip();
    spu_voice1_keyon(SPU_UPLOAD_ADDR, pitch);
    spu_wait_status_bit11_flip();
    spu_read_sync(0x0800, s_capture, 1024);
}

static void spu_adpcm_edge_stop(void) {
    SPU_KEY_OFF_LOW = 0xffff;
    SPU_KEY_OFF_HIGH = 0xffff;
    muteSpu();
}
)

#ifdef SPU_DUMP
#define SPU_ADPCM_EDGE_ASSERT_GOLDEN(name) spu_dump_pcm(#name ".test.pcm", s_capture, 1024)
#elif SPU_ADPCM_EDGE_GOLDENS_AVAILABLE
#define SPU_ADPCM_EDGE_ASSERT_GOLDEN(name) \
    do { \
        extern const uint8_t name[]; \
        cester_assert_int_eq(0, spu_compare_golden(#name, s_capture, name)); \
    } while (0)
#else
#define SPU_ADPCM_EDGE_ASSERT_GOLDEN(name) spu_adpcm_edge_observe(#name)
#endif

#define SPU_ADPCM_EDGE_TEST_PREDICTOR(N) \
CESTER_TEST(adpcm_edge_predictor_##N, spu_tests, \
    uint8_t sample[64]; \
    spu_adpcm_edge_block(sample, 0, ((N) << 4) | 4, 0x04, kEdgeMixed); \
    spu_adpcm_edge_block(sample, 1, ((N) << 4) | 4, 0x00, kEdgeRamp); \
    spu_adpcm_edge_block(sample, 2, ((N) << 4) | 4, 0x00, kEdgeZero); \
    spu_adpcm_edge_block(sample, 3, ((N) << 4) | 4, 0x03, kEdgeAlternating); \
    run_voice1_with_sample(sample, 0x1000); \
    SPU_ADPCM_EDGE_ASSERT_GOLDEN(adpcm_edge_predictor_##N); \
)

SPU_ADPCM_EDGE_TEST_PREDICTOR(0)
SPU_ADPCM_EDGE_TEST_PREDICTOR(1)
SPU_ADPCM_EDGE_TEST_PREDICTOR(2)
SPU_ADPCM_EDGE_TEST_PREDICTOR(3)
SPU_ADPCM_EDGE_TEST_PREDICTOR(4)

CESTER_TEST(adpcm_edge_shift_00_03, spu_tests,
    uint8_t sample[64];
    spu_adpcm_edge_block(sample, 0, 0x00, 0x04, kEdgeAlternating);
    spu_adpcm_edge_block(sample, 1, 0x01, 0x00, kEdgeAlternating);
    spu_adpcm_edge_block(sample, 2, 0x02, 0x00, kEdgeAlternating);
    spu_adpcm_edge_block(sample, 3, 0x03, 0x03, kEdgeAlternating);
    run_voice1_with_sample(sample, 0x1000);
    SPU_ADPCM_EDGE_ASSERT_GOLDEN(adpcm_edge_shift_00_03);
)

CESTER_TEST(adpcm_edge_shift_04_07, spu_tests,
    uint8_t sample[64];
    spu_adpcm_edge_block(sample, 0, 0x04, 0x04, kEdgeAlternating);
    spu_adpcm_edge_block(sample, 1, 0x05, 0x00, kEdgeAlternating);
    spu_adpcm_edge_block(sample, 2, 0x06, 0x00, kEdgeAlternating);
    spu_adpcm_edge_block(sample, 3, 0x07, 0x03, kEdgeAlternating);
    run_voice1_with_sample(sample, 0x1000);
    SPU_ADPCM_EDGE_ASSERT_GOLDEN(adpcm_edge_shift_04_07);
)

CESTER_TEST(adpcm_edge_shift_08_11, spu_tests,
    uint8_t sample[64];
    spu_adpcm_edge_block(sample, 0, 0x08, 0x04, kEdgeAlternating);
    spu_adpcm_edge_block(sample, 1, 0x09, 0x00, kEdgeAlternating);
    spu_adpcm_edge_block(sample, 2, 0x0a, 0x00, kEdgeAlternating);
    spu_adpcm_edge_block(sample, 3, 0x0b, 0x03, kEdgeAlternating);
    run_voice1_with_sample(sample, 0x1000);
    SPU_ADPCM_EDGE_ASSERT_GOLDEN(adpcm_edge_shift_08_11);
)

CESTER_TEST(adpcm_edge_shift_12_15, spu_tests,
    uint8_t sample[64];
    spu_adpcm_edge_block(sample, 0, 0x0c, 0x04, kEdgeAlternating);
    spu_adpcm_edge_block(sample, 1, 0x0d, 0x00, kEdgeAlternating);
    spu_adpcm_edge_block(sample, 2, 0x0e, 0x00, kEdgeAlternating);
    spu_adpcm_edge_block(sample, 3, 0x0f, 0x03, kEdgeAlternating);
    run_voice1_with_sample(sample, 0x1000);
    SPU_ADPCM_EDGE_ASSERT_GOLDEN(adpcm_edge_shift_12_15);
)

CESTER_TEST(adpcm_edge_state_carry, spu_tests,
    uint8_t sample[64];
    spu_adpcm_edge_block(sample, 0, 0x00, 0x04, kEdgePositive);
    spu_adpcm_edge_block(sample, 1, 0x44, 0x00, kEdgeZero);
    spu_adpcm_edge_block(sample, 2, 0x44, 0x00, kEdgeZero);
    spu_adpcm_edge_block(sample, 3, 0x44, 0x03, kEdgeZero);
    run_voice1_with_sample(sample, 0x1000);
    SPU_ADPCM_EDGE_ASSERT_GOLDEN(adpcm_edge_state_carry);
)

CESTER_TEST(adpcm_edge_saturation_positive, spu_tests,
    uint8_t sample[64];
    for (int i = 0; i < 4; i++)
        spu_adpcm_edge_block(sample, i, 0x40, i == 0 ? 0x04 : (i == 3 ? 0x03 : 0x00), kEdgePositive);
    run_voice1_with_sample(sample, 0x1000);
    SPU_ADPCM_EDGE_ASSERT_GOLDEN(adpcm_edge_saturation_positive);
)

CESTER_TEST(adpcm_edge_saturation_negative, spu_tests,
    uint8_t sample[64];
    for (int i = 0; i < 4; i++)
        spu_adpcm_edge_block(sample, i, 0x40, i == 0 ? 0x04 : (i == 3 ? 0x03 : 0x00), kEdgeNegative);
    run_voice1_with_sample(sample, 0x1000);
    SPU_ADPCM_EDGE_ASSERT_GOLDEN(adpcm_edge_saturation_negative);
)

CESTER_TEST(adpcm_edge_flag_code2_ignored, spu_tests,
    uint8_t sample[64];
    spu_adpcm_edge_block(sample, 0, 0x04, 0x04, kEdgeRamp);
    spu_adpcm_edge_block(sample, 1, 0x04, 0x02, kEdgePositive);
    spu_adpcm_edge_block(sample, 2, 0x04, 0x00, kEdgeNegative);
    spu_adpcm_edge_block(sample, 3, 0x04, 0x03, kEdgeZero);
    run_voice1_with_sample(sample, 0x1000);
    SPU_ADPCM_EDGE_ASSERT_GOLDEN(adpcm_edge_flag_code2_ignored);
)

CESTER_TEST(adpcm_edge_flag_loop_start_latch, spu_tests,
    uint8_t sample[64];
    spu_adpcm_edge_block(sample, 0, 0x04, 0x00, kEdgePositive);
    spu_adpcm_edge_block(sample, 1, 0x04, 0x04, kEdgeRamp);
    spu_adpcm_edge_block(sample, 2, 0x04, 0x00, kEdgeNegative);
    spu_adpcm_edge_block(sample, 3, 0x04, 0x03, kEdgeZero);
    spu_adpcm_edge_run_capture_keep_on(sample, 0x1000);
    SPU_ADPCM_EDGE_ASSERT_GOLDEN(adpcm_edge_flag_loop_start_latch);
    spu_adpcm_edge_expect_u32("repeat_loop_start",
        SPU_ADPCM_EDGE_EXPECTED_REPEAT_LOOP_START, SPU_VOICES[1].sampleRepeatAddr);
    spu_adpcm_edge_stop();
)

CESTER_TEST(adpcm_edge_flag_end_mute, spu_tests,
    uint8_t sample[64];
    spu_adpcm_edge_block(sample, 0, 0x04, 0x04, kEdgePositive);
    spu_adpcm_edge_block(sample, 1, 0x04, 0x01, kEdgeNegative);
    spu_adpcm_edge_block(sample, 2, 0x04, 0x00, kEdgePositive);
    spu_adpcm_edge_block(sample, 3, 0x04, 0x03, kEdgePositive);
    spu_adpcm_edge_run_capture_keep_on(sample, 0x1000);
    spu_busy_wait(800000);
    SPU_ADPCM_EDGE_ASSERT_GOLDEN(adpcm_edge_flag_end_mute);
    spu_adpcm_edge_expect_u32("repeat_end_mute",
        SPU_ADPCM_EDGE_EXPECTED_REPEAT_END_MUTE, SPU_VOICES[1].sampleRepeatAddr);
    spu_adpcm_edge_expect_u32("endx_end_mute",
        SPU_ADPCM_EDGE_EXPECTED_ENDX_END_MUTE, (SPU_ENDX_LOW >> 1) & 1);
    spu_adpcm_edge_expect_u32("envx_end_mute",
        SPU_ADPCM_EDGE_EXPECTED_ENVX_END_MUTE, SPU_VOICES[1].currentVolume);
    spu_adpcm_edge_stop();
)

CESTER_TEST(adpcm_edge_flag_end_repeat, spu_tests,
    uint8_t sample[64];
    spu_adpcm_edge_block(sample, 0, 0x04, 0x04, kEdgePositive);
    spu_adpcm_edge_block(sample, 1, 0x04, 0x03, kEdgeNegative);
    spu_adpcm_edge_block(sample, 2, 0x04, 0x00, kEdgePositive);
    spu_adpcm_edge_block(sample, 3, 0x04, 0x03, kEdgePositive);
    spu_adpcm_edge_run_capture_keep_on(sample, 0x1000);
    spu_busy_wait(800000);
    SPU_ADPCM_EDGE_ASSERT_GOLDEN(adpcm_edge_flag_end_repeat);
    spu_adpcm_edge_expect_u32("endx_end_repeat",
        SPU_ADPCM_EDGE_EXPECTED_ENDX_END_REPEAT, (SPU_ENDX_LOW >> 1) & 1);
    spu_adpcm_edge_expect_u32("envx_end_repeat",
        SPU_ADPCM_EDGE_EXPECTED_ENVX_END_REPEAT, SPU_VOICES[1].currentVolume);
    spu_adpcm_edge_stop();
)

CESTER_TEST(adpcm_edge_invalid_predictor_5_7, spu_tests,
    uint8_t sample[64];
    spu_adpcm_edge_block(sample, 0, 0x54, 0x04, kEdgeMixed);
    spu_adpcm_edge_block(sample, 1, 0x64, 0x00, kEdgeRamp);
    spu_adpcm_edge_block(sample, 2, 0x74, 0x00, kEdgeAlternating);
    spu_adpcm_edge_block(sample, 3, 0xf4, 0x03, kEdgeZero);
    run_voice1_with_sample(sample, 0x1000);
    SPU_ADPCM_EDGE_ASSERT_GOLDEN(adpcm_edge_invalid_predictor_5_7);
)
