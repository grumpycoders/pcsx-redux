// ==========================================================================
// Validate ADSR envelope via currentVolume changes
// ==========================================================================

#define ATTACK(step, shift, exp) (\
    (((step) & 3) << 8) | \
    (((shift) & 31) << 10) | \
    (!!(exp) << 15))
#define DECAY(shift) (\
    (((shift) & 15) << 4))
#define SUSTAIN(step, shift, level, direction, exp) (\
    (((step) & 3) << 22) | \
    (((shift) & 31) << 24) | \
    (((level) & 15) << 0) | \
    (!!(direction) << 30) | \
    (!!(exp) << 31))
#define RELEASE(shift, exp) (\
    (((shift) & 31) << 16) | \
    (!!(exp) << 21))

CESTER_BODY(
// Given the envelope settings, spit out a currentVolume trace.
// To avoid jitter and interference, the captured output starts only when
// the volume changes from 0. The sample rate of the ENVX is a sample every
// spu_wait_status_bit11_flip call to try separating CPU clock from the
// SPU clock and increase chances of reproducibility.
static void spu_adsr_capture(
    uint32_t adsr,        // packed ADSR envelope (see ATTACK/DECAY/SUSTAIN/RELEASE macros)
    uint16_t* envx_out,   // output buffer; must be of length n_samples
    unsigned n_samples    // sample count to capture per SPU status bit11 flip
) {
    // drain volume from previous envelope key ON
    spu_reset_quiet();
    SPU_CTRL = 0x8000 | 0x4000;
    SPU_VOL_MAIN_LEFT = 0; SPU_VOL_MAIN_RIGHT = 0;
    SPU_KEY_OFF_LOW = 0xffff; SPU_KEY_OFF_HIGH = 0xffff;
    spu_wait_status_bit11_flip();
    while (SPU_VOICES[1].currentVolume != 0) ;

    // prepare envelope, wait for bit11 flip, then fire voice!
    SPU_VOICES[1].sampleRate = 0x1000;
    SPU_VOICES[1].sampleStartAddr = SPU_UPLOAD_ADDR >> 3;
    SPU_VOICES[1].sampleRepeatAddr = SPU_UPLOAD_ADDR >> 3;
    SPU_VOICES[1].volumeLeft = 0;
    SPU_VOICES[1].volumeRight = 0;
    spu_wait_status_bit11_flip();
    SPU_VOICES[1].adsrLo = (uint16_t)(adsr & 0xFFFF);
    SPU_VOICES[1].adsrHi = (uint16_t)(adsr >> 16);
    SPU_KEY_OFF_LOW = 0; SPU_KEY_OFF_HIGH = 0;
    SPU_KEY_ON_LOW = 1u << 1;

    // synchronize SPU by waiting currentVolume to change
    while (SPU_VOICES[1].currentVolume == 0) ;

    // now capture one sample every bit11 flip
    envx_out[0] = SPU_VOICES[1].currentVolume;
    for (unsigned i = 1; i < n_samples; i++) {
        spu_wait_status_bit11_flip();
        envx_out[i] = SPU_VOICES[1].currentVolume;
    }

    // key off, we finished here
    SPU_KEY_OFF_LOW = 0xffff; SPU_KEY_OFF_HIGH = 0xffff;
    muteSpu();
}

static void spu_adsr_capture_with_keyoff(
    uint32_t adsr,
    uint16_t* envx_out,
    unsigned n_samples,
    unsigned keyoff_at
) {
    spu_adsr_capture(adsr, envx_out, keyoff_at + 1);
    for (unsigned i = keyoff_at + 1; i < n_samples; i++) {
        spu_wait_status_bit11_flip();
        envx_out[i] = SPU_VOICES[1].currentVolume;
    }
}
)

// testing an envelope with the current capturing technique in spu_adsr_capture
// does not lead to exact reproducible samples due to some minor timing
// differences between the CPU polling and the produced SPU results.
// The value step is a delta used as margin of error.
#define ASSERT_ENVX_NEAR(nominal, step, got) \
    cester_assert_true((got) >= (uint16_t)((nominal) - (step)) && \
                       (got) <= (uint16_t)((nominal) + (step)))

CESTER_TEST(adsr_attack_linear_step, spu_tests,
    int i;
    uint16_t envx[0x40];

    const uint32_t base = DECAY(0) | SUSTAIN(3, 0x1f, 15, 0, 0) | RELEASE(0, 0);

    spu_adsr_capture(ATTACK(2, 12, 0) | base, envx, 4);
    cester_assert_uint_eq(0x0005, envx[0]);
    ASSERT_ENVX_NEAR(0x04f1, 5, envx[1]);
    ASSERT_ENVX_NEAR(0x09f1, 5, envx[2]);
    ASSERT_ENVX_NEAR(0x0ef1, 5, envx[3]);

    spu_adsr_capture(ATTACK(3, 12, 0) | base, envx, 4);
    cester_assert_uint_eq(0x0004, envx[0]);
    ASSERT_ENVX_NEAR(0x03f4, 4, envx[1]);
    ASSERT_ENVX_NEAR(0x07f4, 4, envx[2]);
    ASSERT_ENVX_NEAR(0x0bf4, 4, envx[3]);

    spu_adsr_capture(ATTACK(2, 24, 0) | base, envx, 48);
    for (i = 0; i < 17; i++)
        cester_assert_uint_eq(0x0005, envx[i]);
    for (i = 17; i < 33; i++)
        cester_assert_uint_eq(0x000a, envx[i]);
    for (i = 33; i < 48; i++)
        cester_assert_uint_eq(0x000f, envx[i]);

    spu_adsr_capture(ATTACK(3, 24, 0) | base, envx, 48);
    for (i = 0; i < 17; i++)
        cester_assert_uint_eq(0x0004, envx[i]);
    for (i = 17; i < 33; i++)
        cester_assert_uint_eq(0x0008, envx[i]);
    for (i = 33; i < 48; i++)
        cester_assert_uint_eq(0x000c, envx[i]);
)

CESTER_TEST(adsr_attack_linear_shift, spu_tests,
    int i;
    uint16_t envx[0x40];

    const uint32_t base = DECAY(0) | SUSTAIN(3, 0x1f, 15, 0, 0) | RELEASE(0, 0);

    spu_adsr_capture(ATTACK(0, 0, 0) | base, envx, 1);
    cester_assert_uint_eq(0x3800, envx[0]);

    spu_adsr_capture(ATTACK(1, 0, 0) | base, envx, 1);
    cester_assert_uint_eq(0x3000, envx[0]);

    spu_adsr_capture(ATTACK(0, 11, 0) | base, envx, 4);
    cester_assert_uint_eq(0x0007, envx[0]);
    ASSERT_ENVX_NEAR(0x0dcf, 7, envx[1]);
    ASSERT_ENVX_NEAR(0x1bcf, 7, envx[2]);
    ASSERT_ENVX_NEAR(0x29cf, 7, envx[3]);

    spu_adsr_capture(ATTACK(1, 11, 0) | base, envx, 4);
    cester_assert_uint_eq(0x0006, envx[0]);
    ASSERT_ENVX_NEAR(0x0bdc, 7, envx[1]);
    ASSERT_ENVX_NEAR(0x17d6, 7, envx[2]);
    ASSERT_ENVX_NEAR(0x23d6, 7, envx[3]);

    spu_adsr_capture(ATTACK(0, 12, 0) | base, envx, 32);
    cester_assert_uint_eq(0x0007, envx[0]);
    ASSERT_ENVX_NEAR(0x06e4, 7, envx[1]);
    ASSERT_ENVX_NEAR(0x0de4, 7, envx[2]);
    ASSERT_ENVX_NEAR(0x14e4, 7, envx[3]);
    ASSERT_ENVX_NEAR(0x1be4, 7, envx[4]);
    ASSERT_ENVX_NEAR(0x22e4, 7, envx[5]);
    ASSERT_ENVX_NEAR(0x29e4, 7, envx[6]);
    ASSERT_ENVX_NEAR(0x30e4, 7, envx[7]);
    ASSERT_ENVX_NEAR(0x37e4, 7, envx[8]);
    ASSERT_ENVX_NEAR(0x3ee4, 7, envx[9]);
    ASSERT_ENVX_NEAR(0x45e4, 7, envx[10]);
    ASSERT_ENVX_NEAR(0x4ce4, 7, envx[11]);
    ASSERT_ENVX_NEAR(0x53e4, 7, envx[12]);
    ASSERT_ENVX_NEAR(0x5ae4, 7, envx[13]);
    ASSERT_ENVX_NEAR(0x61e4, 7, envx[14]);
    ASSERT_ENVX_NEAR(0x68e4, 7, envx[15]);
    ASSERT_ENVX_NEAR(0x6fe4, 7, envx[16]);
    ASSERT_ENVX_NEAR(0x76e4, 7, envx[17]);
    ASSERT_ENVX_NEAR(0x7de4, 7, envx[18]);

    spu_adsr_capture(ATTACK(1, 12, 0) | base, envx, 4);
    cester_assert_uint_eq(0x0006, envx[0]);
    ASSERT_ENVX_NEAR(0x05ee, 6, envx[1]);
    ASSERT_ENVX_NEAR(0x0bee, 6, envx[2]);
    ASSERT_ENVX_NEAR(0x11ee, 6, envx[3]);

    spu_adsr_capture(ATTACK(0, 23, 0) | base, envx, 48);
    for (i = 0; i < 9; i++)
        cester_assert_uint_eq(0x0007, envx[i]);
    for (i = 9; i < 17; i++)
        cester_assert_uint_eq(0x000e, envx[i]);
    for (i = 17; i < 25; i++)
        cester_assert_uint_eq(0x0015, envx[i]);
    for (i = 25; i < 33; i++)
        cester_assert_uint_eq(0x001c, envx[i]);
    for (i = 33; i < 41; i++)
        cester_assert_uint_eq(0x0023, envx[i]);
    for (i = 41; i < 48; i++)
        cester_assert_uint_eq(0x002a, envx[i]);

    spu_adsr_capture(ATTACK(1, 23, 0) | base, envx, 48);
    for (i = 0; i < 9; i++)
        cester_assert_uint_eq(0x0006, envx[i]);
    for (i = 9; i < 17; i++)
        cester_assert_uint_eq(0x000c, envx[i]);
    for (i = 17; i < 25; i++)
        cester_assert_uint_eq(0x0012, envx[i]);
    for (i = 25; i < 33; i++)
        cester_assert_uint_eq(0x0018, envx[i]);
    for (i = 33; i < 41; i++)
        cester_assert_uint_eq(0x001e, envx[i]);
    for (i = 41; i < 48; i++)
        cester_assert_uint_eq(0x0024, envx[i]);

    spu_adsr_capture(ATTACK(0, 24, 0) | base, envx, 48);
    for (i = 0; i < 17; i++)
        cester_assert_uint_eq(0x0007, envx[i]);
    for (i = 17; i < 33; i++)
        cester_assert_uint_eq(0x000e, envx[i]);
    for (i = 33; i < 48; i++)
        cester_assert_uint_eq(0x0015, envx[i]);

    spu_adsr_capture(ATTACK(1, 24, 0) | base, envx, 48);
    for (i = 0; i < 17; i++)
        cester_assert_uint_eq(0x0006, envx[i]);
    for (i = 17; i < 33; i++)
        cester_assert_uint_eq(0x000c, envx[i]);
    for (i = 33; i < 48; i++)
        cester_assert_uint_eq(0x0012, envx[i]);
)

// Above ENVX 0x6000, exponential attack right-shifts AddStep by 2 (delta /= 4),
// stretching the tail. Below 0x6000 it is bit-identical to linear.
CESTER_TEST(adsr_attack_exponential, spu_tests,
    uint16_t envx[0x40];

    const uint32_t base = DECAY(0) | SUSTAIN(3, 0x1f, 15, 0, 0) | RELEASE(0, 0);

    spu_adsr_capture(ATTACK(0, 12, 1) | base, envx, 32);
    cester_assert_uint_eq(0x0007, envx[0]);
    ASSERT_ENVX_NEAR(0x06e4, 7, envx[1]);
    ASSERT_ENVX_NEAR(0x0de4, 7, envx[2]);
    ASSERT_ENVX_NEAR(0x14e4, 7, envx[3]);
    ASSERT_ENVX_NEAR(0x1be4, 7, envx[4]);
    ASSERT_ENVX_NEAR(0x22e4, 7, envx[5]);
    ASSERT_ENVX_NEAR(0x29e4, 7, envx[6]);
    ASSERT_ENVX_NEAR(0x30e4, 7, envx[7]);
    ASSERT_ENVX_NEAR(0x37e4, 7, envx[8]);
    ASSERT_ENVX_NEAR(0x3ee4, 7, envx[9]);
    ASSERT_ENVX_NEAR(0x45e4, 7, envx[10]);
    ASSERT_ENVX_NEAR(0x4ce4, 7, envx[11]);
    ASSERT_ENVX_NEAR(0x53e4, 7, envx[12]);
    ASSERT_ENVX_NEAR(0x5ae4, 7, envx[13]);
    ASSERT_ENVX_NEAR(0x607f, 7, envx[14]);
    ASSERT_ENVX_NEAR(0x623f, 7, envx[15]);
    ASSERT_ENVX_NEAR(0x63ff, 7, envx[16]);
    ASSERT_ENVX_NEAR(0x65bf, 7, envx[17]);
    ASSERT_ENVX_NEAR(0x677f, 7, envx[18]);
    ASSERT_ENVX_NEAR(0x693f, 7, envx[19]);
    ASSERT_ENVX_NEAR(0x6aff, 7, envx[20]);
    ASSERT_ENVX_NEAR(0x6cbf, 7, envx[21]);
    ASSERT_ENVX_NEAR(0x6e7f, 7, envx[22]);
    ASSERT_ENVX_NEAR(0x703f, 7, envx[23]);
    ASSERT_ENVX_NEAR(0x71ff, 7, envx[24]);
    ASSERT_ENVX_NEAR(0x73bf, 7, envx[25]);
    ASSERT_ENVX_NEAR(0x757f, 7, envx[26]);
    ASSERT_ENVX_NEAR(0x773f, 7, envx[27]);
    ASSERT_ENVX_NEAR(0x78ff, 7, envx[28]);
    ASSERT_ENVX_NEAR(0x7abf, 7, envx[29]);
    ASSERT_ENVX_NEAR(0x7c7f, 7, envx[30]);
    ASSERT_ENVX_NEAR(0x7e3f, 7, envx[31]);
)

// test decay rate after attack peaks; higher value means slower decay
CESTER_TEST(adsr_decay_shift, spu_tests,
    uint16_t envx[0x40];

    spu_adsr_capture(
        ATTACK(0, 1, 0) | DECAY(10) | SUSTAIN(0, 0, 0, 1, 0) | RELEASE(0, 1),
        envx, 16);
    cester_assert_uint_eq(0x1c00, envx[0]);
    ASSERT_ENVX_NEAR(0x6370, 0x07, envx[1]);
    ASSERT_ENVX_NEAR(0x4c95, 0x05, envx[2]);
    ASSERT_ENVX_NEAR(0x3ac6, 0x04, envx[3]);
    ASSERT_ENVX_NEAR(0x2cef, 0x03, envx[4]);
    ASSERT_ENVX_NEAR(0x221c, 0x03, envx[5]);
    ASSERT_ENVX_NEAR(0x19b0, 0x02, envx[6]);
    ASSERT_ENVX_NEAR(0x1343, 0x02, envx[7]);
    ASSERT_ENVX_NEAR(0x0e2d, 0x01, envx[8]);
    ASSERT_ENVX_NEAR(0x0a2d, 0x01, envx[9]);
    for (unsigned i = 10; i < 16; i++)
        cester_assert_uint_eq(0x0000, envx[i]);

    spu_adsr_capture(
        ATTACK(0, 1, 0) | DECAY(12) | SUSTAIN(0, 0, 0, 1, 0) | RELEASE(0, 1),
        envx, 32);
    cester_assert_uint_eq(0x1c00, envx[0]);
    ASSERT_ENVX_NEAR(0x782b, 0x04, envx[1]);
    ASSERT_ENVX_NEAR(0x702b, 0x04, envx[2]);
    ASSERT_ENVX_NEAR(0x6925, 0x04, envx[3]);
    ASSERT_ENVX_NEAR(0x6225, 0x04, envx[4]);
    ASSERT_ENVX_NEAR(0x5bd7, 0x03, envx[5]);
    ASSERT_ENVX_NEAR(0x55d7, 0x03, envx[6]);
    ASSERT_ENVX_NEAR(0x4fdd, 0x03, envx[7]);
    ASSERT_ENVX_NEAR(0x4add, 0x03, envx[8]);
    ASSERT_ENVX_NEAR(0x45dd, 0x03, envx[9]);
    ASSERT_ENVX_NEAR(0x40dd, 0x03, envx[10]);
    ASSERT_ENVX_NEAR(0x3cb1, 0x02, envx[11]);
    ASSERT_ENVX_NEAR(0x38b1, 0x02, envx[12]);
    ASSERT_ENVX_NEAR(0x34b1, 0x02, envx[13]);
    ASSERT_ENVX_NEAR(0x30b1, 0x02, envx[14]);
    ASSERT_ENVX_NEAR(0x2d84, 0x02, envx[15]);
    ASSERT_ENVX_NEAR(0x2a84, 0x02, envx[16]);
    ASSERT_ENVX_NEAR(0x2784, 0x02, envx[17]);
    ASSERT_ENVX_NEAR(0x2484, 0x02, envx[18]);
    ASSERT_ENVX_NEAR(0x2184, 0x02, envx[19]);
    ASSERT_ENVX_NEAR(0x1f03, 0x01, envx[20]);
    ASSERT_ENVX_NEAR(0x1d03, 0x01, envx[21]);
    ASSERT_ENVX_NEAR(0x1b03, 0x01, envx[22]);
    ASSERT_ENVX_NEAR(0x1903, 0x02, envx[23]);
    ASSERT_ENVX_NEAR(0x1703, 0x01, envx[24]);
    ASSERT_ENVX_NEAR(0x1503, 0x01, envx[25]);
    ASSERT_ENVX_NEAR(0x1303, 0x01, envx[26]);
    ASSERT_ENVX_NEAR(0x1103, 0x01, envx[27]);
    ASSERT_ENVX_NEAR(0x0f81, 0x01, envx[28]);
    ASSERT_ENVX_NEAR(0x0e81, 0x01, envx[29]);
    ASSERT_ENVX_NEAR(0x0d81, 0x01, envx[30]);
    ASSERT_ENVX_NEAR(0x0c81, 0x01, envx[31]);

    spu_adsr_capture(
        ATTACK(0, 1, 0) | DECAY(14) | SUSTAIN(0, 0, 0, 1, 0) | RELEASE(0, 1),
        envx, 32);
    cester_assert_uint_eq(0x1c00, envx[0]);
    ASSERT_ENVX_NEAR(0x7e05, 0x02, envx[1]);
    ASSERT_ENVX_NEAR(0x7c05, 0x02, envx[2]);
    ASSERT_ENVX_NEAR(0x7805, 0x02, envx[4]);
    ASSERT_ENVX_NEAR(0x7405, 0x02, envx[6]);
    ASSERT_ENVX_NEAR(0x7005, 0x02, envx[8]);
    ASSERT_ENVX_NEAR(0x6906, 0x02, envx[12]);
    ASSERT_ENVX_NEAR(0x6206, 0x02, envx[16]);
    ASSERT_ENVX_NEAR(0x5bba, 0x02, envx[20]);
    ASSERT_ENVX_NEAR(0x55ba, 0x02, envx[24]);
    ASSERT_ENVX_NEAR(0x4fc7, 0x02, envx[28]);
    ASSERT_ENVX_NEAR(0x4c05, 0x02, envx[31]);
)

// test to which volume level the voice sits on key on sustain
CESTER_TEST(adsr_sustain_level, spu_tests,
    uint16_t envx[16];

    spu_adsr_capture(
        ATTACK(0, 1, 0) | DECAY(10) | SUSTAIN(3, 0x1f, 0, 1, 0) | RELEASE(0, 1),
        envx, 16);
    for (unsigned i = 10; i < 16; i++)
        cester_assert_uint_eq(0x07ff, envx[i]);

    spu_adsr_capture(
        ATTACK(0, 1, 0) | DECAY(10) | SUSTAIN(3, 0x1f, 7, 1, 0) | RELEASE(0, 1),
        envx, 16);
    for (unsigned i = 3; i < 16; i++)
        cester_assert_uint_eq(0x3ffa, envx[i]);

    spu_adsr_capture(
        ATTACK(0, 1, 0) | DECAY(10) | SUSTAIN(3, 0x1f, 11, 1, 0) | RELEASE(0, 1),
        envx, 16);
    for (unsigned i = 2; i < 16; i++)
        cester_assert_uint_eq(0x5ff6, envx[i]);

    spu_adsr_capture(
        ATTACK(0, 1, 0) | DECAY(10) | SUSTAIN(3, 0x1f, 14, 1, 0) | RELEASE(0, 1),
        envx, 16);
    for (unsigned i = 1; i < 16; i++)
        cester_assert_uint_eq(0x77ff, envx[i]);

    spu_adsr_capture(
        ATTACK(0, 1, 0) | DECAY(10) | SUSTAIN(3, 0x1f, 15, 1, 0) | RELEASE(0, 1),
        envx, 16);
    for (unsigned i = 1; i < 16; i++)
        cester_assert_uint_eq(0x7fef, envx[i]);
)

// sustain at various levels while direction scale positive linearly
CESTER_TEST(adsr_sustain_up_linear, spu_tests,
    uint16_t envx[0x20];

    spu_adsr_capture(
        ATTACK(0, 1, 0) | DECAY(0) | SUSTAIN(0, 10, 15, 0, 0) | RELEASE(0, 1),
        envx, 8);
    cester_assert_uint_eq(0x1c00, envx[0]);
    ASSERT_ENVX_NEAR(0x5b50, 0x07, envx[1]);
    ASSERT_ENVX_NEAR(0x7750, 0x07, envx[2]);
    for (unsigned i = 3; i < 8; i++)
        cester_assert_uint_eq(0x7fff, envx[i]);

    spu_adsr_capture(
        ATTACK(0, 1, 0) | DECAY(0) | SUSTAIN(3, 10, 15, 0, 0) | RELEASE(0, 1),
        envx, 8);
    cester_assert_uint_eq(0x1c00, envx[0]);
    ASSERT_ENVX_NEAR(0x4f9b, 0x04, envx[1]);
    ASSERT_ENVX_NEAR(0x5f9b, 0x04, envx[2]);
    ASSERT_ENVX_NEAR(0x6f9b, 0x04, envx[3]);
    ASSERT_ENVX_NEAR(0x7f9b, 0x04, envx[4]);
    for (unsigned i = 5; i < 8; i++)
        cester_assert_uint_eq(0x7fff, envx[i]);

    spu_adsr_capture(
        ATTACK(0, 1, 0) | DECAY(0) | SUSTAIN(0, 12, 15, 0, 0) | RELEASE(0, 1),
        envx, 16);
    cester_assert_uint_eq(0x1c00, envx[0]);
    ASSERT_ENVX_NEAR(0x46d1, 0x04, envx[1]);
    ASSERT_ENVX_NEAR(0x4dd1, 0x04, envx[2]);
    ASSERT_ENVX_NEAR(0x54d1, 0x04, envx[3]);
    ASSERT_ENVX_NEAR(0x5bd1, 0x04, envx[4]);
    ASSERT_ENVX_NEAR(0x62d1, 0x04, envx[5]);
    ASSERT_ENVX_NEAR(0x69d1, 0x04, envx[6]);
    ASSERT_ENVX_NEAR(0x70d1, 0x04, envx[7]);
    ASSERT_ENVX_NEAR(0x77d1, 0x04, envx[8]);
    ASSERT_ENVX_NEAR(0x7ed1, 0x04, envx[9]);
    for (unsigned i = 10; i < 16; i++)
        cester_assert_uint_eq(0x7fff, envx[i]);

    spu_adsr_capture(
        ATTACK(0, 1, 0) | DECAY(0) | SUSTAIN(0, 14, 15, 0, 0) | RELEASE(0, 1),
        envx, 32);
    cester_assert_uint_eq(0x1c00, envx[0]);
    ASSERT_ENVX_NEAR(0x41b8, 0x02, envx[1]);
    ASSERT_ENVX_NEAR(0x4378, 0x02, envx[2]);
    ASSERT_ENVX_NEAR(0x46f8, 0x02, envx[4]);
    ASSERT_ENVX_NEAR(0x4df8, 0x02, envx[8]);
    ASSERT_ENVX_NEAR(0x54f8, 0x02, envx[12]);
    ASSERT_ENVX_NEAR(0x5bf8, 0x02, envx[16]);
    ASSERT_ENVX_NEAR(0x62f8, 0x02, envx[20]);
    ASSERT_ENVX_NEAR(0x69f8, 0x02, envx[24]);
    ASSERT_ENVX_NEAR(0x70f8, 0x02, envx[28]);
    ASSERT_ENVX_NEAR(0x7638, 0x02, envx[31]);

    spu_adsr_capture(
        ATTACK(0, 1, 0) | DECAY(0) | SUSTAIN(0, 16, 15, 0, 0) | RELEASE(0, 1),
        envx, 32);
    cester_assert_uint_eq(0x1c00, envx[0]);
    ASSERT_ENVX_NEAR(0x4068, 0x02, envx[1]);
    ASSERT_ENVX_NEAR(0x4228, 0x02, envx[5]);
    ASSERT_ENVX_NEAR(0x4458, 0x02, envx[10]);
    ASSERT_ENVX_NEAR(0x4688, 0x02, envx[15]);
    ASSERT_ENVX_NEAR(0x48b8, 0x02, envx[20]);
    ASSERT_ENVX_NEAR(0x4ae8, 0x02, envx[25]);
    ASSERT_ENVX_NEAR(0x4d88, 0x02, envx[31]);
)

// sustain at various levels while direction scale negative linearly
CESTER_TEST(adsr_sustain_down_linear, spu_tests,
    uint16_t envx[0x20];

    spu_adsr_capture(
        ATTACK(0, 1, 0) | DECAY(0) | SUSTAIN(3, 10, 15, 1, 0) | RELEASE(0, 1),
        envx, 8);
    cester_assert_uint_eq(0x1c00, envx[0]);
    ASSERT_ENVX_NEAR(0x2c7c, 0x05, envx[1]);
    ASSERT_ENVX_NEAR(0x187c, 0x05, envx[2]);
    ASSERT_ENVX_NEAR(0x047c, 0x05, envx[3]);
    for (unsigned i = 4; i < 8; i++)
        cester_assert_uint_eq(0x0000, envx[i]);

    spu_adsr_capture(
        ATTACK(0, 1, 0) | DECAY(0) | SUSTAIN(0, 12, 15, 1, 0) | RELEASE(0, 1),
        envx, 16);
    cester_assert_uint_eq(0x1c00, envx[0]);
    ASSERT_ENVX_NEAR(0x3833, 0x04, envx[1]);
    ASSERT_ENVX_NEAR(0x3033, 0x04, envx[2]);
    ASSERT_ENVX_NEAR(0x2833, 0x04, envx[3]);
    ASSERT_ENVX_NEAR(0x2033, 0x04, envx[4]);
    ASSERT_ENVX_NEAR(0x1833, 0x04, envx[5]);
    ASSERT_ENVX_NEAR(0x1033, 0x04, envx[6]);
    ASSERT_ENVX_NEAR(0x0833, 0x04, envx[7]);
    ASSERT_ENVX_NEAR(0x0033, 0x04, envx[8]);
    for (unsigned i = 9; i < 16; i++)
        cester_assert_uint_eq(0x0000, envx[i]);

    spu_adsr_capture(
        ATTACK(0, 1, 0) | DECAY(0) | SUSTAIN(0, 14, 15, 1, 0) | RELEASE(0, 1),
        envx, 32);
    cester_assert_uint_eq(0x1c00, envx[0]);
    ASSERT_ENVX_NEAR(0x3e05, 0x02, envx[1]);
    ASSERT_ENVX_NEAR(0x3c05, 0x02, envx[2]);
    ASSERT_ENVX_NEAR(0x3805, 0x02, envx[4]);
    ASSERT_ENVX_NEAR(0x3005, 0x02, envx[8]);
    ASSERT_ENVX_NEAR(0x2805, 0x02, envx[12]);
    ASSERT_ENVX_NEAR(0x2005, 0x02, envx[16]);
    ASSERT_ENVX_NEAR(0x1805, 0x02, envx[20]);
    ASSERT_ENVX_NEAR(0x1005, 0x02, envx[24]);
    ASSERT_ENVX_NEAR(0x0805, 0x02, envx[28]);
    ASSERT_ENVX_NEAR(0x0205, 0x02, envx[31]);

    spu_adsr_capture(
        ATTACK(0, 1, 0) | DECAY(0) | SUSTAIN(0, 16, 15, 1, 0) | RELEASE(0, 1),
        envx, 32);
    cester_assert_uint_eq(0x1c00, envx[0]);
    ASSERT_ENVX_NEAR(0x3f85, 0x02, envx[1]);
    ASSERT_ENVX_NEAR(0x3e85, 0x02, envx[3]);
    ASSERT_ENVX_NEAR(0x3d05, 0x02, envx[6]);
    ASSERT_ENVX_NEAR(0x3b85, 0x02, envx[9]);
    ASSERT_ENVX_NEAR(0x3a05, 0x02, envx[12]);
    ASSERT_ENVX_NEAR(0x3885, 0x02, envx[15]);
    ASSERT_ENVX_NEAR(0x3705, 0x02, envx[18]);
    ASSERT_ENVX_NEAR(0x3585, 0x02, envx[21]);
    ASSERT_ENVX_NEAR(0x3405, 0x02, envx[24]);
    ASSERT_ENVX_NEAR(0x3285, 0x02, envx[27]);
    ASSERT_ENVX_NEAR(0x3105, 0x02, envx[30]);
)

// sustain at various levels while direction scale positive exponentially
CESTER_TEST(adsr_sustain_up_exponential, spu_tests,
    uint16_t envx[0x20];

    spu_adsr_capture(
        ATTACK(0, 1, 0) | DECAY(0) | SUSTAIN(0, 12, 15, 0, 1) | RELEASE(0, 1),
        envx, 24);
    cester_assert_uint_eq(0x1c00, envx[0]);
    ASSERT_ENVX_NEAR(0x46d1, 0x04, envx[1]);
    ASSERT_ENVX_NEAR(0x4dd1, 0x04, envx[2]);
    ASSERT_ENVX_NEAR(0x54d1, 0x04, envx[3]);
    ASSERT_ENVX_NEAR(0x5bd1, 0x04, envx[4]);
    ASSERT_ENVX_NEAR(0x60ba, 0x02, envx[5]);
    ASSERT_ENVX_NEAR(0x627a, 0x02, envx[6]);
    ASSERT_ENVX_NEAR(0x643a, 0x02, envx[7]);
    ASSERT_ENVX_NEAR(0x65fa, 0x02, envx[8]);
    ASSERT_ENVX_NEAR(0x67ba, 0x02, envx[9]);
    ASSERT_ENVX_NEAR(0x6cfa, 0x02, envx[12]);
    ASSERT_ENVX_NEAR(0x73fa, 0x02, envx[16]);
    ASSERT_ENVX_NEAR(0x7afa, 0x02, envx[20]);
    cester_assert_uint_eq(0x7fff, envx[23]);

    spu_adsr_capture(
        ATTACK(0, 1, 0) | DECAY(0) | SUSTAIN(0, 14, 15, 0, 1) | RELEASE(0, 1),
        envx, 32);
    cester_assert_uint_eq(0x1c00, envx[0]);
    ASSERT_ENVX_NEAR(0x41b8, 0x02, envx[1]);
    ASSERT_ENVX_NEAR(0x4df8, 0x02, envx[8]);
    ASSERT_ENVX_NEAR(0x5bf8, 0x02, envx[16]);
    ASSERT_ENVX_NEAR(0x6051, 0x02, envx[19]);
    ASSERT_ENVX_NEAR(0x60c1, 0x02, envx[20]);
    ASSERT_ENVX_NEAR(0x6211, 0x02, envx[23]);
    ASSERT_ENVX_NEAR(0x6361, 0x02, envx[26]);
    ASSERT_ENVX_NEAR(0x6591, 0x02, envx[31]);
)

// sustain at various levels while direction scale negative exponentially
CESTER_TEST(adsr_sustain_down_exponential, spu_tests,
    uint16_t envx[0x20];

    spu_adsr_capture(
        ATTACK(0, 1, 0) | DECAY(0) | SUSTAIN(0, 12, 15, 1, 1) | RELEASE(0, 1),
        envx, 32);
    cester_assert_uint_eq(0x1c00, envx[0]);
    // Multiplicative decrease — deltas shrink as EnvVol drops.
    ASSERT_ENVX_NEAR(0x3c19, 0x02, envx[1]);
    ASSERT_ENVX_NEAR(0x3819, 0x02, envx[2]);
    ASSERT_ENVX_NEAR(0x3419, 0x02, envx[3]);
    ASSERT_ENVX_NEAR(0x3019, 0x02, envx[4]);
    ASSERT_ENVX_NEAR(0x2d12, 0x02, envx[5]);
    ASSERT_ENVX_NEAR(0x2a12, 0x02, envx[6]);
    ASSERT_ENVX_NEAR(0x2712, 0x02, envx[7]);
    ASSERT_ENVX_NEAR(0x2412, 0x02, envx[8]);
    ASSERT_ENVX_NEAR(0x2112, 0x02, envx[9]);
    ASSERT_ENVX_NEAR(0x1eb7, 0x01, envx[10]);
    ASSERT_ENVX_NEAR(0x1ab7, 0x01, envx[12]);
    ASSERT_ENVX_NEAR(0x16b7, 0x01, envx[14]);
    ASSERT_ENVX_NEAR(0x12b7, 0x01, envx[16]);
    ASSERT_ENVX_NEAR(0x0f5b, 0x01, envx[18]);
    ASSERT_ENVX_NEAR(0x0c5b, 0x01, envx[21]);
    ASSERT_ENVX_NEAR(0x095b, 0x01, envx[24]);
    ASSERT_ENVX_NEAR(0x065b, 0x01, envx[27]);
    ASSERT_ENVX_NEAR(0x035b, 0x01, envx[30]);
)

// release linear, capture samples as soon as key goes off
CESTER_TEST(adsr_release_linear, spu_tests,
    uint16_t envx[0x20];

    spu_adsr_capture_with_keyoff(
        ATTACK(0, 1, 0) | DECAY(15) |
        SUSTAIN(3, 0x1f, 15, 0, 0) | RELEASE(12, 0),
        envx, 24, 3);
    cester_assert_uint_eq(0x1c00, envx[0]);
    cester_assert_uint_eq(0x7ff7, envx[1]);
    cester_assert_uint_eq(0x7ff7, envx[2]);
    cester_assert_uint_eq(0x7ff7, envx[3]);
    ASSERT_ENVX_NEAR(0x77fb, 0x04, envx[4]);
    ASSERT_ENVX_NEAR(0x6ffb, 0x04, envx[5]);
    ASSERT_ENVX_NEAR(0x67fb, 0x04, envx[6]);
    ASSERT_ENVX_NEAR(0x5ffb, 0x04, envx[7]);
    ASSERT_ENVX_NEAR(0x57fb, 0x04, envx[8]);
    ASSERT_ENVX_NEAR(0x4ffb, 0x04, envx[9]);
    ASSERT_ENVX_NEAR(0x47fb, 0x04, envx[10]);
    ASSERT_ENVX_NEAR(0x3ffb, 0x04, envx[11]);
    ASSERT_ENVX_NEAR(0x37fb, 0x04, envx[12]);
    ASSERT_ENVX_NEAR(0x2ffb, 0x04, envx[13]);
    ASSERT_ENVX_NEAR(0x27fb, 0x04, envx[14]);
    ASSERT_ENVX_NEAR(0x1ffb, 0x04, envx[15]);
    ASSERT_ENVX_NEAR(0x17fb, 0x04, envx[16]);
    ASSERT_ENVX_NEAR(0x0ffb, 0x04, envx[17]);
    ASSERT_ENVX_NEAR(0x07fb, 0x04, envx[18]);
    for (unsigned i = 19; i < 24; i++)
        cester_assert_uint_eq(0x0000, envx[i]);

    spu_adsr_capture_with_keyoff(
        ATTACK(0, 1, 0) | DECAY(15) |
        SUSTAIN(3, 0x1f, 15, 0, 0) | RELEASE(14, 0),
        envx, 32, 3);
    cester_assert_uint_eq(0x1c00, envx[0]);
    ASSERT_ENVX_NEAR(0x7ffb, 0x04, envx[3]);
    ASSERT_ENVX_NEAR(0x7dfb, 0x04, envx[4]);
    ASSERT_ENVX_NEAR(0x7bfb, 0x04, envx[5]);
    ASSERT_ENVX_NEAR(0x77fb, 0x04, envx[7]);
    ASSERT_ENVX_NEAR(0x6ffb, 0x04, envx[11]);
    ASSERT_ENVX_NEAR(0x67fb, 0x04, envx[15]);
    ASSERT_ENVX_NEAR(0x5ffb, 0x04, envx[19]);
    ASSERT_ENVX_NEAR(0x57fb, 0x04, envx[23]);
    ASSERT_ENVX_NEAR(0x4ffb, 0x04, envx[27]);
    ASSERT_ENVX_NEAR(0x47fb, 0x04, envx[31]);

    spu_adsr_capture_with_keyoff(
        ATTACK(0, 1, 0) | DECAY(15) |
        SUSTAIN(3, 0x1f, 15, 0, 0) | RELEASE(16, 0),
        envx, 16, 3);
    cester_assert_uint_eq(0x1c00, envx[0]);
    ASSERT_ENVX_NEAR(0x7ffb, 0x04, envx[3]);
    ASSERT_ENVX_NEAR(0x7f7b, 0x04, envx[4]);
    ASSERT_ENVX_NEAR(0x7efb, 0x04, envx[5]);
    ASSERT_ENVX_NEAR(0x7dfb, 0x04, envx[7]);
    ASSERT_ENVX_NEAR(0x7bfb, 0x04, envx[11]);
    ASSERT_ENVX_NEAR(0x79fb, 0x04, envx[15]);
)

// release exponential, capture samples as soon as key goes off
CESTER_TEST(adsr_release_exponential, spu_tests,
    uint16_t envx[0x20];

    spu_adsr_capture_with_keyoff(
        ATTACK(0, 1, 0) | DECAY(15) |
        SUSTAIN(3, 0x1f, 15, 0, 0) | RELEASE(12, 1),
        envx, 24, 2);
    cester_assert_uint_eq(0x1c00, envx[0]);
    cester_assert_uint_eq(0x7ff7, envx[1]);
    cester_assert_uint_eq(0x7ff7, envx[2]);
    ASSERT_ENVX_NEAR(0x77fb, 0x04, envx[3]);
    ASSERT_ENVX_NEAR(0x6ffb, 0x04, envx[4]);
    ASSERT_ENVX_NEAR(0x68fb, 0x04, envx[5]);
    ASSERT_ENVX_NEAR(0x61fb, 0x04, envx[6]);
    ASSERT_ENVX_NEAR(0x5bb3, 0x03, envx[7]);
    ASSERT_ENVX_NEAR(0x55b3, 0x03, envx[8]);
    ASSERT_ENVX_NEAR(0x4fbf, 0x03, envx[9]);
    ASSERT_ENVX_NEAR(0x4abf, 0x03, envx[10]);
    ASSERT_ENVX_NEAR(0x45bf, 0x03, envx[11]);
    ASSERT_ENVX_NEAR(0x40bf, 0x03, envx[12]);
    ASSERT_ENVX_NEAR(0x3c99, 0x02, envx[13]);
    ASSERT_ENVX_NEAR(0x3899, 0x02, envx[14]);
    ASSERT_ENVX_NEAR(0x3499, 0x02, envx[15]);
    ASSERT_ENVX_NEAR(0x3099, 0x02, envx[16]);
    ASSERT_ENVX_NEAR(0x2d72, 0x02, envx[17]);
    ASSERT_ENVX_NEAR(0x2a72, 0x02, envx[18]);
    ASSERT_ENVX_NEAR(0x2772, 0x02, envx[19]);
    ASSERT_ENVX_NEAR(0x2472, 0x02, envx[20]);
    ASSERT_ENVX_NEAR(0x2172, 0x02, envx[21]);
    ASSERT_ENVX_NEAR(0x1ef7, 0x01, envx[22]);
    ASSERT_ENVX_NEAR(0x1cf7, 0x01, envx[23]);
)
