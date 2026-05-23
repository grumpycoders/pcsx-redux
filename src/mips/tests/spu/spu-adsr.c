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
    SPU_VOICES[1].ad = (uint16_t)(adsr & 0xFFFF);
    SPU_VOICES[1].sr = (uint16_t)(adsr >> 16);
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
