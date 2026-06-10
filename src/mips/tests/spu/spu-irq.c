// ==========================================================================
// Characterize SPU IRQs from the voice ADPCM read pointer
// ==========================================================================
//
// Hardware goldens captured on real silicon. Only the deterministic latch-
// semantics values are pinned: where the IRQ-gated data lands in the capture
// buffer (firstNonzero, nonzeroCount, sum), that an ack re-arms immediately
// (rearm.secondPolls), and the mid-block re-fire count (midblock.hits). The
// poll counts (aligned.polls, rearm.firstPolls, midblock.firstPolls) and the
// capture tail index (aligned.lastNonzero) are left UNSET on purpose: they are
// CPU-vs-SPU timing / capture-window-edge quantities that vary run-to-run even
// on the same console (measured across repeat hardware runs), so pinning them
// would assert a value neither hardware nor an emulator reproduces.

#ifndef SPU_IRQ_EXPECTED_UNSET
#define SPU_IRQ_EXPECTED_UNSET 0xffffffffu
#endif

#ifndef SPU_IRQ_EXPECTED_ALIGNED_POLLS
#define SPU_IRQ_EXPECTED_ALIGNED_POLLS SPU_IRQ_EXPECTED_UNSET
#endif
#ifndef SPU_IRQ_EXPECTED_ALIGNED_FIRST_NONZERO
#define SPU_IRQ_EXPECTED_ALIGNED_FIRST_NONZERO 0u
#endif
#ifndef SPU_IRQ_EXPECTED_ALIGNED_LAST_NONZERO
#define SPU_IRQ_EXPECTED_ALIGNED_LAST_NONZERO SPU_IRQ_EXPECTED_UNSET
#endif
#ifndef SPU_IRQ_EXPECTED_ALIGNED_NONZERO_COUNT
#define SPU_IRQ_EXPECTED_ALIGNED_NONZERO_COUNT 345u
#endif
#ifndef SPU_IRQ_EXPECTED_ALIGNED_SUM
#define SPU_IRQ_EXPECTED_ALIGNED_SUM 18806188u
#endif

#ifndef SPU_IRQ_EXPECTED_REARM_FIRST_POLLS
#define SPU_IRQ_EXPECTED_REARM_FIRST_POLLS SPU_IRQ_EXPECTED_UNSET
#endif
#ifndef SPU_IRQ_EXPECTED_REARM_SECOND_POLLS
#define SPU_IRQ_EXPECTED_REARM_SECOND_POLLS 1u
#endif

#ifndef SPU_IRQ_EXPECTED_MIDBLOCK_HITS
#define SPU_IRQ_EXPECTED_MIDBLOCK_HITS 2u
#endif
#ifndef SPU_IRQ_EXPECTED_MIDBLOCK_FIRST_POLLS
#define SPU_IRQ_EXPECTED_MIDBLOCK_FIRST_POLLS SPU_IRQ_EXPECTED_UNSET
#endif

#define SPU_IRQ_TEST_ADDR 0x2000
#define SPU_IRQ_DUMMY_ADDR 0x7000
#define SPU_IRQ_POLL_TIMEOUT 2000000u
#define SPU_IRQ_REARM_TIMEOUT 6000000u

CESTER_BODY(
typedef struct {
    uint32_t irqAddr;
    uint32_t fired;
    uint32_t polls;
    uint32_t statusAtFire;
    uint32_t statusAfterAck;
    uint32_t ackCleared;
    uint32_t currentVolumeAtFire;
    uint32_t captureFirstNonzero;
    uint32_t captureLastNonzero;
    uint32_t captureNonzeroCount;
    uint32_t captureSum;
} SpuIrqMeasurement;

static uint8_t s_irqSample[128] __attribute__((aligned(4)));

static void spu_irq_make_sample(void) {
    for (int block = 0; block < 8; block++) {
        uint8_t *p = &s_irqSample[block * 16];
        p[0] = 0x00;
        p[1] = 0x00;
        if (block == 0) p[1] = 0x06;  // loop start
        if (block == 7) p[1] = 0x03;  // loop end
        uint8_t nybble = (uint8_t)((block + 1) & 7);
        uint8_t packed = (uint8_t)(nybble | (nybble << 4));
        for (int i = 2; i < 16; i++) p[i] = packed;
    }
}

static void spu_irq_arm(uint32_t byteAddr) {
    SPU_IRQ_ADDR = (uint16_t)(byteAddr >> 3);
    SPU_CTRL = (SPU_CTRL & ~0x0030) | 0x8000 | 0x4000 | 0x0040;
    for (volatile int i = 0; i < 120; i++) ;
}

static uint32_t spu_irq_ack_by_disable(void) {
    SPU_CTRL = SPU_CTRL & ~0x0040;
    for (uint32_t i = 0; i < 100000; i++) {
        if ((SPU_STATUS & 0x0040) == 0) return 1;
    }
    return 0;
}

static uint32_t spu_irq_poll_until(uint32_t maxPolls) {
    for (uint32_t i = 0; i < maxPolls; i++) {
        if (SPU_STATUS & 0x0040) return i + 1;
        __asm__ volatile("");
    }
    return 0;
}

static void spu_irq_quiet_unused_voices(void) {
    for (int v = 0; v < 24; v++) {
        SPU_VOICES[v].volumeLeft = 0;
        SPU_VOICES[v].volumeRight = 0;
        SPU_VOICES[v].sampleRate = 0x1000;
        SPU_VOICES[v].sampleStartAddr = SPU_IRQ_DUMMY_ADDR >> 3;
        SPU_VOICES[v].sampleRepeatAddr = SPU_IRQ_DUMMY_ADDR >> 3;
        SPU_VOICES[v].adsrLo = 0x000f;
        SPU_VOICES[v].adsrHi = 0x1fc0;
    }
    SPU_KEY_OFF_LOW = 0;
    SPU_KEY_OFF_HIGH = 0;
    SPU_KEY_ON_LOW = 0xffff;
    SPU_KEY_ON_HIGH = 0x00ff;
    spu_busy_wait(200000);
}

static void spu_irq_prepare(void) {
    spu_reset_quiet();
    spu_irq_make_sample();
    spu_write_sync(SPU_IRQ_DUMMY_ADDR, kAdpcmSilent, sizeof(kAdpcmSilent));
    spu_write_sync(SPU_IRQ_TEST_ADDR, s_irqSample, sizeof(s_irqSample));
    SPU_CTRL = 0x8000 | 0x4000;
    SPU_VOL_MAIN_LEFT = 0;
    SPU_VOL_MAIN_RIGHT = 0;
    spu_irq_quiet_unused_voices();
    (void)spu_irq_ack_by_disable();
}

static void spu_irq_start_voice1(void) {
    SPU_VOICES[1].volumeLeft = 0;
    SPU_VOICES[1].volumeRight = 0;
    spu_voice1_keyon(SPU_IRQ_TEST_ADDR, 0x1000);
}

static void spu_irq_analyze_capture(SpuIrqMeasurement *m) {
    uint32_t first = 0xffffffffu;
    uint32_t last = 0;
    uint32_t count = 0;
    uint32_t sum = 0;

    spu_read_sync(0x0800, s_capture, 1024);
    for (uint32_t i = 0; i < 512; i++) {
        uint16_t v = s_capture[i];
        if (v != 0) {
            if (first == 0xffffffffu) first = i;
            last = i;
            count++;
            sum += v;
        }
    }

    m->captureFirstNonzero = first;
    m->captureLastNonzero = last;
    m->captureNonzeroCount = count;
    m->captureSum = sum;
}

static void spu_irq_measure_once(uint32_t irqByteAddr, SpuIrqMeasurement *m) {
    spu_irq_prepare();
    m->irqAddr = irqByteAddr;

    // The suite disables CPU interrupts globally. For this characterization pass
    // we deliberately poll SPUSTAT.6 instead of taking IRQ9: it measures the SPU
    // IRQ latch/ack semantics without re-enabling Unirom/vblank/SIO handlers into
    // the jitter-sensitive SPU tests. A later interrupt-delivery test can layer on
    // IMASK/IREG once the SPU-side latch behavior is known.
    spu_wait_status_bit11_flip();
    spu_irq_arm(irqByteAddr);
    spu_irq_start_voice1();

    m->polls = spu_irq_poll_until(SPU_IRQ_POLL_TIMEOUT);
    m->fired = (m->polls != 0);
    m->statusAtFire = SPU_STATUS;
    m->currentVolumeAtFire = SPU_VOICES[1].currentVolume;
    m->ackCleared = spu_irq_ack_by_disable();
    m->statusAfterAck = SPU_STATUS;
    spu_irq_analyze_capture(m);

    SPU_KEY_OFF_LOW = 0xffff;
    SPU_KEY_OFF_HIGH = 0xffff;
    muteSpu();
}

static void spu_irq_print_measurement(const char *name, const SpuIrqMeasurement *m) {
    ramsyscall_printf(
        "OBS spu_irq %s irq=0x%05lx fired=%lu polls=%lu statusFire=0x%04lx "
        "ackCleared=%lu statusAck=0x%04lx envx=0x%04lx capFirst=%lu capLast=%lu "
        "capCount=%lu capSum=0x%08lx\n",
        name, m->irqAddr, m->fired, m->polls, m->statusAtFire & 0xffff,
        m->ackCleared, m->statusAfterAck & 0xffff, m->currentVolumeAtFire & 0xffff,
        m->captureFirstNonzero, m->captureLastNonzero, m->captureNonzeroCount, m->captureSum);
}

static void spu_irq_expect_u32(const char *name, uint32_t expected, uint32_t got) {
    if (expected == SPU_IRQ_EXPECTED_UNSET) {
        ramsyscall_printf("OBS spu_irq expected %s=%lu\n", name, got);
    } else {
        cester_assert_uint_eq(expected, got);
    }
}
)

CESTER_TEST(irq_voice_read_pointer_block_aligned, spu_tests,
    SpuIrqMeasurement m;
    spu_irq_measure_once(SPU_IRQ_TEST_ADDR + 16, &m);
    spu_irq_print_measurement("aligned_block1", &m);

    uint32_t statusFlagAfterAck = m.statusAfterAck & 0x0040;
    cester_assert_uint_eq(1, m.fired);
    cester_assert_uint_eq(1, m.ackCleared);
    cester_assert_uint_eq(0, statusFlagAfterAck);
    spu_irq_expect_u32("aligned.polls", SPU_IRQ_EXPECTED_ALIGNED_POLLS, m.polls);
    spu_irq_expect_u32("aligned.firstNonzero", SPU_IRQ_EXPECTED_ALIGNED_FIRST_NONZERO, m.captureFirstNonzero);
    spu_irq_expect_u32("aligned.lastNonzero", SPU_IRQ_EXPECTED_ALIGNED_LAST_NONZERO, m.captureLastNonzero);
    spu_irq_expect_u32("aligned.nonzeroCount", SPU_IRQ_EXPECTED_ALIGNED_NONZERO_COUNT, m.captureNonzeroCount);
    spu_irq_expect_u32("aligned.sum", SPU_IRQ_EXPECTED_ALIGNED_SUM, m.captureSum);
)

CESTER_TEST(irq_voice_read_pointer_ack_rearms, spu_tests,
    SpuIrqMeasurement first;
    spu_irq_prepare();
    spu_wait_status_bit11_flip();
    spu_irq_arm(SPU_IRQ_TEST_ADDR + 16);
    spu_irq_start_voice1();

    first.polls = spu_irq_poll_until(SPU_IRQ_POLL_TIMEOUT);
    first.fired = (first.polls != 0);
    first.statusAtFire = SPU_STATUS;
    first.ackCleared = spu_irq_ack_by_disable();
    first.statusAfterAck = SPU_STATUS;

    spu_irq_arm(SPU_IRQ_TEST_ADDR + 16);
    uint32_t secondPolls = spu_irq_poll_until(SPU_IRQ_REARM_TIMEOUT);
    uint32_t secondFired = (secondPolls != 0);
    uint32_t secondStatus = SPU_STATUS;
    uint32_t secondAckCleared = spu_irq_ack_by_disable();

    ramsyscall_printf(
        "OBS spu_irq rearm firstFired=%lu firstPolls=%lu firstStatus=0x%04lx "
        "firstAck=%lu firstStatusAck=0x%04lx secondFired=%lu secondPolls=%lu "
        "secondStatus=0x%04lx secondAck=%lu\n",
        first.fired, first.polls, first.statusAtFire & 0xffff, first.ackCleared,
        first.statusAfterAck & 0xffff, secondFired, secondPolls, secondStatus & 0xffff,
        secondAckCleared);

    SPU_KEY_OFF_LOW = 0xffff;
    SPU_KEY_OFF_HIGH = 0xffff;
    muteSpu();

    cester_assert_uint_eq(1, first.fired);
    cester_assert_uint_eq(1, first.ackCleared);
    cester_assert_uint_eq(1, secondFired);
    cester_assert_uint_eq(1, secondAckCleared);
    spu_irq_expect_u32("rearm.firstPolls", SPU_IRQ_EXPECTED_REARM_FIRST_POLLS, first.polls);
    spu_irq_expect_u32("rearm.secondPolls", SPU_IRQ_EXPECTED_REARM_SECOND_POLLS, secondPolls);
)

CESTER_TEST(irq_voice_read_pointer_mid_block_probe, spu_tests,
    uint32_t hits = 0;
    uint32_t firstPolls = 0;

    spu_irq_prepare();
    spu_wait_status_bit11_flip();
    spu_irq_arm(SPU_IRQ_TEST_ADDR + 8);
    spu_irq_start_voice1();

    for (uint32_t attempt = 0; attempt < 8; attempt++) {
        uint32_t polls = spu_irq_poll_until(SPU_IRQ_REARM_TIMEOUT);
        if (polls != 0) {
            hits++;
            if (firstPolls == 0) firstPolls = polls;
            (void)spu_irq_ack_by_disable();
            spu_irq_arm(SPU_IRQ_TEST_ADDR + 8);
        } else {
            break;
        }
    }

    ramsyscall_printf("OBS spu_irq midblock irq=0x%05x hits=%lu firstPolls=%lu\n",
                      SPU_IRQ_TEST_ADDR + 8, hits, firstPolls);

    SPU_KEY_OFF_LOW = 0xffff;
    SPU_KEY_OFF_HIGH = 0xffff;
    (void)spu_irq_ack_by_disable();
    muteSpu();

    spu_irq_expect_u32("midblock.hits", SPU_IRQ_EXPECTED_MIDBLOCK_HITS, hits);
    spu_irq_expect_u32("midblock.firstPolls", SPU_IRQ_EXPECTED_MIDBLOCK_FIRST_POLLS, firstPolls);
)
