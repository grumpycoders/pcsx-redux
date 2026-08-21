// ============================================================================
// Validate reverb work-area state
// ============================================================================
//
// Tier 1.5 oracle: this file reads the SPU reverb work area from SPU RAM after
// a deterministic stimulus. The normal capture buffers at 0x000/0x400/0x800/
// 0xC00 are dry pre-reverb mirrors, so they cannot see the final reverb mix.
// The work area is still a real hardware state oracle: it captures the IIR,
// comb, and APF delay-line state that the reverb unit writes while running.
//
// Tier 2 oracle, later: Pixel's I2S logic-analyzer rig will capture BCLK/LRCK/
// DATA from the SPU's digital audio output. That gives the post-mix, post-reverb
// final audio stream. These tests do not depend on that rig; the I2S path should
// slot in later as a separate final-mix comparison, not replace this autonomous
// SPU-RAM state test.
//
// The expected files are intentionally not doc-derived. Run with SPU_DUMP=true
// on real silicon to create the .test.rev files, then enable
// SPU_REVERB_GOLDENS=true once those hardware captures have been checked in.

#ifndef SPU_REVERB_HELPERS_DEFINED
#define SPU_REVERB_HELPERS_DEFINED

#define SPU_REVERB_ROOM_SIZE 0x26c0u
#define SPU_REVERB_ROOM_BASE (0x80000u - SPU_REVERB_ROOM_SIZE)
#define SPU_REVERB_ROOM_BASE_REG (SPU_REVERB_ROOM_BASE >> 3)

#define SPU_REVERB_INPUT_IMPULSE 1u
#define SPU_REVERB_INPUT_STEADY_SINE 2u
#define SPU_REVERB_PRESET_ROOM 1u

// One positive ADPCM impulse, followed by a silent loop. The first block has no
// loop flag; the second block marks the silent loop point, and the last block
// ends/repeats back to that silence. This gives the reverb a clean transient
// without continuously re-triggering the impulse.
static const uint8_t kAdpcmImpulseThenSilence[64] __attribute__((aligned(4))) = {
    0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

struct SPUReverbCaptureHeader {
    uint32_t magic;       // 'REVR'
    uint32_t length;      // sizeof(struct SPUReverbCaptureHeader)
    uint32_t preset;      // SPU_REVERB_PRESET_*
    uint32_t input;       // SPU_REVERB_INPUT_*
    uint32_t workBase;    // byte address in SPU RAM
    uint32_t workBytes;   // bytes captured after this header
    uint32_t syncWindows; // count of bit11 high->low waits after key-on
    uint32_t reserved;
};

static const uint16_t kReverbRoomPreset[32] = {
    0x007d, 0x005b, 0x6d80, 0x54b8, 0xbed0, 0x0000, 0x0000, 0xba80,
    0x5800, 0x5300, 0x04d6, 0x0333, 0x03f0, 0x0227, 0x0374, 0x01ef,
    0x0334, 0x01b5, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    0x0000, 0x0000, 0x01b4, 0x0136, 0x00b8, 0x005c, 0x8000, 0x8000,
};

static void spu_reverb_apply_room_preset(void) {
    volatile uint16_t *regs = (volatile uint16_t *)SPU_REVERB;
    for (unsigned i = 0; i < 32; i++) regs[i] = kReverbRoomPreset[i];
}

static void spu_zero_reverb_work_area(void) {
    for (unsigned off = 0; off < SPU_REVERB_ROOM_SIZE; off += sizeof(s_reverb_work)) {
        unsigned chunk = SPU_REVERB_ROOM_SIZE - off;
        if (chunk > sizeof(s_reverb_work)) chunk = sizeof(s_reverb_work);
        for (unsigned i = 0; i < chunk; i++) s_reverb_work[i] = 0;
        spu_write_sync(SPU_REVERB_ROOM_BASE + off, s_reverb_work, chunk);
    }
}

static void spu_wait_reverb_windows(unsigned windows) {
    for (unsigned i = 0; i < windows; i++) spu_wait_status_bit11_flip();
}

static void run_reverb_room_work_area(const uint8_t *sample64, uint32_t inputKind, unsigned syncWindows) {
    (void)inputKind;
    spu_reset_quiet();

    for (int i = 0; i < 64; i++) s_upload[i] = sample64[i];
    for (int i = 64; i < 128; i++) s_upload[i] = 0xaa;
    spu_write_sync(SPU_UPLOAD_ADDR, s_upload, 128);

    // Disable reverb writes while clearing the work area, then program mBASE.
    SPU_CTRL = 0x8000 | 0x4000;
    spu_zero_reverb_work_area();
    SPU_REVERB_ADDR = SPU_REVERB_ROOM_BASE_REG;
    spu_reverb_apply_room_preset();

    SPU_VOICES[1].volumeLeft = 0x3fff;
    SPU_VOICES[1].volumeRight = 0x3fff;
    SPU_VOL_MAIN_LEFT = 0;
    SPU_VOL_MAIN_RIGHT = 0;
    SPU_REVERB_LEFT = 0;
    SPU_REVERB_RIGHT = 0;
    SPU_REVERB_EN_LOW = 1u << 1;
    SPU_REVERB_EN_HIGH = 0;

    // Master reverb enable gates writes into the work area. Output volume is
    // left at zero: this test observes SPU RAM state, not audible final mix.
    SPU_CTRL = 0x8000 | 0x4000 | 0x0080;

    // Align the stimulus to the same capture-half edge used by the dry tests.
    // With zero input and a zeroed work area, the pre-key-on reverb ticks leave
    // the work area unchanged.
    spu_wait_status_bit11_flip();
    spu_voice1_keyon(SPU_UPLOAD_ADDR, 0x1000);
    spu_wait_reverb_windows(syncWindows);

    spu_read_sync(SPU_REVERB_ROOM_BASE, s_reverb_work, SPU_REVERB_ROOM_SIZE);
    SPU_KEY_OFF_LOW = 0xffff;
    SPU_KEY_OFF_HIGH = 0xffff;
    SPU_REVERB_EN_LOW = 0;
    SPU_REVERB_EN_HIGH = 0;
    muteSpu();
}

#ifdef SPU_DUMP
// File-scope (main-RAM .bss) header buffer: PCwrite must read its source from a
// stable RAM address. A stack local got captured as live stack contents (saved
// registers) rather than the initialized struct on real hardware, so the header
// is built into this static instead.
static struct SPUReverbCaptureHeader s_reverb_hdr;
static void spu_dump_reverb(const char *name, uint32_t inputKind, unsigned syncWindows) {
    s_reverb_hdr.magic = 0x52564552u;
    s_reverb_hdr.length = sizeof(struct SPUReverbCaptureHeader);
    s_reverb_hdr.preset = SPU_REVERB_PRESET_ROOM;
    s_reverb_hdr.input = inputKind;
    s_reverb_hdr.workBase = SPU_REVERB_ROOM_BASE;
    s_reverb_hdr.workBytes = SPU_REVERB_ROOM_SIZE;
    s_reverb_hdr.syncWindows = syncWindows;
    s_reverb_hdr.reserved = 0;
    if (!is_pcdrv_init) {
        PCinit();
        is_pcdrv_init = 1;
    }
    int fd = PCcreat(name, 0);
    if (fd < 0) return;
    PCwrite(fd, &s_reverb_hdr, sizeof(s_reverb_hdr));
    PCwrite(fd, s_reverb_work, SPU_REVERB_ROOM_SIZE);
    PCclose(fd);
}
#define SPU_ASSERT_REVERB_GOLDEN(NAME, INPUT, WINDOWS) spu_dump_reverb(#NAME ".test.rev", INPUT, WINDOWS)
#else
static int spu_compare_reverb_golden(const char *name, const void *capture, const uint8_t *goldenFile,
                                     uint32_t inputKind, unsigned syncWindows) {
    const struct SPUReverbCaptureHeader *hdr = (const struct SPUReverbCaptureHeader *)goldenFile;
    const uint8_t *expected = goldenFile + hdr->length;
    if (hdr->magic != 0x52564552u || hdr->length != sizeof(struct SPUReverbCaptureHeader) ||
        hdr->preset != SPU_REVERB_PRESET_ROOM || hdr->input != inputKind ||
        hdr->workBase != SPU_REVERB_ROOM_BASE || hdr->workBytes != SPU_REVERB_ROOM_SIZE ||
        hdr->syncWindows != syncWindows) {
        ramsyscall_printf("%s reverb golden header mismatch\n", name);
        return 1;
    }
    const uint8_t *got = (const uint8_t *)capture;
    for (unsigned i = 0; i < SPU_REVERB_ROOM_SIZE; i++) {
        if (got[i] != expected[i]) {
            ramsyscall_printf("%s reverb mismatch at +0x%04x: got 0x%02x, want 0x%02x\n",
                              name, i, got[i], expected[i]);
            return i + 1;
        }
    }
    return 0;
}
#endif

#ifdef SPU_REVERB_GOLDENS_AVAILABLE
#define INCLUDE_REVERB_GOLDEN(NAME) \
    asm( \
        ".pushsection .rodata\n" \
        ".global " #NAME "\n" \
        ".align 2\n" \
        #NAME ":\n" \
        ".incbin \"" #NAME ".test.rev\"\n" \
        ".popsection"); \
    extern const uint8_t NAME[]

INCLUDE_REVERB_GOLDEN(room_impulse);
INCLUDE_REVERB_GOLDEN(room_steady_sine);
#define SPU_ASSERT_REVERB_GOLDEN(NAME, INPUT, WINDOWS) \
    cester_assert_int_eq(0, spu_compare_reverb_golden(#NAME, s_reverb_work, NAME, INPUT, WINDOWS))
#define SPU_REVERB_TEST CESTER_TEST
#elif defined(SPU_DUMP)
#define SPU_REVERB_TEST CESTER_TEST
#else
#define SPU_ASSERT_REVERB_GOLDEN(NAME, INPUT, WINDOWS) ((void)0)
#define SPU_REVERB_TEST CESTER_SKIP_TEST
#endif

#endif

SPU_REVERB_TEST(reverb_room_impulse_work_area, spu_tests,
    run_reverb_room_work_area(kAdpcmImpulseThenSilence, SPU_REVERB_INPUT_IMPULSE, 8);
    SPU_ASSERT_REVERB_GOLDEN(room_impulse, SPU_REVERB_INPUT_IMPULSE, 8);
)

SPU_REVERB_TEST(reverb_room_steady_sine_work_area, spu_tests,
    run_reverb_room_work_area(kAdpcmSine, SPU_REVERB_INPUT_STEADY_SINE, 32);
    SPU_ASSERT_REVERB_GOLDEN(room_steady_sine, SPU_REVERB_INPUT_STEADY_SINE, 32);
)
