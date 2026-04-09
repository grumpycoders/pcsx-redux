// Depth cue instructions: DPCS, DPCT, DCPL, INTPL

// DPCS: depth cue single - interpolates RGBC toward far color using IR0
CESTER_TEST(dpcs_basic, gte_tests,
    gte_set_far_color(0x1000, 0x1000, 0x1000);  // FC = (4096, 4096, 4096)
    GTE_WRITE_DATA(6, 0x00808080);  // RGBC: R=0x80, G=0x80, B=0x80
    GTE_WRITE_DATA(8, 0x0800);      // IR0 = 0.5
    gte_clear_flag();
    GTE_EXEC(GTE_CMD_DPCS);
    int32_t mac1, mac2, mac3;
    uint32_t rgb2;
    GTE_READ_DATA(25, mac1);
    GTE_READ_DATA(26, mac2);
    GTE_READ_DATA(27, mac3);
    GTE_READ_DATA(22, rgb2);
    ramsyscall_printf("DPCS: MAC=(%d,%d,%d) RGB2=0x%08x\n", mac1, mac2, mac3, rgb2);
    // Formula: MAC = R<<16 + IR0*(FC<<12 - R<<16) >> shift
    // R<<16 = 0x80<<16 = 0x800000
    // FC<<12 = 0x1000<<12 = 0x1000000
    // diff = 0x1000000 - 0x800000 = 0x800000
    // IR0 * diff = 0x800 * 0x800000 ... this is large
)

// DPCS with IR0=0: no interpolation, output = input color
CESTER_TEST(dpcs_ir0_zero, gte_tests,
    gte_set_far_color(0xff00, 0xff00, 0xff00);
    GTE_WRITE_DATA(6, 0x00406080);  // R=0x80, G=0x60, B=0x40
    GTE_WRITE_DATA(8, 0);           // IR0 = 0
    gte_clear_flag();
    GTE_EXEC(GTE_CMD_DPCS);
    uint32_t rgb2;
    GTE_READ_DATA(22, rgb2);
    uint8_t r = rgb2 & 0xff;
    uint8_t g = (rgb2 >> 8) & 0xff;
    uint8_t b = (rgb2 >> 16) & 0xff;
    // With IR0=0, interpolation weight is 0, so output = input
    cester_assert_uint_eq(0x80, r);
    cester_assert_uint_eq(0x60, g);
    cester_assert_uint_eq(0x40, b);
)

// DPCS with IR0=0x1000: full interpolation toward far color
CESTER_TEST(dpcs_ir0_max, gte_tests,
    gte_set_far_color(0x1000, 0x800, 0x400);  // FC scaled
    GTE_WRITE_DATA(6, 0x00000000);  // RGBC: all zero
    GTE_WRITE_DATA(8, 0x1000);      // IR0 = 1.0
    gte_clear_flag();
    GTE_EXEC(GTE_CMD_DPCS);
    int32_t mac1, mac2, mac3;
    GTE_READ_DATA(25, mac1);
    GTE_READ_DATA(26, mac2);
    GTE_READ_DATA(27, mac3);
    ramsyscall_printf("DPCS max: MAC=(%d,%d,%d)\n", mac1, mac2, mac3);
    // With R=0, MAC = 0 + IR0 * (FC<<12 - 0) = 1.0 * FC<<12 >> 12 = FC
)

// DPCS color FIFO push and CODE preservation
CESTER_TEST(dpcs_code_preserved, gte_tests,
    gte_set_far_color(0, 0, 0);
    GTE_WRITE_DATA(6, 0xab102030);  // CODE=0xAB, R=0x30, G=0x20, B=0x10
    GTE_WRITE_DATA(8, 0);
    gte_clear_flag();
    GTE_EXEC(GTE_CMD_DPCS);
    uint32_t rgb2;
    GTE_READ_DATA(22, rgb2);
    cester_assert_uint_eq(0xab, (rgb2 >> 24) & 0xff);  // CODE preserved
)

// DPCT: depth cue triple - reads from color FIFO front (RGB0), not RGBC
CESTER_TEST(dpct_reads_fifo, gte_tests,
    gte_set_far_color(0, 0, 0);
    // Set up color FIFO with known values
    GTE_WRITE_DATA(20, 0x00102030);  // RGB0: R=0x30, G=0x20, B=0x10
    GTE_WRITE_DATA(21, 0x00405060);  // RGB1
    GTE_WRITE_DATA(22, 0x00708090);  // RGB2
    GTE_WRITE_DATA(6, 0xff000000);   // RGBC: CODE=0xff, colors=0 (should NOT be used as input)
    GTE_WRITE_DATA(8, 0);            // IR0=0: output = input
    gte_clear_flag();
    GTE_EXEC(GTE_CMD_DPCT);
    // After 3 iterations, the FIFO has been processed
    uint32_t rgb0, rgb1, rgb2;
    GTE_READ_DATA(20, rgb0);
    GTE_READ_DATA(21, rgb1);
    GTE_READ_DATA(22, rgb2);
    ramsyscall_printf("DPCT: RGB0=0x%08x RGB1=0x%08x RGB2=0x%08x\n", rgb0, rgb1, rgb2);
    // Each iteration: reads R0/G0/B0 (front of FIFO), pushes result
    // With IR0=0, each iteration's output = its input color
    // Iteration 1: reads RGB0(0x102030), pushes -> FIFO shifts
    // Iteration 2: reads new RGB0 (was RGB1: 0x405060), pushes
    // Iteration 3: reads new RGB0 (was RGB2: 0x708090), pushes
    // Result FIFO should contain the 3 processed colors
    // CODE comes from RGBC (0xff)
    cester_assert_uint_eq(0xff, (rgb0 >> 24) & 0xff);
)

// DCPL: depth cue with pre-computed light
CESTER_TEST(dcpl_basic, gte_tests,
    gte_set_far_color(0x1000, 0x1000, 0x1000);
    GTE_WRITE_DATA(6, 0x00808080);  // RGBC
    // Pre-computed light in IR1-3
    GTE_WRITE_DATA(9, 0x1000);   // IR1 = 1.0
    GTE_WRITE_DATA(10, 0x0800);  // IR2 = 0.5
    GTE_WRITE_DATA(11, 0x0400);  // IR3 = 0.25
    GTE_WRITE_DATA(8, 0);        // IR0 = 0 (no depth cue)
    gte_clear_flag();
    GTE_EXEC(GTE_CMD_DCPL);
    int32_t mac1, mac2, mac3;
    uint32_t rgb2;
    GTE_READ_DATA(25, mac1);
    GTE_READ_DATA(26, mac2);
    GTE_READ_DATA(27, mac3);
    GTE_READ_DATA(22, rgb2);
    ramsyscall_printf("DCPL: MAC=(%d,%d,%d) RGB2=0x%08x\n", mac1, mac2, mac3, rgb2);
    // With IR0=0: MAC = (R<<4)*IR, no depth cue interpolation
    // MAC1 = (0x80 << 4) * 0x1000 = 0x800 * 0x1000 = 0x800000
    // After >>12: 0x800 = 2048 -> IR1, /16 = 128 -> R2
)

// DCPL with depth cue interpolation
CESTER_TEST(dcpl_with_depth, gte_tests,
    gte_set_far_color(0x1000, 0x1000, 0x1000);
    GTE_WRITE_DATA(6, 0x00808080);
    GTE_WRITE_DATA(9, 0x1000);
    GTE_WRITE_DATA(10, 0x1000);
    GTE_WRITE_DATA(11, 0x1000);
    GTE_WRITE_DATA(8, 0x0800);  // IR0 = 0.5
    gte_clear_flag();
    GTE_EXEC(GTE_CMD_DCPL);
    int32_t mac1, mac2, mac3;
    uint32_t flag;
    GTE_READ_DATA(25, mac1);
    GTE_READ_DATA(26, mac2);
    GTE_READ_DATA(27, mac3);
    flag = gte_read_flag();
    ramsyscall_printf("DCPL depth: MAC=(%d,%d,%d) FLAG=0x%08x\n", mac1, mac2, mac3, flag);
)

// INTPL: interpolation (depth cue on IR vector directly)
CESTER_TEST(intpl_basic, gte_tests,
    gte_set_far_color(0x1000, 0x2000, 0x3000);
    GTE_WRITE_DATA(9, 0x100);   // IR1
    GTE_WRITE_DATA(10, 0x200);  // IR2
    GTE_WRITE_DATA(11, 0x300);  // IR3
    GTE_WRITE_DATA(8, 0);       // IR0 = 0: no interpolation
    gte_clear_flag();
    GTE_EXEC(GTE_CMD_INTPL);
    int32_t mac1, mac2, mac3;
    GTE_READ_DATA(25, mac1);
    GTE_READ_DATA(26, mac2);
    GTE_READ_DATA(27, mac3);
    // With IR0=0: MAC = IR << 12 >> shift = IR (with sf=1)
    cester_assert_int_eq(0x100, mac1);
    cester_assert_int_eq(0x200, mac2);
    cester_assert_int_eq(0x300, mac3);
)

CESTER_TEST(intpl_half, gte_tests,
    gte_set_far_color(0x1000, 0x1000, 0x1000);
    GTE_WRITE_DATA(9, 0);
    GTE_WRITE_DATA(10, 0);
    GTE_WRITE_DATA(11, 0);
    GTE_WRITE_DATA(8, 0x0800);  // IR0 = 0.5
    gte_clear_flag();
    GTE_EXEC(GTE_CMD_INTPL);
    int32_t mac1, mac2, mac3;
    GTE_READ_DATA(25, mac1);
    GTE_READ_DATA(26, mac2);
    GTE_READ_DATA(27, mac3);
    ramsyscall_printf("INTPL half: MAC=(%d,%d,%d)\n", mac1, mac2, mac3);
    // IR=0, FC=0x1000, IR0=0.5
    // MAC = 0 + 0.5*(FC - 0) = 0.5 * 0x1000 = 0x800
)

// INTPL pushes color FIFO
CESTER_TEST(intpl_color_push, gte_tests,
    gte_set_far_color(0, 0, 0);
    GTE_WRITE_DATA(9, 0x0ff0);  // MAC1=0x0ff0, /16 = 255
    GTE_WRITE_DATA(10, 0x0800); // MAC2=0x0800, /16 = 128
    GTE_WRITE_DATA(11, 0x0010); // MAC3=0x0010, /16 = 1
    GTE_WRITE_DATA(8, 0);
    GTE_WRITE_DATA(6, 0xcc000000);  // CODE=0xCC
    gte_clear_flag();
    GTE_EXEC(GTE_CMD_INTPL);
    uint32_t rgb2;
    GTE_READ_DATA(22, rgb2);
    uint8_t cd = (rgb2 >> 24) & 0xff;
    uint8_t r = rgb2 & 0xff;
    uint8_t g = (rgb2 >> 8) & 0xff;
    uint8_t b = (rgb2 >> 16) & 0xff;
    ramsyscall_printf("INTPL color: R=%u G=%u B=%u CD=0x%02x raw=0x%08x\n", r, g, b, cd, rgb2);
    cester_assert_uint_eq(0xcc, cd);
)
