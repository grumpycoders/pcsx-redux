// Lighting instructions: NCS, NCT, NCCS, NCCT, NCDS, NCDT, CC, CDP

// NCS: normal color single (2-stage: normal->light, light->color)
CESTER_TEST(ncs_z_normal_white_light, gte_tests,
    gte_set_simple_light();       // L33=0x1000
    gte_set_white_light_color();  // LC identity
    gte_set_zero_bk();
    // Normal pointing at light: (0, 0, 0x1000)
    GTE_WRITE_DATA(0, 0x00000000);
    GTE_WRITE_DATA(1, 0x1000);
    GTE_WRITE_DATA(6, 0x00808080);  // RGBC (not used by NCS but CODE is)
    gte_clear_flag();
    GTE_EXEC(GTE_CMD_NCS);
    int32_t mac1, mac2, mac3;
    uint32_t rgb2;
    GTE_READ_DATA(25, mac1);
    GTE_READ_DATA(26, mac2);
    GTE_READ_DATA(27, mac3);
    GTE_READ_DATA(22, rgb2);
    ramsyscall_printf("NCS z-normal: MAC=(%d,%d,%d) RGB2=0x%08x\n", mac1, mac2, mac3, rgb2);
    // Stage 1: L * normal = (0,0,0x1000).(0,0,0x1000) = only IR3 = 0x1000
    // Stage 2: LC * (0,0,0x1000) + BK = (0,0,0x1000) since LC is identity, BK=0
    // Color FIFO: MAC/16 = 0x1000/16 = 256 -> saturates to 255
)

// NCS with background color
CESTER_TEST(ncs_with_background, gte_tests,
    gte_set_simple_light();
    gte_set_white_light_color();
    GTE_WRITE_CTRL(13, 0x800);  // RBK = 0x800
    GTE_WRITE_CTRL(14, 0x400);  // GBK = 0x400
    GTE_WRITE_CTRL(15, 0x200);  // BBK = 0x200
    GTE_WRITE_DATA(0, 0x00000000);
    GTE_WRITE_DATA(1, 0x1000);
    GTE_WRITE_DATA(6, 0x00000000);
    gte_clear_flag();
    GTE_EXEC(GTE_CMD_NCS);
    int32_t mac1, mac2, mac3;
    GTE_READ_DATA(25, mac1);
    GTE_READ_DATA(26, mac2);
    GTE_READ_DATA(27, mac3);
    // Stage 1: IR = (0, 0, 0x1000)
    // Stage 2: MAC = BK + LC*(0,0,0x1000) = (0x800+0, 0x400+0, 0x200+0x1000)
    cester_assert_int_eq(0x800, mac1);
    cester_assert_int_eq(0x400, mac2);
    cester_assert_int_eq(0x1200, mac3);
)

// NCT: normal color triple
CESTER_TEST(nct_three_normals, gte_tests,
    gte_set_simple_light();
    gte_set_white_light_color();
    gte_set_zero_bk();
    // V0 = (0, 0, 0x1000) - facing light
    GTE_WRITE_DATA(0, 0x00000000);
    GTE_WRITE_DATA(1, 0x1000);
    // V1 = (0x1000, 0, 0) - perpendicular
    GTE_WRITE_DATA(2, (0 << 16) | 0x1000);
    GTE_WRITE_DATA(3, 0);
    // V2 = (0, 0x1000, 0) - perpendicular
    GTE_WRITE_DATA(4, (0x1000 << 16) | 0);
    GTE_WRITE_DATA(5, 0);
    GTE_WRITE_DATA(6, 0x00000000);
    gte_clear_flag();
    GTE_EXEC(GTE_CMD_NCT);
    uint32_t rgb0, rgb1, rgb2;
    GTE_READ_DATA(20, rgb0);
    GTE_READ_DATA(21, rgb1);
    GTE_READ_DATA(22, rgb2);
    ramsyscall_printf("NCT: RGB0=0x%08x RGB1=0x%08x RGB2=0x%08x\n", rgb0, rgb1, rgb2);
    // V0 facing light: should have color
    // V1, V2 perpendicular: should be dark (light only in Z)
)

// NCCS: normal color color single (adds vertex color multiplication)
CESTER_TEST(nccs_basic, gte_tests,
    gte_set_simple_light();
    gte_set_white_light_color();
    gte_set_zero_bk();
    GTE_WRITE_DATA(0, 0x00000000);
    GTE_WRITE_DATA(1, 0x1000);
    GTE_WRITE_DATA(6, 0x00808080);  // R=0x80, G=0x80, B=0x80
    gte_clear_flag();
    GTE_EXEC(GTE_CMD_NCCS);
    int32_t mac1, mac2, mac3;
    uint32_t rgb2;
    GTE_READ_DATA(25, mac1);
    GTE_READ_DATA(26, mac2);
    GTE_READ_DATA(27, mac3);
    GTE_READ_DATA(22, rgb2);
    ramsyscall_printf("NCCS: MAC=(%d,%d,%d) RGB2=0x%08x\n", mac1, mac2, mac3, rgb2);
    // Stage 1: IR = (0, 0, 0x1000)
    // Stage 2: MAC = LC*(0,0,0x1000) = (0, 0, 0x1000)
    // Stage 3: MAC = (R<<4)*IR = (0x80<<4)*0 for R,G; (0x80<<4)*0x1000 for B... wait
    // Actually after stage 2, IR1=0, IR2=0, IR3=0x1000
    // Stage 3: MAC1 = (R<<4)*IR1 = 0x800*0 = 0
    // Only B channel gets lit since only IR3 is non-zero
)

// NCCT: normal color color triple
CESTER_TEST(ncct_basic, gte_tests,
    gte_set_simple_light();
    gte_set_white_light_color();
    gte_set_zero_bk();
    GTE_WRITE_DATA(0, 0x00000000);
    GTE_WRITE_DATA(1, 0x1000);
    GTE_WRITE_DATA(2, 0x00000000);
    GTE_WRITE_DATA(3, 0x1000);
    GTE_WRITE_DATA(4, 0x00000000);
    GTE_WRITE_DATA(5, 0x1000);
    GTE_WRITE_DATA(6, 0x00808080);
    gte_clear_flag();
    GTE_EXEC(GTE_CMD_NCCT);
    uint32_t rgb0, rgb1, rgb2;
    GTE_READ_DATA(20, rgb0);
    GTE_READ_DATA(21, rgb1);
    GTE_READ_DATA(22, rgb2);
    ramsyscall_printf("NCCT: RGB0=0x%08x RGB1=0x%08x RGB2=0x%08x\n", rgb0, rgb1, rgb2);
    // All three normals identical -> all three results should match
)

// NCDS: normal color depth single (full 3-stage pipeline + depth cue)
CESTER_TEST(ncds_no_depth, gte_tests,
    gte_set_simple_light();
    gte_set_white_light_color();
    gte_set_zero_bk();
    gte_set_far_color(0, 0, 0);
    GTE_WRITE_DATA(0, 0x00000000);
    GTE_WRITE_DATA(1, 0x1000);
    GTE_WRITE_DATA(6, 0x00808080);
    GTE_WRITE_DATA(8, 0);  // IR0 = 0 (no depth cue)
    gte_clear_flag();
    GTE_EXEC(GTE_CMD_NCDS);
    int32_t mac1, mac2, mac3;
    uint32_t rgb2;
    GTE_READ_DATA(25, mac1);
    GTE_READ_DATA(26, mac2);
    GTE_READ_DATA(27, mac3);
    GTE_READ_DATA(22, rgb2);
    ramsyscall_printf("NCDS no depth: MAC=(%d,%d,%d) RGB2=0x%08x\n", mac1, mac2, mac3, rgb2);
)

// NCDS with depth cue
CESTER_TEST(ncds_with_depth, gte_tests,
    gte_set_simple_light();
    gte_set_white_light_color();
    gte_set_zero_bk();
    gte_set_far_color(0x1000, 0x1000, 0x1000);
    GTE_WRITE_DATA(0, 0x00000000);
    GTE_WRITE_DATA(1, 0x1000);
    GTE_WRITE_DATA(6, 0x00808080);
    GTE_WRITE_DATA(8, 0x0800);  // IR0 = 0.5
    gte_clear_flag();
    GTE_EXEC(GTE_CMD_NCDS);
    int32_t mac1, mac2, mac3;
    uint32_t rgb2, flag;
    GTE_READ_DATA(25, mac1);
    GTE_READ_DATA(26, mac2);
    GTE_READ_DATA(27, mac3);
    GTE_READ_DATA(22, rgb2);
    flag = gte_read_flag();
    ramsyscall_printf("NCDS depth: MAC=(%d,%d,%d) RGB2=0x%08x FLAG=0x%08x\n",
                      mac1, mac2, mac3, rgb2, flag);
)

// NCDT: normal color depth triple
CESTER_TEST(ncdt_basic, gte_tests,
    gte_set_simple_light();
    gte_set_white_light_color();
    gte_set_zero_bk();
    gte_set_far_color(0, 0, 0);
    GTE_WRITE_DATA(0, 0x00000000);
    GTE_WRITE_DATA(1, 0x1000);
    GTE_WRITE_DATA(2, 0x00000000);
    GTE_WRITE_DATA(3, 0x0800);
    GTE_WRITE_DATA(4, 0x00000000);
    GTE_WRITE_DATA(5, 0x0400);
    GTE_WRITE_DATA(6, 0x00808080);
    GTE_WRITE_DATA(8, 0);
    gte_clear_flag();
    GTE_EXEC(GTE_CMD_NCDT);
    uint32_t rgb0, rgb1, rgb2;
    GTE_READ_DATA(20, rgb0);
    GTE_READ_DATA(21, rgb1);
    GTE_READ_DATA(22, rgb2);
    ramsyscall_printf("NCDT: RGB0=0x%08x RGB1=0x%08x RGB2=0x%08x\n", rgb0, rgb1, rgb2);
    // V0 has strongest light (normal = 0x1000), V2 weakest (0x400)
)

// CC: color color (light-to-color + vertex color multiply)
CESTER_TEST(cc_basic, gte_tests,
    gte_set_white_light_color();
    gte_set_zero_bk();
    // Pre-computed light intensity in IR1-3
    GTE_WRITE_DATA(9, 0x1000);
    GTE_WRITE_DATA(10, 0x0800);
    GTE_WRITE_DATA(11, 0x0400);
    GTE_WRITE_DATA(6, 0x00808080);  // RGBC
    gte_clear_flag();
    GTE_EXEC(GTE_CMD_CC);
    int32_t mac1, mac2, mac3;
    uint32_t rgb2;
    GTE_READ_DATA(25, mac1);
    GTE_READ_DATA(26, mac2);
    GTE_READ_DATA(27, mac3);
    GTE_READ_DATA(22, rgb2);
    ramsyscall_printf("CC: MAC=(%d,%d,%d) RGB2=0x%08x\n", mac1, mac2, mac3, rgb2);
    // Stage 1 (light to color): with white LC identity and zero BK,
    // MAC = LC*IR = IR (identity)
    // Stage 2 (color mult): MAC = (R<<4)*IR1 = 0x800*0x1000 = 0x800000
    // After >>12 = 0x800, /16 = 128
)

// CDP: color depth cue with pre-computed light
CESTER_TEST(cdp_basic, gte_tests,
    gte_set_white_light_color();
    gte_set_zero_bk();
    gte_set_far_color(0x1000, 0x1000, 0x1000);
    GTE_WRITE_DATA(9, 0x1000);
    GTE_WRITE_DATA(10, 0x1000);
    GTE_WRITE_DATA(11, 0x1000);
    GTE_WRITE_DATA(6, 0x00808080);
    GTE_WRITE_DATA(8, 0);  // IR0=0: no depth cue
    gte_clear_flag();
    GTE_EXEC(GTE_CMD_CDP);
    int32_t mac1, mac2, mac3;
    uint32_t rgb2;
    GTE_READ_DATA(25, mac1);
    GTE_READ_DATA(26, mac2);
    GTE_READ_DATA(27, mac3);
    GTE_READ_DATA(22, rgb2);
    ramsyscall_printf("CDP: MAC=(%d,%d,%d) RGB2=0x%08x\n", mac1, mac2, mac3, rgb2);
)

// CDP with depth cue
CESTER_TEST(cdp_with_depth, gte_tests,
    gte_set_white_light_color();
    gte_set_zero_bk();
    gte_set_far_color(0x1000, 0x1000, 0x1000);
    GTE_WRITE_DATA(9, 0x1000);
    GTE_WRITE_DATA(10, 0x1000);
    GTE_WRITE_DATA(11, 0x1000);
    GTE_WRITE_DATA(6, 0x00808080);
    GTE_WRITE_DATA(8, 0x0800);  // IR0=0.5
    gte_clear_flag();
    GTE_EXEC(GTE_CMD_CDP);
    int32_t mac1, mac2, mac3;
    uint32_t rgb2, flag;
    GTE_READ_DATA(25, mac1);
    GTE_READ_DATA(26, mac2);
    GTE_READ_DATA(27, mac3);
    GTE_READ_DATA(22, rgb2);
    flag = gte_read_flag();
    ramsyscall_printf("CDP depth: MAC=(%d,%d,%d) RGB2=0x%08x FLAG=0x%08x\n",
                      mac1, mac2, mac3, rgb2, flag);
)

// Full lighting pipeline: light matrix with non-trivial light direction
CESTER_TEST(ncs_full_light_matrix, gte_tests,
    // Light from (0.707, 0, 0.707) direction - 45 degrees
    // In 4.12 fixed: 0.707 ~ 0x0B50
    GTE_WRITE_CTRL(8, 0x00000b50);   // L11=0x0B50, L12=0
    GTE_WRITE_CTRL(9, 0x00000000);   // L13=0, L21=0
    GTE_WRITE_CTRL(10, 0x00000000);  // L22=0, L23=0
    GTE_WRITE_CTRL(11, 0x00000000);  // L31=0, L32=0
    GTE_WRITE_CTRL(12, 0x0b50);      // L33=0x0B50
    gte_set_white_light_color();
    gte_set_zero_bk();
    // Normal = (0x1000, 0, 0) - facing X
    GTE_WRITE_DATA(0, (0 << 16) | 0x1000);
    GTE_WRITE_DATA(1, 0);
    GTE_WRITE_DATA(6, 0x00000000);
    gte_clear_flag();
    GTE_EXEC(GTE_CMD_NCS);
    int32_t mac1, mac2, mac3;
    GTE_READ_DATA(25, mac1);
    GTE_READ_DATA(26, mac2);
    GTE_READ_DATA(27, mac3);
    ramsyscall_printf("NCS 45deg: MAC=(%d,%d,%d)\n", mac1, mac2, mac3);
    // Stage 1: L * normal = (L11*VX, 0, L31*VX) = (0x0B50*0x1000, 0, 0)
    //   >> 12 = (0x0B50, 0, 0), so IR = (0x0B50, 0, 0)
    // Stage 2: LC * IR = (0x0B50, 0, 0) since LC is identity, BK=0
    // MAC1 = 0x0B50, MAC2 = 0, MAC3 = 0
    cester_assert_int_eq(0x0b50, mac1);
    cester_assert_int_eq(0, mac2);
    cester_assert_int_eq(0, mac3);
)
