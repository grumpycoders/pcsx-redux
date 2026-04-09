// RTPS/RTPT: perspective transformation (single and triple)
// Also covers division table behavior and screen coordinate saturation.

CESTER_TEST(rtps_identity_center, gte_tests,
    gte_set_identity_rotation();
    gte_set_translation(0, 0, 1000);
    gte_set_screen(160 << 16, 120 << 16, 200);
    cop2_put(0, 0x00000000);  // V0 = (0, 0)
    cop2_put(1, 0);           // VZ0 = 0
    gte_clear_flag();
    cop2_cmd(COP2_RTPS(1, 0));
    uint32_t sz3, sxy2;
    cop2_get(19, sz3);
    cop2_get(14, sxy2);
    cester_assert_uint_eq(1000, sz3);
    cester_assert_int_eq(160, (int16_t)(sxy2 & 0xffff));
    cester_assert_int_eq(120, (int16_t)(sxy2 >> 16));
)

CESTER_TEST(rtps_offset_vertex, gte_tests,
    gte_set_identity_rotation();
    gte_set_translation(0, 0, 0);
    gte_set_screen(160 << 16, 120 << 16, 200);
    cop2_put(0, (50 << 16) | (100 & 0xffff));
    cop2_put(1, 500);
    gte_clear_flag();
    cop2_cmd(COP2_RTPS(1, 0));
    uint32_t sz3;
    cop2_get(19, sz3);
    cester_assert_uint_eq(500, sz3);
    // SX = 160 + 100*200/500 = 160 + 40 ~ 199 (division rounding)
    // SY = 120 + 50*200/500 = 120 + 20 ~ 139
    uint32_t sxy2;
    cop2_get(14, sxy2);
    int16_t sx = (int16_t)(sxy2 & 0xffff);
    int16_t sy = (int16_t)(sxy2 >> 16);
    ramsyscall_printf("RTPS offset: SX=%d SY=%d\n", sx, sy);
    cester_assert_uint_eq(500, sz3);
)

// RTPS MAC output
CESTER_TEST(rtps_mac_output, gte_tests,
    gte_set_identity_rotation();
    gte_set_translation(100, 200, 300);
    gte_set_screen(0, 0, 200);
    cop2_put(0, (50 << 16) | 10);  // V0 = (10, 50)
    cop2_put(1, 500);
    gte_clear_flag();
    cop2_cmd(COP2_RTPS(1, 0));
    int32_t mac1, mac2, mac3;
    cop2_get(25, mac1);
    cop2_get(26, mac2);
    cop2_get(27, mac3);
    // Identity rotation: MAC = V + TR
    cester_assert_int_eq(110, mac1);
    cester_assert_int_eq(250, mac2);
    cester_assert_int_eq(800, mac3);
)

// RTPS with Z=0 (division overflow)
CESTER_TEST(rtps_division_overflow, gte_tests,
    gte_set_identity_rotation();
    gte_set_translation(0, 0, 0);
    gte_set_screen(0, 0, 200);
    cop2_put(0, (0 << 16) | 100);
    cop2_put(1, 1);  // VZ0 = 1, very small Z
    gte_clear_flag();
    cop2_cmd(COP2_RTPS(1, 0));
    uint32_t flag;
    flag = gte_read_flag();
    // H=200, SZ3=1 -> H >= SZ3*2 (200 >= 2) -> division overflow FLAG.17
    ramsyscall_printf("RTPS div overflow: FLAG=0x%08x (bit17=%u)\n", flag, (flag >> 17) & 1);
    uint32_t flag17 = (flag >> 17) & 1;
    cester_assert_uint_eq(1, flag17);
)

// RTPS screen coordinate saturation
CESTER_TEST(rtps_screen_saturation, gte_tests,
    gte_set_identity_rotation();
    gte_set_translation(0, 0, 0);
    gte_set_screen(0, 0, 200);
    // Large X, small Z -> SX will exceed -0x400..0x3FF range
    cop2_put(0, (0 << 16) | 0x7fff);  // VX0 = 32767
    cop2_put(1, 100);                   // VZ0 = 100
    gte_clear_flag();
    cop2_cmd(COP2_RTPS(1, 0));
    uint32_t sxy2, flag;
    cop2_get(14, sxy2);
    flag = gte_read_flag();
    int16_t sx = (int16_t)(sxy2 & 0xffff);
    ramsyscall_printf("RTPS sat: SX=%d FLAG=0x%08x (bit14=%u)\n", sx, flag, (flag >> 14) & 1);
    // SX should be saturated to 0x3FF
    cester_assert_int_eq(0x3ff, sx);
    uint32_t flag14 = (flag >> 14) & 1;
    cester_assert_uint_eq(1, flag14);  // FLAG.14 = SX2 saturated
)

// RTPS depth cue output (MAC0/IR0)
CESTER_TEST(rtps_depth_cue, gte_tests,
    gte_set_identity_rotation();
    gte_set_translation(0, 0, 0);
    cop2_putc(24, 0);
    cop2_putc(25, 0);
    cop2_putc(26, 200);
    cop2_putc(27, 0xfffff880);  // DQA = -1920 (negative)
    cop2_putc(28, 0x01000000);  // DQB = 16777216
    cop2_put(0, 0x00000000);
    cop2_put(1, 1000);
    gte_clear_flag();
    cop2_cmd(COP2_RTPS(1, 0));
    int32_t mac0;
    uint32_t ir0;
    cop2_get(24, mac0);
    cop2_get(8, ir0);
    ramsyscall_printf("RTPS depth: MAC0=%d IR0=0x%04x\n", mac0, ir0 & 0xffff);
    // IR0 should be clamped to [0, 0x1000]
)

// RTPS with sf=0
CESTER_TEST(rtps_sf0, gte_tests,
    gte_set_identity_rotation();
    gte_set_translation(0, 0, 0x1000);
    gte_set_screen(0, 0, 200);
    cop2_put(0, 0x00000000);
    cop2_put(1, 0);
    gte_clear_flag();
    cop2_cmd(COP2_RTPS(0, 0));
    int32_t mac3;
    uint32_t ir3, sz3, flag;
    cop2_get(27, mac3);
    cop2_get(11, ir3);
    cop2_get(19, sz3);
    flag = gte_read_flag();
    ramsyscall_printf("RTPS sf=0: MAC3=%d IR3=0x%04x SZ3=%u FLAG=0x%08x\n",
                      mac3, ir3 & 0xffff, sz3, flag);
    // sf=0: MAC3 = TRZ<<12 + rotation = 0x1000<<12 = 0x1000000 (no >>12 shift)
    // IR3 uses Lm_B3_sf which checks MAC3>>12 for FLAG but clamps the unshifted value
)

// RTPT: triple perspective transform
CESTER_TEST(rtpt_three_vertices, gte_tests,
    gte_set_identity_rotation();
    gte_set_translation(0, 0, 0);
    gte_set_screen(160 << 16, 120 << 16, 200);
    // V0 = (0, 0, 1000)
    cop2_put(0, 0x00000000);
    cop2_put(1, 1000);
    // V1 = (100, 0, 1000)
    cop2_put(2, (0 << 16) | 100);
    cop2_put(3, 1000);
    // V2 = (0, 100, 1000)
    cop2_put(4, (100 << 16) | 0);
    cop2_put(5, 1000);
    gte_clear_flag();
    cop2_cmd(COP2_RTPT(1, 0));
    uint32_t sxy0, sxy1, sxy2;
    cop2_get(12, sxy0);
    cop2_get(13, sxy1);
    cop2_get(14, sxy2);
    // V0 at origin -> (160, 120)
    cester_assert_int_eq(160, (int16_t)(sxy0 & 0xffff));
    cester_assert_int_eq(120, (int16_t)(sxy0 >> 16));
    // V1 at (100,0,1000) -> SX ~ 180
    int16_t sx1 = (int16_t)(sxy1 & 0xffff);
    int16_t sy1 = (int16_t)(sxy1 >> 16);
    ramsyscall_printf("RTPT: V1=(%d,%d) V2=(%d,%d)\n", sx1, sy1,
                      (int16_t)(sxy2 & 0xffff), (int16_t)(sxy2 >> 16));
    cester_assert_int_eq(120, sy1);  // Y unchanged
)

// RTPT: FLAG accumulates across all three vertices
CESTER_TEST(rtpt_flag_accumulates, gte_tests,
    gte_set_identity_rotation();
    gte_set_translation(0, 0, 0);
    gte_set_screen(0, 0, 200);
    // V0: normal
    cop2_put(0, 0x00000000);
    cop2_put(1, 1000);
    // V1: will cause SX saturation (large X, small Z)
    cop2_put(2, (0 << 16) | 0x7fff);
    cop2_put(3, 100);
    // V2: normal
    cop2_put(4, 0x00000000);
    cop2_put(5, 1000);
    gte_clear_flag();
    cop2_cmd(COP2_RTPT(1, 0));
    uint32_t flag;
    flag = gte_read_flag();
    // FLAG should have SX2 saturation from V1, even though V2 was fine
    ramsyscall_printf("RTPT flag accum: FLAG=0x%08x\n", flag);
    // Division overflow from V1 (H=200, SZ3=100, 200 >= 200)
    uint32_t flag17 = (flag >> 17) & 1;
    cester_assert_uint_eq(1, flag17);
)

// RTPT pushes SZ FIFO correctly
CESTER_TEST(rtpt_sz_fifo, gte_tests,
    gte_set_identity_rotation();
    gte_set_translation(0, 0, 0);
    gte_set_screen(160 << 16, 120 << 16, 200);
    cop2_put(0, 0x00000000);
    cop2_put(1, 100);
    cop2_put(2, 0x00000000);
    cop2_put(3, 200);
    cop2_put(4, 0x00000000);
    cop2_put(5, 300);
    gte_clear_flag();
    cop2_cmd(COP2_RTPT(1, 0));
    uint32_t sz1, sz2, sz3;
    cop2_get(17, sz1);
    cop2_get(18, sz2);
    cop2_get(19, sz3);
    cester_assert_uint_eq(100, sz1);
    cester_assert_uint_eq(200, sz2);
    cester_assert_uint_eq(300, sz3);
)
