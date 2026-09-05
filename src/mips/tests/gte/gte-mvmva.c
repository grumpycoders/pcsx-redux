// MVMVA: parameterized matrix-vector multiply and add

// mx=RT, v=V0, cv=TR (standard transform)
CESTER_TEST(mvmva_rt_v0_tr, gte_tests,
    // 90-degree Z rotation
    cop2_putc(0, 0xf0000000);  // R11=0, R12=-0x1000
    cop2_putc(1, 0x10000000);  // R13=0, R21=0x1000
    cop2_putc(2, 0x00000000);
    cop2_putc(3, 0x00000000);
    cop2_putc(4, 0x1000);
    gte_set_translation(10, 20, 30);
    cop2_put(0, (200 << 16) | 100);
    cop2_put(1, 300);
    gte_clear_flag();
    cop2_cmd(COP2_MVMVA(1, 0, 0, 0, 0));
    int32_t mac1, mac2, mac3;
    cop2_get(25, mac1);
    cop2_get(26, mac2);
    cop2_get(27, mac3);
    cester_assert_int_eq(-190, mac1);
    cester_assert_int_eq(120, mac2);
    cester_assert_int_eq(330, mac3);
)

// mx=RT, v=V1, cv=Zero
CESTER_TEST(mvmva_rt_v1_zero, gte_tests,
    gte_set_identity_rotation();
    cop2_put(2, (40 << 16) | 30);  // V1 = (30, 40)
    cop2_put(3, 50);                // V1.Z = 50
    gte_clear_flag();
    cop2_cmd(COP2_MVMVA(1, 0, 1, 3, 0));
    int32_t mac1, mac2, mac3;
    cop2_get(25, mac1);
    cop2_get(26, mac2);
    cop2_get(27, mac3);
    cester_assert_int_eq(30, mac1);
    cester_assert_int_eq(40, mac2);
    cester_assert_int_eq(50, mac3);
)

// mx=RT, v=V2, cv=BK
CESTER_TEST(mvmva_rt_v2_bk, gte_tests,
    gte_set_identity_rotation();
    cop2_putc(13, 1000);  // RBK
    cop2_putc(14, 2000);  // GBK
    cop2_putc(15, 3000);  // BBK
    cop2_put(4, (200 << 16) | 100);  // V2
    cop2_put(5, 300);
    gte_clear_flag();
    cop2_cmd(COP2_MVMVA(1, 0, 2, 1, 0));
    int32_t mac1, mac2, mac3;
    cop2_get(25, mac1);
    cop2_get(26, mac2);
    cop2_get(27, mac3);
    cester_assert_int_eq(1100, mac1);
    cester_assert_int_eq(2200, mac2);
    cester_assert_int_eq(3300, mac3);
)

// mx=RT, v=IR, cv=Zero
CESTER_TEST(mvmva_rt_ir_zero, gte_tests,
    gte_set_identity_rotation();
    cop2_put(9, 500);
    cop2_put(10, 600);
    cop2_put(11, 700);
    gte_clear_flag();
    cop2_cmd(COP2_MVMVA(1, 0, 3, 3, 0));
    int32_t mac1, mac2, mac3;
    cop2_get(25, mac1);
    cop2_get(26, mac2);
    cop2_get(27, mac3);
    cester_assert_int_eq(500, mac1);
    cester_assert_int_eq(600, mac2);
    cester_assert_int_eq(700, mac3);
)

// mx=LL (light matrix), v=V0, cv=Zero
CESTER_TEST(mvmva_ll_v0_zero, gte_tests,
    gte_set_simple_light();  // L33=0x1000, rest zero
    cop2_put(0, (200 << 16) | 100);
    cop2_put(1, 0x1000);
    gte_clear_flag();
    cop2_cmd(COP2_MVMVA(1, 1, 0, 3, 0));
    int32_t mac1, mac2, mac3;
    cop2_get(25, mac1);
    cop2_get(26, mac2);
    cop2_get(27, mac3);
    // Only L33 is non-zero, so MAC3 = L33*VZ0 >> 12 = 0x1000 * 0x1000 >> 12 = 0x1000
    cester_assert_int_eq(0, mac1);
    cester_assert_int_eq(0, mac2);
    cester_assert_int_eq(0x1000, mac3);
)

// mx=LC (light color), v=IR, cv=BK
CESTER_TEST(mvmva_lc_ir_bk, gte_tests,
    gte_set_white_light_color();
    cop2_putc(13, 100);  // RBK
    cop2_putc(14, 200);  // GBK
    cop2_putc(15, 300);  // BBK
    cop2_put(9, 0x1000);
    cop2_put(10, 0x1000);
    cop2_put(11, 0x1000);
    gte_clear_flag();
    cop2_cmd(COP2_MVMVA(1, 2, 3, 1, 0));
    int32_t mac1, mac2, mac3;
    cop2_get(25, mac1);
    cop2_get(26, mac2);
    cop2_get(27, mac3);
    // White LC identity: MAC = (BK<<12 + LR1*IR1) >> 12 = BK + IR
    // BK = (100, 200, 300), IR = (0x1000, 0x1000, 0x1000) = (4096, 4096, 4096)
    // MAC1 = 100 + 4096 = 4196, etc.
    cester_assert_int_eq(4196, mac1);
    cester_assert_int_eq(4296, mac2);
    cester_assert_int_eq(4396, mac3);
)

// cv=2 (far color) bug
CESTER_TEST(mvmva_cv2_fc_bug, gte_tests,
    gte_set_identity_rotation();
    gte_set_far_color(0x1000, 0x2000, 0x3000);
    cop2_put(0, (0x200 << 16) | 0x100);
    cop2_put(1, 0x300);
    gte_clear_flag();
    cop2_cmd(COP2_MVMVA(1, 0, 0, 2, 0));
    int32_t mac1, mac2, mac3;
    uint32_t flag;
    cop2_get(25, mac1);
    cop2_get(26, mac2);
    cop2_get(27, mac3);
    flag = gte_read_flag();
    // Buggy: result is partial - only last column (R13*VZ, R23*VZ, R33*VZ)
    // With identity: R13=0, R23=0, R33=0x1000
    // MAC1 = R13*VZ >> 12 = 0
    // MAC2 = R23*VZ >> 12 = 0 (but VY contribution leaks? Let's check)
    // MAC3 = R33*VZ >> 12 = 0x300
    ramsyscall_printf("MVMVA cv=2: MAC=(%d,%d,%d) FLAG=0x%08x\n", mac1, mac2, mac3, flag);
    cester_assert_int_eq(0, mac1);
    cester_assert_int_eq(512, mac2);
    cester_assert_int_eq(768, mac3);
    cester_assert_uint_eq(0x00000000, flag);
)

// mx=3 (garbage matrix)
CESTER_TEST(mvmva_mx3_garbage, gte_tests,
    cop2_putc(0, 0x20001000);  // R11=0x1000, R12=0x2000
    cop2_putc(1, 0x40003000);  // R13=0x3000, R21=0x4000
    cop2_putc(2, 0x60005000);  // R22=0x5000, R23=0x6000
    cop2_putc(3, 0x80007000);  // R31=0x7000, R32=-0x8000
    cop2_putc(4, 0x1000);
    cop2_put(8, 0x0800);  // IR0
    cop2_put(0, (0x100 << 16) | 0x100);
    cop2_put(1, 0x100);
    gte_clear_flag();
    cop2_cmd(COP2_MVMVA(1, 3, 0, 3, 0));
    int32_t mac1, mac2, mac3;
    uint32_t flag;
    cop2_get(25, mac1);
    cop2_get(26, mac2);
    cop2_get(27, mac3);
    flag = gte_read_flag();
    ramsyscall_printf("MVMVA mx=3: MAC=(%d,%d,%d) FLAG=0x%08x\n", mac1, mac2, mac3, flag);
    cester_assert_int_eq(128, mac1);
    cester_assert_int_eq(2304, mac2);
    cester_assert_int_eq(3840, mac3);
    cester_assert_uint_eq(0x00000000, flag);
)

// MVMVA with lm=1
CESTER_TEST(mvmva_lm1, gte_tests,
    gte_set_identity_rotation();
    gte_set_translation(-500, -600, -700);
    cop2_put(0, (100 << 16) | 100);
    cop2_put(1, 100);
    gte_clear_flag();
    // sf=1, mx=RT, v=V0, cv=TR, lm=1
    cop2_cmd(COP2_MVMVA(1, 0, 0, 0, 1));
    int32_t mac1;
    uint32_t ir1;
    cop2_get(25, mac1);
    cop2_get(9, ir1);
    // MAC1 = 100 + (-500) = -400
    cester_assert_int_eq(-400, mac1);
    // IR1 with lm=1: clamped to [0, 0x7fff], so -400 -> 0
    cester_assert_uint_eq(0, ir1);
)

// MVMVA sf=0 (no shift)
CESTER_TEST(mvmva_sf0, gte_tests,
    gte_set_identity_rotation();
    gte_set_translation(0, 0, 0);
    cop2_put(0, (10 << 16) | 10);
    cop2_put(1, 10);
    gte_clear_flag();
    cop2_cmd(COP2_MVMVA(0, 0, 0, 3, 0));
    int32_t mac1, mac2, mac3;
    cop2_get(25, mac1);
    cop2_get(26, mac2);
    cop2_get(27, mac3);
    // sf=0: no >>12 shift. MAC = R * V = 0x1000 * 10 = 40960
    cester_assert_int_eq(40960, mac1);
    cester_assert_int_eq(40960, mac2);
    cester_assert_int_eq(40960, mac3);
)
