// SQR: square of IR vector

CESTER_TEST(sqr_shifted, gte_tests,
    cop2_put(9, 0x1000);   // 1.0
    cop2_put(10, 0x0800);  // 0.5
    cop2_put(11, 0x2000);  // 2.0
    gte_clear_flag();
    cop2_cmd(COP2_SQR(1, 0));
    uint32_t ir1, ir2, ir3;
    cop2_get(9, ir1);
    cop2_get(10, ir2);
    cop2_get(11, ir3);
    cester_assert_uint_eq(0x1000, ir1);  // 1.0^2 = 1.0
    cester_assert_uint_eq(0x0400, ir2);  // 0.5^2 = 0.25
    cester_assert_uint_eq(0x4000, ir3);  // 2.0^2 = 4.0 (no saturation, lm=0)
)

CESTER_TEST(sqr_unshifted, gte_tests,
    cop2_put(9, 4);
    cop2_put(10, 5);
    cop2_put(11, 6);
    gte_clear_flag();
    cop2_cmd(COP2_SQR(0, 0));
    uint32_t ir1, ir2, ir3;
    cop2_get(9, ir1);
    cop2_get(10, ir2);
    cop2_get(11, ir3);
    cester_assert_uint_eq(16, ir1);
    cester_assert_uint_eq(25, ir2);
    cester_assert_uint_eq(36, ir3);
)

// SQR sets MAC1-3 as well
CESTER_TEST(sqr_mac_output, gte_tests,
    cop2_put(9, 100);
    cop2_put(10, 200);
    cop2_put(11, 300);
    gte_clear_flag();
    cop2_cmd(COP2_SQR(0, 0));
    int32_t mac1, mac2, mac3;
    cop2_get(25, mac1);
    cop2_get(26, mac2);
    cop2_get(27, mac3);
    cester_assert_int_eq(10000, mac1);
    cester_assert_int_eq(40000, mac2);
    cester_assert_int_eq(90000, mac3);
)

// SQR with IR saturation (shifted, result > 0x7fff with lm=0)
CESTER_TEST(sqr_saturation_shifted, gte_tests,
    cop2_put(9, 0x4000);  // 4.0 in 4.12; 4^2 = 16, >>12 = 0x4000 (fits)
    cop2_put(10, 0x5a82); // ~5.656 (sqrt(32)); 32 >>12 = 0x8000 = saturates
    cop2_put(11, 0x7fff); // max positive; 0x7fff^2 >>12 = huge, saturates
    gte_clear_flag();
    cop2_cmd(COP2_SQR(1, 0));
    uint32_t ir1, ir2, ir3;
    uint32_t flag;
    cop2_get(9, ir1);
    cop2_get(10, ir2);
    cop2_get(11, ir3);
    flag = gte_read_flag();
    ramsyscall_printf("SQR sat: IR1=0x%04x IR2=0x%04x IR3=0x%04x FLAG=0x%08x\n",
                      ir1 & 0xffff, ir2 & 0xffff, ir3 & 0xffff, flag);
)

// SQR with negative input (result should still be positive: square)
CESTER_TEST(sqr_negative_input, gte_tests,
    cop2_put(9, 0xfffffff6);  // -10 (sign-extended)
    cop2_put(10, 0xffffffce); // -50
    cop2_put(11, 0xffffff9c); // -100
    gte_clear_flag();
    cop2_cmd(COP2_SQR(0, 0));
    int32_t mac1, mac2, mac3;
    cop2_get(25, mac1);
    cop2_get(26, mac2);
    cop2_get(27, mac3);
    // Squares of negative numbers are positive
    // But GTE multiplies IR*IR where IR is 16-bit signed
    // -10 * -10 = 100, -50 * -50 = 2500, -100 * -100 = 10000
    ramsyscall_printf("SQR neg: MAC1=%d MAC2=%d MAC3=%d\n", mac1, mac2, mac3);
)
