// AVSZ3 / AVSZ4: Average Z value computation

CESTER_TEST(avsz3_basic, gte_tests,
    cop2_put(17, 100);
    cop2_put(18, 200);
    cop2_put(19, 300);
    cop2_putc(29, 0x555);  // ZSF3 ~ 4096/3
    gte_clear_flag();
    cop2_cmd(COP2_AVSZ3);
    int32_t mac0;
    uint32_t otz;
    cop2_get(24, mac0);
    cop2_get(7, otz);
    cester_assert_int_eq(819000, mac0);
    cester_assert_uint_eq(199, otz);
)

CESTER_TEST(avsz4_basic, gte_tests,
    cop2_put(16, 100);
    cop2_put(17, 200);
    cop2_put(18, 300);
    cop2_put(19, 400);
    cop2_putc(30, 0x400);  // ZSF4 = 4096/4
    gte_clear_flag();
    cop2_cmd(COP2_AVSZ4);
    int32_t mac0;
    uint32_t otz;
    cop2_get(24, mac0);
    cop2_get(7, otz);
    cester_assert_int_eq(1024000, mac0);
    cester_assert_uint_eq(250, otz);
)

// Verify AVSZ3 uses SZ1+SZ2+SZ3, not SZ0+SZ1+SZ2
CESTER_TEST(avsz3_uses_sz123, gte_tests,
    cop2_put(16, 1000);   // SZ0 - should be ignored
    cop2_put(17, 2000);   // SZ1
    cop2_put(18, 3000);   // SZ2
    cop2_put(19, 4000);   // SZ3
    cop2_putc(29, 0x1000); // ZSF3 = 1.0 in 4.12
    gte_clear_flag();
    cop2_cmd(COP2_AVSZ3);
    int32_t mac0;
    cop2_get(24, mac0);
    // SZ1+SZ2+SZ3 = 9000, * 4096 = 36864000
    cester_assert_int_eq(36864000, mac0);
)

// OTZ saturation: result > 0xffff
CESTER_TEST(avsz3_otz_saturate, gte_tests,
    cop2_put(17, 0xffff);
    cop2_put(18, 0xffff);
    cop2_put(19, 0xffff);
    cop2_putc(29, 0x1000);
    gte_clear_flag();
    cop2_cmd(COP2_AVSZ3);
    uint32_t otz, flag;
    cop2_get(7, otz);
    flag = gte_read_flag();
    cester_assert_uint_eq(0xffff, otz);
    // FLAG.18 (OTZ saturation) should be set
    uint32_t flag18 = (flag >> 18) & 1;
    cester_assert_uint_eq(1, flag18);
)

// Negative ZSF producing negative MAC0
CESTER_TEST(avsz3_negative_zsf, gte_tests,
    cop2_put(17, 100);
    cop2_put(18, 200);
    cop2_put(19, 300);
    cop2_putc(29, 0xf000);  // ZSF3 = negative (sign-extended)
    gte_clear_flag();
    cop2_cmd(COP2_AVSZ3);
    int32_t mac0;
    uint32_t otz, flag;
    cop2_get(24, mac0);
    cop2_get(7, otz);
    flag = gte_read_flag();
    ramsyscall_printf("AVSZ3 neg ZSF: MAC0=%d OTZ=%u FLAG=0x%08x\n", mac0, otz, flag);
    // Negative result should saturate OTZ to 0
    cester_assert_uint_eq(0, otz);
)
