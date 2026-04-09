// AVSZ3 / AVSZ4: Average Z value computation

CESTER_TEST(avsz3_basic, gte_tests,
    GTE_WRITE_DATA(17, 100);
    GTE_WRITE_DATA(18, 200);
    GTE_WRITE_DATA(19, 300);
    GTE_WRITE_CTRL(29, 0x555);  // ZSF3 ~ 4096/3
    gte_clear_flag();
    GTE_EXEC(GTE_CMD_AVSZ3);
    int32_t mac0;
    uint32_t otz;
    GTE_READ_DATA(24, mac0);
    GTE_READ_DATA(7, otz);
    cester_assert_int_eq(819000, mac0);
    cester_assert_uint_eq(199, otz);
)

CESTER_TEST(avsz4_basic, gte_tests,
    GTE_WRITE_DATA(16, 100);
    GTE_WRITE_DATA(17, 200);
    GTE_WRITE_DATA(18, 300);
    GTE_WRITE_DATA(19, 400);
    GTE_WRITE_CTRL(30, 0x400);  // ZSF4 = 4096/4
    gte_clear_flag();
    GTE_EXEC(GTE_CMD_AVSZ4);
    int32_t mac0;
    uint32_t otz;
    GTE_READ_DATA(24, mac0);
    GTE_READ_DATA(7, otz);
    cester_assert_int_eq(1024000, mac0);
    cester_assert_uint_eq(250, otz);
)

// Verify AVSZ3 uses SZ1+SZ2+SZ3, not SZ0+SZ1+SZ2
CESTER_TEST(avsz3_uses_sz123, gte_tests,
    GTE_WRITE_DATA(16, 1000);   // SZ0 - should be ignored
    GTE_WRITE_DATA(17, 2000);   // SZ1
    GTE_WRITE_DATA(18, 3000);   // SZ2
    GTE_WRITE_DATA(19, 4000);   // SZ3
    GTE_WRITE_CTRL(29, 0x1000); // ZSF3 = 1.0 in 4.12
    gte_clear_flag();
    GTE_EXEC(GTE_CMD_AVSZ3);
    int32_t mac0;
    GTE_READ_DATA(24, mac0);
    // SZ1+SZ2+SZ3 = 9000, * 4096 = 36864000
    cester_assert_int_eq(36864000, mac0);
)

// OTZ saturation: result > 0xffff
CESTER_TEST(avsz3_otz_saturate, gte_tests,
    GTE_WRITE_DATA(17, 0xffff);
    GTE_WRITE_DATA(18, 0xffff);
    GTE_WRITE_DATA(19, 0xffff);
    GTE_WRITE_CTRL(29, 0x1000);
    gte_clear_flag();
    GTE_EXEC(GTE_CMD_AVSZ3);
    uint32_t otz, flag;
    GTE_READ_DATA(7, otz);
    flag = gte_read_flag();
    cester_assert_uint_eq(0xffff, otz);
    // FLAG.18 (OTZ saturation) should be set
    uint32_t flag18 = (flag >> 18) & 1;
    cester_assert_uint_eq(1, flag18);
)

// Negative ZSF producing negative MAC0
CESTER_TEST(avsz3_negative_zsf, gte_tests,
    GTE_WRITE_DATA(17, 100);
    GTE_WRITE_DATA(18, 200);
    GTE_WRITE_DATA(19, 300);
    GTE_WRITE_CTRL(29, 0xf000);  // ZSF3 = negative (sign-extended)
    gte_clear_flag();
    GTE_EXEC(GTE_CMD_AVSZ3);
    int32_t mac0;
    uint32_t otz, flag;
    GTE_READ_DATA(24, mac0);
    GTE_READ_DATA(7, otz);
    flag = gte_read_flag();
    ramsyscall_printf("AVSZ3 neg ZSF: MAC0=%d OTZ=%u FLAG=0x%08x\n", mac0, otz, flag);
    // Negative result should saturate OTZ to 0
    cester_assert_uint_eq(0, otz);
)
