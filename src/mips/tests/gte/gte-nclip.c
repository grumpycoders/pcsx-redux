// NCLIP: normal clipping (screen-space triangle winding / area)
// MAC0 = SX0*(SY1-SY2) + SX1*(SY2-SY0) + SX2*(SY0-SY1)

CESTER_TEST(nclip_ccw, gte_tests,
    cop2_put(12, 0x00000000);  // (0,0)
    cop2_put(13, 0x00000064);  // (100,0)
    cop2_put(14, 0x00640000);  // (0,100)
    gte_clear_flag();
    cop2_cmd(COP2_NCLIP);
    int32_t mac0;
    cop2_get(24, mac0);
    cester_assert_int_eq(10000, mac0);
    cester_assert_uint_eq(0, gte_read_flag());
)

CESTER_TEST(nclip_cw, gte_tests,
    cop2_put(12, 0x00000000);
    cop2_put(13, 0x00640000);  // (0,100)
    cop2_put(14, 0x00000064);  // (100,0)
    gte_clear_flag();
    cop2_cmd(COP2_NCLIP);
    int32_t mac0;
    cop2_get(24, mac0);
    cester_assert_int_eq(-10000, mac0);
)

CESTER_TEST(nclip_collinear, gte_tests,
    cop2_put(12, 0x00000000);
    cop2_put(13, 0x00320032);  // (50,50)
    cop2_put(14, 0x00640064);  // (100,100)
    gte_clear_flag();
    cop2_cmd(COP2_NCLIP);
    int32_t mac0;
    cop2_get(24, mac0);
    cester_assert_int_eq(0, mac0);
)

// NCLIP with large screen coords near saturation limits
CESTER_TEST(nclip_large_coords, gte_tests,
    // SXY values near the screen coord limits (-0x400..0x3FF)
    cop2_put(12, (0xfc00 << 16) | 0x03ff);  // (0x3FF, -0x400)
    cop2_put(13, (0x03ff << 16) | 0xfc00);  // (-0x400, 0x3FF)
    cop2_put(14, 0x00000000);                // (0, 0)
    gte_clear_flag();
    cop2_cmd(COP2_NCLIP);
    int32_t mac0;
    uint32_t flag;
    cop2_get(24, mac0);
    flag = gte_read_flag();
    // (0x3FF * 0x3FF) + (-0x400 * 0) + (0 * (-0x400))
    // - (0x3FF * 0) - (-0x400 * (-0x400)) - (0 * 0x3FF)
    // = 0x3FF*0x3FF - 0x400*0x400 = 1046529 - 1048576 = -2047
    // Actually: SX0=0x3FF, SY0=-0x400, SX1=-0x400, SY1=0x3FF, SX2=0, SY2=0
    // MAC0 = SX0*(SY1-SY2) + SX1*(SY2-SY0) + SX2*(SY0-SY1)
    //      = 0x3FF*(0x3FF-0) + (-0x400)*(0-(-0x400)) + 0*((-0x400)-0x3FF)
    //      = 0x3FF*0x3FF + (-0x400)*0x400
    //      = 1046529 - 1048576 = -2047
    ramsyscall_printf("NCLIP large: MAC0=%d FLAG=0x%08x\n", mac0, flag);
)

// NCLIP MAC0 overflow: maximum possible cross product
CESTER_TEST(nclip_overflow, gte_tests,
    // Use values that produce MAC0 > 0x7FFFFFFF
    // Max SX/SY after saturation is -0x400..0x3FF (11-bit signed)
    // Max cross product: 0x3FF*0x3FF*2 + 0x400*0x400*2 ~ 4 million, no overflow
    // Need unsaturated values: SXY registers are 16-bit signed
    cop2_put(12, (0x7fff << 16) | 0x7fff);  // (32767, 32767)
    cop2_put(13, (0x8000 << 16) | 0x8000);  // (-32768, -32768)
    cop2_put(14, (0x7fff << 16) | 0x8000);  // (-32768, 32767)
    gte_clear_flag();
    cop2_cmd(COP2_NCLIP);
    int32_t mac0;
    uint32_t flag;
    cop2_get(24, mac0);
    flag = gte_read_flag();
    ramsyscall_printf("NCLIP overflow: MAC0=%d FLAG=0x%08x\n", mac0, flag);
    // Check if FLAG.16 or FLAG.15 (MAC0 overflow) is set
    ramsyscall_printf("  FLAG.16=%u FLAG.15=%u\n", (flag >> 16) & 1, (flag >> 15) & 1);
)
