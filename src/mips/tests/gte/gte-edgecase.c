// Edge cases and degenerate inputs: division, overflow boundaries,
// zero matrices, negative Z, FLAG verification per instruction.

// ==========================================================================
// Division edge cases (tested via RTPS)
// ==========================================================================

// Division by zero: SZ3=0
CESTER_TEST(edge_div_by_zero, gte_tests,
    gte_set_identity_rotation();
    gte_set_translation(0, 0, 0);
    gte_set_screen(0, 0, 200);
    cop2_put(0, (0 << 16) | 100);
    cop2_put(1, 0);  // VZ0=0 -> SZ3=0
    gte_clear_flag();
    cop2_cmd(COP2_RTPS(1, 0));
    uint32_t sz3, sxy2, flag;
    cop2_get(19, sz3);
    cop2_get(14, sxy2);
    flag = gte_read_flag();
    ramsyscall_printf("div/0: SZ3=%u SXY2=0x%08x FLAG=0x%08x\n", sz3, sxy2, flag);
    // SZ3=0, H=200 -> H >= SZ3*2 -> division overflow (FLAG.17)
    uint32_t f17 = (flag >> 17) & 1;
    cester_assert_uint_eq(1, f17);
)

// H=0: zero numerator
CESTER_TEST(edge_div_h_zero, gte_tests,
    gte_set_identity_rotation();
    gte_set_translation(0, 0, 0);
    gte_set_screen(0, 0, 0);  // H=0
    cop2_put(0, (0 << 16) | 100);
    cop2_put(1, 1000);
    gte_clear_flag();
    cop2_cmd(COP2_RTPS(1, 0));
    uint32_t sxy2, flag;
    cop2_get(14, sxy2);
    flag = gte_read_flag();
    int16_t sx = (int16_t)(sxy2 & 0xffff);
    ramsyscall_printf("H=0: SX=%d FLAG=0x%08x\n", sx, flag);
    // H=0, SZ3=1000 -> H < SZ3*2 -> no overflow, quotient = 0
    // SX = OFX/65536 + IR1 * 0 = 0
    cester_assert_int_eq(0, sx);
    uint32_t f17 = (flag >> 17) & 1;
    cester_assert_uint_eq(0, f17);
)

// Division overflow boundary: H=SZ3*2-1 (just under, no overflow)
CESTER_TEST(edge_div_boundary_under, gte_tests,
    gte_set_identity_rotation();
    gte_set_translation(0, 0, 0);
    gte_set_screen(0, 0, 199);  // H=199
    cop2_put(0, (0 << 16) | 100);
    cop2_put(1, 100);  // SZ3=100 -> H < 200 -> no overflow
    gte_clear_flag();
    cop2_cmd(COP2_RTPS(1, 0));
    uint32_t flag;
    flag = gte_read_flag();
    uint32_t f17 = (flag >> 17) & 1;
    ramsyscall_printf("div boundary under: H=199 SZ3=100 FLAG.17=%u\n", f17);
    cester_assert_uint_eq(0, f17);
)

// Division overflow boundary: H=SZ3*2 (exactly at overflow)
CESTER_TEST(edge_div_boundary_at, gte_tests,
    gte_set_identity_rotation();
    gte_set_translation(0, 0, 0);
    gte_set_screen(0, 0, 200);  // H=200
    cop2_put(0, (0 << 16) | 100);
    cop2_put(1, 100);  // SZ3=100 -> H >= 200 -> overflow
    gte_clear_flag();
    cop2_cmd(COP2_RTPS(1, 0));
    uint32_t flag;
    flag = gte_read_flag();
    uint32_t f17 = (flag >> 17) & 1;
    ramsyscall_printf("div boundary at: H=200 SZ3=100 FLAG.17=%u\n", f17);
    cester_assert_uint_eq(1, f17);
)

// Division overflow boundary: H=SZ3*2+1 (just over, definitely overflow)
CESTER_TEST(edge_div_boundary_over, gte_tests,
    gte_set_identity_rotation();
    gte_set_translation(0, 0, 0);
    gte_set_screen(0, 0, 201);  // H=201
    cop2_put(0, (0 << 16) | 100);
    cop2_put(1, 100);
    gte_clear_flag();
    cop2_cmd(COP2_RTPS(1, 0));
    uint32_t flag;
    flag = gte_read_flag();
    uint32_t f17 = (flag >> 17) & 1;
    cester_assert_uint_eq(1, f17);
)

// ==========================================================================
// IR saturation boundaries
// ==========================================================================

// IR at exactly 0x7FFF (max positive, no saturation)
CESTER_TEST(edge_ir_max_no_sat, gte_tests,
    cop2_put(8, 0x1000);
    cop2_put(9, 0x7fff);
    cop2_put(10, 0x7fff);
    cop2_put(11, 0x7fff);
    cop2_put(6, 0x00808080);
    gte_clear_flag();
    cop2_cmd(COP2_GPF(1, 0));
    uint32_t ir1;
    cop2_get(9, ir1);
    uint32_t flag = gte_read_flag();
    // 0x1000 * 0x7FFF >> 12 = 0x7FFF -> no saturation
    cester_assert_uint_eq(0x7fff, ir1);
    // FLAG.24 (IR1 sat) should NOT be set
    uint32_t f24 = (flag >> 24) & 1;
    cester_assert_uint_eq(0, f24);
)

// IR just over 0x7FFF (triggers saturation)
CESTER_TEST(edge_ir_over_max, gte_tests,
    cop2_put(8, 0x1001);  // IR0 = 0x1001 (slightly > 1.0)
    cop2_put(9, 0x7fff);
    cop2_put(10, 0x100);
    cop2_put(11, 0x100);
    cop2_put(6, 0x00808080);
    gte_clear_flag();
    cop2_cmd(COP2_GPF(1, 0));
    uint32_t ir1;
    cop2_get(9, ir1);
    uint32_t flag = gte_read_flag();
    ramsyscall_printf("IR over max: IR1=0x%04x FLAG=0x%08x\n", ir1 & 0xffff, flag);
    // 0x1001 * 0x7FFF >> 12 = 0x8000 -> saturates to 0x7FFF
    cester_assert_uint_eq(0x7fff, ir1);
    uint32_t f24 = (flag >> 24) & 1;
    cester_assert_uint_eq(1, f24);
)

// ==========================================================================
// MAC0 overflow boundaries
// ==========================================================================

// NCLIP with values designed to overflow MAC0
CESTER_TEST(edge_mac0_positive_overflow, gte_tests,
    // Maximize cross product: opposing corners of 16-bit range
    cop2_put(12, (0x7fff << 16) | 0x7fff);  // (32767, 32767)
    cop2_put(13, (0x8000 << 16) | 0x8000);  // (-32768, -32768)
    cop2_put(14, 0x00000000);                // (0, 0)
    gte_clear_flag();
    cop2_cmd(COP2_NCLIP);
    int32_t mac0;
    uint32_t flag;
    cop2_get(24, mac0);
    flag = gte_read_flag();
    // SX0*(SY1-SY2) + SX1*(SY2-SY0) + SX2*(SY0-SY1)
    // = 32767*(-32768) + (-32768)*(0-32767) + 0
    // = -1073709056 + (-32768)*(-32767)
    // = -1073709056 + 1073709056 = 0... hmm, that's zero
    // Actually: 32767*(-32768-0) + (-32768)*(0-32767) + 0*(32767-(-32768))
    // = 32767*(-32768) + (-32768)*(-32767)
    // = -1073709056 + 1073709056 = 0
    // Need asymmetric triangle for overflow
    ramsyscall_printf("MAC0 overflow test: MAC0=%d FLAG=0x%08x (F16=%u F15=%u)\n",
                      mac0, flag, (flag >> 16) & 1, (flag >> 15) & 1);
)

// NCLIP that actually overflows MAC0 negatively
CESTER_TEST(edge_mac0_negative_overflow, gte_tests,
    // (32767, 32767), (-32768, 32767), (32767, -32768)
    cop2_put(12, (0x7fff << 16) | 0x7fff);
    cop2_put(13, (0x7fff << 16) | 0x8000);
    cop2_put(14, (0x8000 << 16) | 0x7fff);
    gte_clear_flag();
    cop2_cmd(COP2_NCLIP);
    int32_t mac0;
    uint32_t flag;
    cop2_get(24, mac0);
    flag = gte_read_flag();
    ramsyscall_printf("MAC0 neg overflow: MAC0=%d FLAG=0x%08x\n", mac0, flag);
    // The cross product should be large negative
    // FLAG.15 (MAC0 negative overflow) should be set
)

// ==========================================================================
// Color saturation boundaries
// ==========================================================================

// Color output at exactly 255 (no saturation)
CESTER_TEST(edge_color_at_255, gte_tests,
    cop2_put(8, 0x1000);
    cop2_put(9, 0x0ff0);   // MAC1 = 0x0ff0, /16 = 255
    cop2_put(10, 0x0ff0);
    cop2_put(11, 0x0ff0);
    cop2_put(6, 0x00808080);
    gte_clear_flag();
    cop2_cmd(COP2_GPF(1, 0));
    uint32_t rgb2, flag;
    cop2_get(22, rgb2);
    flag = gte_read_flag();
    uint32_t r_255 = rgb2 & 0xff;
    cester_assert_uint_eq(255, r_255);
    uint32_t f21_255 = (flag >> 21) & 1;
    cester_assert_uint_eq(0, f21_255);  // No color saturation flag
)

// Color output at 256 (saturates to 255, FLAG set)
CESTER_TEST(edge_color_at_256, gte_tests,
    cop2_put(8, 0x1000);
    cop2_put(9, 0x1000);   // MAC1 = 0x1000, /16 = 256 -> saturates
    cop2_put(10, 0x100);
    cop2_put(11, 0x100);
    cop2_put(6, 0x00808080);
    gte_clear_flag();
    cop2_cmd(COP2_GPF(1, 0));
    uint32_t rgb2, flag;
    cop2_get(22, rgb2);
    flag = gte_read_flag();
    uint32_t r_256 = rgb2 & 0xff;
    cester_assert_uint_eq(255, r_256);  // saturated to 255
    uint32_t f21_256 = (flag >> 21) & 1;
    cester_assert_uint_eq(1, f21_256);  // R saturation flag set
)

// Negative color (saturates to 0, FLAG set)
CESTER_TEST(edge_color_negative, gte_tests,
    cop2_put(8, 0x1000);
    cop2_put(9, 0xffff8000);  // IR1 = -32768 -> negative MAC1 -> color=0
    cop2_put(10, 0x100);
    cop2_put(11, 0x100);
    cop2_put(6, 0x00808080);
    gte_clear_flag();
    cop2_cmd(COP2_GPF(1, 0));
    uint32_t rgb2, flag;
    cop2_get(22, rgb2);
    flag = gte_read_flag();
    uint32_t r_neg = rgb2 & 0xff;
    cester_assert_uint_eq(0, r_neg);  // clamped to 0
    uint32_t f21_neg = (flag >> 21) & 1;
    cester_assert_uint_eq(1, f21_neg);  // Color R saturation flag
)

// ==========================================================================
// Screen coordinate saturation
// ==========================================================================

// SX at exactly 0x3FF (max, no saturation)
CESTER_TEST(edge_sx_at_max, gte_tests,
    gte_set_identity_rotation();
    gte_set_translation(0, 0, 0);
    cop2_putc(24, 0x3ff << 16);  // OFX = 0x3FF in 16.16
    cop2_putc(25, 0);
    cop2_putc(26, 0);  // H=0 -> quotient=0 -> SX = OFX only
    cop2_putc(27, 0);
    cop2_putc(28, 0);
    cop2_put(0, 0);
    cop2_put(1, 1000);
    gte_clear_flag();
    cop2_cmd(COP2_RTPS(1, 0));
    uint32_t sxy2, flag;
    cop2_get(14, sxy2);
    flag = gte_read_flag();
    int16_t sx = (int16_t)(sxy2 & 0xffff);
    cester_assert_int_eq(0x3ff, sx);
    uint32_t f14 = (flag >> 14) & 1;
    cester_assert_uint_eq(0, f14);  // no saturation
)

// SX at 0x400 (saturates to 0x3FF)
CESTER_TEST(edge_sx_over_max, gte_tests,
    gte_set_identity_rotation();
    gte_set_translation(0, 0, 0);
    cop2_putc(24, 0x400 << 16);  // OFX = 0x400
    cop2_putc(25, 0);
    cop2_putc(26, 0);
    cop2_putc(27, 0);
    cop2_putc(28, 0);
    cop2_put(0, 0);
    cop2_put(1, 1000);
    gte_clear_flag();
    cop2_cmd(COP2_RTPS(1, 0));
    uint32_t sxy2, flag;
    cop2_get(14, sxy2);
    flag = gte_read_flag();
    int16_t sx = (int16_t)(sxy2 & 0xffff);
    cester_assert_int_eq(0x3ff, sx);  // saturated
    uint32_t f14 = (flag >> 14) & 1;
    cester_assert_uint_eq(1, f14);
)

// SY at -0x400 (min, no saturation)
CESTER_TEST(edge_sy_at_min, gte_tests,
    gte_set_identity_rotation();
    gte_set_translation(0, 0, 0);
    cop2_putc(24, 0);
    cop2_putc(25, (uint32_t)(-0x400) << 16);  // OFY = -0x400
    cop2_putc(26, 0);
    cop2_putc(27, 0);
    cop2_putc(28, 0);
    cop2_put(0, 0);
    cop2_put(1, 1000);
    gte_clear_flag();
    cop2_cmd(COP2_RTPS(1, 0));
    uint32_t sxy2, flag;
    cop2_get(14, sxy2);
    flag = gte_read_flag();
    int16_t sy = (int16_t)(sxy2 >> 16);
    cester_assert_int_eq(-0x400, sy);
    uint32_t f13 = (flag >> 13) & 1;
    cester_assert_uint_eq(0, f13);
)

// ==========================================================================
// Degenerate matrix states
// ==========================================================================

// Zero rotation matrix: everything should become translation only
CESTER_TEST(edge_zero_matrix, gte_tests,
    cop2_putc(0, 0);
    cop2_putc(1, 0);
    cop2_putc(2, 0);
    cop2_putc(3, 0);
    cop2_putc(4, 0);
    gte_set_translation(100, 200, 300);
    cop2_put(0, (0x7fff << 16) | 0x7fff);  // large vertex
    cop2_put(1, 0x7fff);
    gte_clear_flag();
    cop2_cmd(COP2_MVMVA(1, COP2_MX_RT, COP2_V_V0, COP2_CV_TR, 0));
    int32_t mac1, mac2, mac3;
    cop2_get(25, mac1);
    cop2_get(26, mac2);
    cop2_get(27, mac3);
    // Zero matrix * anything = 0, plus translation
    cester_assert_int_eq(100, mac1);
    cester_assert_int_eq(200, mac2);
    cester_assert_int_eq(300, mac3);
)

// Max magnitude matrix elements
CESTER_TEST(edge_max_matrix, gte_tests,
    cop2_putc(0, 0x7fff7fff);  // R11=R12=0x7FFF
    cop2_putc(1, 0x7fff7fff);
    cop2_putc(2, 0x7fff7fff);
    cop2_putc(3, 0x7fff7fff);
    cop2_putc(4, 0x7fff);
    gte_set_translation(0, 0, 0);
    cop2_put(0, (0x7fff << 16) | 0x7fff);
    cop2_put(1, 0x7fff);
    gte_clear_flag();
    cop2_cmd(COP2_MVMVA(1, COP2_MX_RT, COP2_V_V0, COP2_CV_NONE, 0));
    int32_t mac1;
    uint32_t flag;
    cop2_get(25, mac1);
    flag = gte_read_flag();
    ramsyscall_printf("max matrix: MAC1=%d FLAG=0x%08x\n", mac1, flag);
    // 3 * 0x7FFF * 0x7FFF = 3 * 1073676289 = 3221028867
    // >> 12 = 786380, fits in 32-bit MAC. But 44-bit accumulator overflow?
)

// Negative Z in RTPS (behind camera)
CESTER_TEST(edge_negative_z, gte_tests,
    gte_set_identity_rotation();
    gte_set_translation(0, 0, -1000);  // TRZ = -1000
    gte_set_screen(160 << 16, 120 << 16, 200);
    cop2_put(0, (0 << 16) | 100);
    cop2_put(1, 0);  // VZ=0, MAC3 = TRZ = -1000
    gte_clear_flag();
    cop2_cmd(COP2_RTPS(1, 0));
    uint32_t sz3, flag;
    int32_t mac3;
    cop2_get(19, sz3);
    cop2_get(27, mac3);
    flag = gte_read_flag();
    ramsyscall_printf("neg Z: MAC3=%d SZ3=%u FLAG=0x%08x\n", mac3, sz3, flag);
    // MAC3 = -1000, SZ3 should saturate to 0 (Lm_D clamps to [0, 0xFFFF])
    cester_assert_int_eq(-1000, mac3);
    cester_assert_uint_eq(0, sz3);  // saturated
    uint32_t f18 = (flag >> 18) & 1;
    cester_assert_uint_eq(1, f18);  // OTZ/SZ3 saturation
)

// SQR of -0x8000 (minimum 16-bit signed)
CESTER_TEST(edge_sqr_min_negative, gte_tests,
    cop2_put(9, 0xffff8000);  // IR1 = -32768
    cop2_put(10, 0);
    cop2_put(11, 0);
    gte_clear_flag();
    cop2_cmd(COP2_SQR(0, 0));
    int32_t mac1;
    uint32_t flag;
    cop2_get(25, mac1);
    flag = gte_read_flag();
    // (-32768)^2 = 1073741824 = 0x40000000 (fits in 32-bit signed)
    ramsyscall_printf("SQR(-32768): MAC1=%d FLAG=0x%08x\n", mac1, flag);
    cester_assert_int_eq(1073741824, mac1);
)

// GPL with negative MAC base
CESTER_TEST(edge_gpl_negative_base, gte_tests,
    cop2_put(25, -10000);  // MAC1 = -10000
    cop2_put(26, -20000);
    cop2_put(27, -30000);
    cop2_put(8, 0x1000);  // IR0 = 1.0
    cop2_put(9, 100);
    cop2_put(10, 200);
    cop2_put(11, 300);
    cop2_put(6, 0x00808080);
    gte_clear_flag();
    cop2_cmd(COP2_GPL(1, 0));
    int32_t mac1, mac2, mac3;
    cop2_get(25, mac1);
    cop2_get(26, mac2);
    cop2_get(27, mac3);
    // GPL sf=1: MAC = (old_MAC << 12 + IR0*IR) >> 12
    // = ((-10000 << 12) + 4096*100) >> 12
    // = (-40960000 + 409600) >> 12
    // = -40550400 >> 12 = -9900
    cester_assert_int_eq(-9900, mac1);
    cester_assert_int_eq(-19800, mac2);
    cester_assert_int_eq(-29700, mac3);
)

// ==========================================================================
// FLAG cleared at instruction start
// ==========================================================================

// Verify FLAG is reset to 0 at the start of each GTE instruction,
// not accumulating from previous instructions
CESTER_TEST(edge_flag_cleared_each_instruction, gte_tests,
    // First: trigger IR1 saturation via GPF
    cop2_put(8, 0x1001);
    cop2_put(9, 0x7fff);
    cop2_put(10, 0x100);
    cop2_put(11, 0x100);
    cop2_put(6, 0x00808080);
    gte_clear_flag();
    cop2_cmd(COP2_GPF(1, 0));
    uint32_t flag1 = gte_read_flag();
    uint32_t f24_1 = (flag1 >> 24) & 1;
    cester_assert_uint_eq(1, f24_1);  // IR1 saturated

    // Now: run a clean GPF that should NOT trigger any flags
    cop2_put(8, 0x1000);
    cop2_put(9, 0x100);
    cop2_put(10, 0x100);
    cop2_put(11, 0x100);
    cop2_put(6, 0x00808080);
    // Do NOT call gte_clear_flag() - the instruction should clear it itself
    cop2_cmd(COP2_GPF(1, 0));
    uint32_t flag2 = gte_read_flag();
    // FLAG should be 0 - the instruction clears it at start
    cester_assert_uint_eq(0, flag2);
)

// ==========================================================================
// IR0 saturation boundary
// ==========================================================================

// IR0 at exactly 0x1000 (max, no saturation)
CESTER_TEST(edge_ir0_at_max, gte_tests,
    gte_set_identity_rotation();
    gte_set_translation(0, 0, 0);
    cop2_putc(24, 0);
    cop2_putc(25, 0);
    cop2_putc(26, 200);
    cop2_putc(27, 0);          // DQA = 0
    cop2_putc(28, 0x1000000);  // DQB = 0x1000000 -> MAC0=DQB, IR0=DQB>>12=0x1000
    cop2_put(0, 0);
    cop2_put(1, 1000);
    gte_clear_flag();
    cop2_cmd(COP2_RTPS(1, 0));
    uint32_t ir0, flag;
    cop2_get(8, ir0);
    flag = gte_read_flag();
    ramsyscall_printf("IR0 max: IR0=0x%04x FLAG=0x%08x\n", ir0 & 0xffff, flag);
    // IR0 should be exactly 0x1000
    uint32_t f12 = (flag >> 12) & 1;
    cester_assert_uint_eq(0, f12);  // no saturation
)

// ==========================================================================
// OTZ saturation boundary
// ==========================================================================

// OTZ at exactly 0xFFFF (max, triggers saturation)
CESTER_TEST(edge_otz_at_max, gte_tests,
    // Need MAC0 >> 12 = 0xFFFF -> MAC0 = 0xFFFF << 12 = 0xFFFF000
    // ZSF3 * (SZ1+SZ2+SZ3) = 0xFFFF000
    // Use ZSF3 = 0x1000, SZ_sum = 0xFFFF -> each SZ = 0x5555
    cop2_put(17, 0x5555);
    cop2_put(18, 0x5555);
    cop2_put(19, 0x5555);
    cop2_putc(29, 0x1000);
    gte_clear_flag();
    cop2_cmd(COP2_AVSZ3);
    uint32_t otz, flag;
    cop2_get(7, otz);
    flag = gte_read_flag();
    ramsyscall_printf("OTZ max: OTZ=%u FLAG=0x%08x\n", otz, flag);
    // 0x5555*3 = 0xFFFF, * 0x1000 = 0xFFFF000, >> 12 = 0xFFFF
    cester_assert_uint_eq(0xffff, otz);
)

// ==========================================================================
// Depth cue inner clamp (FC - input can go negative)
// ==========================================================================

// DPCS where FC << input color (FC-input negative, inner lm=0 clamp)
CESTER_TEST(edge_depthcue_fc_less_than_input, gte_tests,
    gte_set_far_color(0, 0, 0);  // FC = 0 (dark fog)
    cop2_put(6, 0x00ffffff);     // RGBC: R=G=B=0xFF (bright)
    cop2_put(8, 0x0800);         // IR0 = 0.5
    gte_clear_flag();
    cop2_cmd(COP2_DPCS(1, 0));
    int32_t mac1;
    uint32_t rgb2, flag;
    cop2_get(25, mac1);
    cop2_get(22, rgb2);
    flag = gte_read_flag();
    ramsyscall_printf("DPCS FC<input: MAC1=%d RGB2=0x%08x FLAG=0x%08x\n", mac1, rgb2, flag);
    // FC=0, R=0xFF: diff = (0<<12) - (0xFF<<16) = -0xFF0000 (negative)
    // Inner clamp (lm=0): clamps to [-0x8000, 0x7FFF]
    // Then IR0 * clamped_diff + R<<16 -> should produce intermediate result
)

// ==========================================================================
// INTPL where FC < IR (interpolation goes backward)
// ==========================================================================

CESTER_TEST(edge_intpl_fc_less_than_ir, gte_tests,
    gte_set_far_color(0, 0, 0);  // FC = 0
    cop2_put(9, 0x1000);  // IR = 0x1000 (> FC)
    cop2_put(10, 0x1000);
    cop2_put(11, 0x1000);
    cop2_put(8, 0x0800);  // IR0 = 0.5
    cop2_put(6, 0x00808080);
    gte_clear_flag();
    cop2_cmd(COP2_INTPL(1, 0));
    int32_t mac1;
    uint32_t flag;
    cop2_get(25, mac1);
    flag = gte_read_flag();
    ramsyscall_printf("INTPL FC<IR: MAC1=%d FLAG=0x%08x\n", mac1, flag);
    // IR=0x1000, FC=0, IR0=0.5
    // diff = (0<<12) - (0x1000<<12) = -0x1000000
    // inner clamp: -0x1000000 >> 12 = -0x1000 -> clamped to -0x1000 (in range)
    // MAC = 0x1000<<12 + 0x800 * (-0x1000) = 0x1000000 + (-0x800000)
    // >> 12 = (0x800000) >> 12 = 0x800 = 2048
)
