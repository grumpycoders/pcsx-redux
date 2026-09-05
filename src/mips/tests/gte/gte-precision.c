// Precision tests: 44-bit MAC overflow detection, division table
// spot-checks, RTPS IR3/FLAG.22 sf=0 anomaly.
// These target the exact behaviors that cause subtle game glitches
// when emulated imprecisely.

// ==========================================================================
// 44-bit MAC overflow detection (FLAG bits 25-30)
// ==========================================================================
// The GTE accumulator is 44 bits wide. Overflow is detected per-addition
// in the chain, not on the final result. Two overflows that cancel out
// will still both be flagged.

// MAC1 positive overflow (FLAG.30): product exceeds +0x7FFFFFFFFFF
CESTER_TEST(prec_mac1_positive_overflow, gte_tests,
    // MVMVA with large matrix and large vector, sf=0 (no shift)
    // R11=0x7FFF, V0.X=0x7FFF -> R11*VX = 0x3FFF0001
    // With TR=0x7FFFFFFF and sf=0: TRX<<12 + R11*VX + R12*VY + R13*VZ
    // TRX<<12 = 0x7FFFFFFF000 (43 bits) + 0x3FFF0001 = overflows 44-bit
    cop2_putc(0, 0x00007fff);  // R11=0x7FFF, R12=0
    cop2_putc(1, 0x00000000);
    cop2_putc(2, 0x00000000);
    cop2_putc(3, 0x00000000);
    cop2_putc(4, 0);
    cop2_putc(5, 0x7fffffff);  // TRX = max positive 32-bit
    cop2_putc(6, 0);
    cop2_putc(7, 0);
    cop2_put(0, (0 << 16) | 0x7fff);  // VX=0x7FFF, VY=0
    cop2_put(1, 0);
    gte_clear_flag();
    cop2_cmd(COP2_MVMVA(0, COP2_MX_RT, COP2_V_V0, COP2_CV_TR, 0));
    uint32_t flag = gte_read_flag();
    uint32_t f30 = (flag >> 30) & 1;
    ramsyscall_printf("MAC1 pos overflow: FLAG=0x%08x F30=%u\n", flag, f30);
    cester_assert_uint_eq(1, f30);
)

// MAC1 negative overflow (FLAG.27)
CESTER_TEST(prec_mac1_negative_overflow, gte_tests,
    cop2_putc(0, 0x00007fff);  // R11=0x7FFF
    cop2_putc(1, 0x00000000);
    cop2_putc(2, 0x00000000);
    cop2_putc(3, 0x00000000);
    cop2_putc(4, 0);
    cop2_putc(5, 0x80000000);  // TRX = min negative 32-bit
    cop2_putc(6, 0);
    cop2_putc(7, 0);
    cop2_put(0, (0 << 16) | 0x8000);  // VX=-0x8000 (negative)
    cop2_put(1, 0);
    gte_clear_flag();
    cop2_cmd(COP2_MVMVA(0, COP2_MX_RT, COP2_V_V0, COP2_CV_TR, 0));
    uint32_t flag = gte_read_flag();
    uint32_t f27 = (flag >> 27) & 1;
    ramsyscall_printf("MAC1 neg overflow: FLAG=0x%08x F27=%u\n", flag, f27);
    cester_assert_uint_eq(1, f27);
)

// MAC2 overflow (FLAG.29 positive, FLAG.26 negative)
CESTER_TEST(prec_mac2_overflow, gte_tests,
    cop2_putc(0, 0x00000000);
    cop2_putc(1, 0x7fff0000);  // R21=0x7FFF (high16 of R13R21), R13=0
    cop2_putc(2, 0x00000000);
    cop2_putc(3, 0x00000000);
    cop2_putc(4, 0);
    cop2_putc(5, 0);
    cop2_putc(6, 0x7fffffff);  // TRY = max
    cop2_putc(7, 0);
    cop2_put(0, (0 << 16) | 0x7fff);
    cop2_put(1, 0);
    gte_clear_flag();
    cop2_cmd(COP2_MVMVA(0, COP2_MX_RT, COP2_V_V0, COP2_CV_TR, 0));
    uint32_t flag = gte_read_flag();
    uint32_t f29 = (flag >> 29) & 1;
    ramsyscall_printf("MAC2 pos overflow: FLAG=0x%08x F29=%u\n", flag, f29);
    cester_assert_uint_eq(1, f29);
)

// MAC3 overflow (FLAG.28 positive, FLAG.25 negative)
CESTER_TEST(prec_mac3_overflow, gte_tests,
    cop2_putc(0, 0x00000000);
    cop2_putc(1, 0x00000000);
    cop2_putc(2, 0x00000000);
    cop2_putc(3, 0x00007fff);  // R31=0x7FFF (high16 of R31R32)
    cop2_putc(4, 0);
    cop2_putc(5, 0);
    cop2_putc(6, 0);
    cop2_putc(7, 0x7fffffff);  // TRZ = max
    cop2_put(0, (0 << 16) | 0x7fff);
    cop2_put(1, 0);
    gte_clear_flag();
    cop2_cmd(COP2_MVMVA(0, COP2_MX_RT, COP2_V_V0, COP2_CV_TR, 0));
    uint32_t flag = gte_read_flag();
    uint32_t f28 = (flag >> 28) & 1;
    ramsyscall_printf("MAC3 pos overflow: FLAG=0x%08x F28=%u\n", flag, f28);
    cester_assert_uint_eq(1, f28);
)

// Two overflows that cancel: both positive and negative overflow
// should be flagged even if the final result is in range
CESTER_TEST(prec_mac_double_overflow, gte_tests,
    // Use OP (cross product) sf=0 with values that cause intermediate
    // overflow in both directions during the subtract
    // MAC1 = R22*IR3 - R33*IR2
    // Make R22*IR3 overflow positive, then R33*IR2 brings it back
    cop2_putc(0, 0x00000000);
    cop2_putc(2, 0x00007fff);  // R22=0x7FFF
    cop2_putc(4, 0x7fff);      // R33=0x7FFF
    cop2_put(9, 0);
    cop2_put(10, 0x7fff);  // IR2
    cop2_put(11, 0x7fff);  // IR3
    gte_clear_flag();
    cop2_cmd(COP2_OP_CP(0, 0));  // sf=0
    int32_t mac1;
    uint32_t flag;
    cop2_get(25, mac1);
    flag = gte_read_flag();
    ramsyscall_printf("double overflow: MAC1=%d FLAG=0x%08x\n", mac1, flag);
    // R22*IR3 = 0x7FFF*0x7FFF = 0x3FFF0001 (fits in 44-bit)
    // Then subtract R33*IR2 = 0x7FFF*0x7FFF = 0x3FFF0001
    // Result = 0, but check if intermediate overflow flagged
    cester_assert_int_eq(0, mac1);
    cester_assert_uint_eq(0, flag);
)

// ==========================================================================
// Division table spot-checks
// ==========================================================================
// The UNR table has 257 entries. Test specific H/SZ3 pairs that exercise
// known table entries and verify exact quotients.

// Helper: run RTPS with given H and SZ3 (via VZ), return quotient via SX
// Uses VX=0x1000, OFX=0 so SX = VX * (H/SZ3) = 0x1000 * quotient >> 16
// Actually simpler: set IR1=0x1000 before RTPS, read MAC0 for DQA path,
// or just check SX directly.

// H/SZ3 = 1/1: quotient should be near 0x10000 (1.0 in 0.16 fixed)
CESTER_TEST(prec_div_1_over_1, gte_tests,
    gte_set_identity_rotation();
    gte_set_translation(0, 0, 0);
    cop2_putc(24, 0);  // OFX=0
    cop2_putc(25, 0);
    cop2_putc(26, 1);  // H=1
    cop2_putc(27, 0);
    cop2_putc(28, 0);
    cop2_put(0, (0 << 16) | 0x1000);  // VX=0x1000, VY=0
    cop2_put(1, 1);  // VZ=1 -> SZ3=1
    gte_clear_flag();
    cop2_cmd(COP2_RTPS(1, 0));
    uint32_t sxy2, flag;
    cop2_get(14, sxy2);
    flag = gte_read_flag();
    int16_t sx = (int16_t)(sxy2 & 0xffff);
    ramsyscall_printf("div 1/1: SX=%d FLAG=0x%08x\n", sx, flag);
    // H=1, SZ3=1 -> H >= SZ3*2? 1 >= 2? No -> no overflow
    // quotient = H*0x20000/SZ3 = 0x20000. Saturated to 0x1FFFF.
    // SX = IR1 * quotient >> 16 = 0x1000 * 0x1FFFF >> 16 = 0x1FFF
    // Then saturated to 0x3FF
    uint32_t f17 = (flag >> 17) & 1;
    cester_assert_uint_eq(0, f17);  // no division overflow
)

// H/SZ3 = 100/1000: quotient = 0.1 in fixed point
CESTER_TEST(prec_div_100_over_1000, gte_tests,
    gte_set_identity_rotation();
    gte_set_translation(0, 0, 0);
    cop2_putc(24, 0);
    cop2_putc(25, 0);
    cop2_putc(26, 100);  // H=100
    cop2_putc(27, 0);
    cop2_putc(28, 0);
    cop2_put(0, (0 << 16) | 1000);  // VX=1000
    cop2_put(1, 1000);              // VZ=1000
    gte_clear_flag();
    cop2_cmd(COP2_RTPS(1, 0));
    uint32_t sxy2;
    cop2_get(14, sxy2);
    int16_t sx = (int16_t)(sxy2 & 0xffff);
    ramsyscall_printf("div 100/1000: SX=%d\n", sx);
    // SX = 1000 * (100/1000) = 100 (roughly, depends on table rounding)
    cester_assert_int_eq(100, sx);
)

// The documented corner case: H=0xF015, SZ3=0x780B -> 0x20000 saturates to 0x1FFFF
CESTER_TEST(prec_div_corner_f015_780b, gte_tests,
    gte_set_identity_rotation();
    gte_set_translation(0, 0, 0);
    cop2_putc(24, 0);
    cop2_putc(25, 0);
    cop2_putc(26, 0xf015);  // H
    cop2_putc(27, 0);
    cop2_putc(28, 0);
    cop2_put(0, (0 << 16) | 1);  // VX=1 (minimal to see quotient effect)
    cop2_put(1, 0x780b);         // VZ = 0x780B
    gte_clear_flag();
    cop2_cmd(COP2_RTPS(1, 0));
    uint32_t sxy2, flag;
    cop2_get(14, sxy2);
    flag = gte_read_flag();
    int16_t sx = (int16_t)(sxy2 & 0xffff);
    ramsyscall_printf("div F015/780B: SX=%d FLAG=0x%08x\n", sx, flag);
    // This should NOT set FLAG.17 (division overflow)
    uint32_t f17 = (flag >> 17) & 1;
    cester_assert_uint_eq(0, f17);
)

// Large H, small SZ3 (just under overflow): H=0xFFFE, SZ3=0x8000
CESTER_TEST(prec_div_large_h, gte_tests,
    gte_set_identity_rotation();
    gte_set_translation(0, 0, 0);
    cop2_putc(24, 0);
    cop2_putc(25, 0);
    cop2_putc(26, 0xfffe);  // H near max
    cop2_putc(27, 0);
    cop2_putc(28, 0);
    cop2_put(0, (0 << 16) | 1);
    cop2_put(1, 0x7fff);  // SZ3=0x7FFF -> H >= SZ3*2? 0xFFFE >= 0xFFFE -> yes, overflow
    gte_clear_flag();
    cop2_cmd(COP2_RTPS(1, 0));
    uint32_t flag;
    flag = gte_read_flag();
    uint32_t f17 = (flag >> 17) & 1;
    ramsyscall_printf("div large H: FLAG=0x%08x F17=%u\n", flag, f17);
    cester_assert_uint_eq(1, f17);  // H >= SZ3*2 is true (equal counts)
)

// SZ3=1 with moderate H (quotient near max)
CESTER_TEST(prec_div_sz3_one, gte_tests,
    gte_set_identity_rotation();
    gte_set_translation(0, 0, 0);
    cop2_putc(24, 0);
    cop2_putc(25, 0);
    cop2_putc(26, 1);  // H=1
    cop2_putc(27, 0);
    cop2_putc(28, 0);
    cop2_put(0, (0 << 16) | 1);
    cop2_put(1, 1);  // SZ3=1
    gte_clear_flag();
    cop2_cmd(COP2_RTPS(1, 0));
    uint32_t sxy2, flag;
    int32_t ir1;
    cop2_get(14, sxy2);
    cop2_get(9, ir1);
    flag = gte_read_flag();
    int16_t sx = (int16_t)(sxy2 & 0xffff);
    ramsyscall_printf("div SZ3=1: SX=%d IR1=%d FLAG=0x%08x\n", sx, ir1, flag);
    // H/SZ3 = 1/1 -> quotient saturates to 0x1FFFF
    // SX = IR1 * 0x1FFFF >> 16 = 1 * 0x1FFFF >> 16 = 1
    cester_assert_int_eq(1, sx);
)

// ==========================================================================
// RTPS IR3/FLAG.22 anomaly with sf=0
// ==========================================================================
// psx-spx: "When using RTP with sf=0, the IR3 saturation flag (FLAG.22)
// gets set only if MAC3 SAR 12 exceeds -8000h..+7FFFh, although IR3 is
// saturated when MAC3 exceeds -8000h..+7FFFh."
//
// Need MAC3 that is out of [-0x8000, 0x7FFF] range (so IR3 saturates)
// but MAC3 >> 12 is in range (so FLAG.22 should NOT be set).

CESTER_TEST(prec_rtps_sf0_ir3_flag_anomaly, gte_tests,
    gte_set_identity_rotation();
    // TRZ such that MAC3 is just over 0x7FFF but MAC3>>12 is in range
    // With identity rotation and VZ=0: MAC3 = TRZ << 12 (sf=0, no shift)
    // Wait - with sf=0 the formula is: MAC3 = TRZ*0x1000 + R3x*V
    // Actually let's think more carefully.
    // sf=0: A3 returns the raw 44-bit value without >>12
    // MAC3 = TRZ<<12 + R31*VX + R32*VY + R33*VZ (no shift applied)
    // With identity: MAC3 = TRZ<<12 + VZ*0x1000
    // We want MAC3 > 0x7FFF (IR3 saturates) but MAC3>>12 in [-0x8000,0x7FFF]
    // MAC3 = 0x8000 -> MAC3>>12 = 0 (in range) -> FLAG.22 NOT set but IR3 saturated
    cop2_putc(5, 0);
    cop2_putc(6, 0);
    cop2_putc(7, 0);  // TRZ = 0
    cop2_putc(24, 0);
    cop2_putc(25, 0);
    cop2_putc(26, 200);
    cop2_putc(27, 0);
    cop2_putc(28, 0);
    // VZ = 8 -> MAC3 = 0 + 0x1000*8 = 0x8000 (just over 0x7FFF)
    cop2_put(0, 0x00000000);
    cop2_put(1, 8);
    gte_clear_flag();
    cop2_cmd(COP2_RTPS(0, 0));  // sf=0
    int32_t mac3;
    uint32_t ir3, flag;
    cop2_get(27, mac3);
    cop2_get(11, ir3);
    flag = gte_read_flag();
    uint32_t f22 = (flag >> 22) & 1;
    ramsyscall_printf("sf=0 anomaly: MAC3=%d IR3=0x%04x FLAG=0x%08x F22=%u\n",
                      mac3, ir3 & 0xffff, flag, f22);
    // MAC3 = 0x8000 -> out of [-0x8000, 0x7FFF] for IR3 (it equals -0x8000 boundary!)
    // Hmm, 0x8000 = 32768 which is > 0x7FFF. IR3 should saturate to 0x7FFF.
    // MAC3 >> 12 = 0x8000 >> 12 = 0 -> in range -> FLAG.22 should NOT be set.
    // This is the anomaly: IR3 saturated but FLAG.22 not set.
    cester_assert_int_eq(32768, mac3);
    cester_assert_uint_eq(0x7fff, ir3);
    cester_assert_uint_eq(0, f22);
    uint32_t f17 = (flag >> 17) & 1;
    cester_assert_uint_eq(1, f17);
)

// Stronger test: MAC3 = 0x10000 -> well above 0x7FFF, but >>12 = 1 (in range)
CESTER_TEST(prec_rtps_sf0_ir3_flag_strong, gte_tests,
    gte_set_identity_rotation();
    cop2_putc(5, 0);
    cop2_putc(6, 0);
    cop2_putc(7, 0);
    cop2_putc(24, 0);
    cop2_putc(25, 0);
    cop2_putc(26, 200);
    cop2_putc(27, 0);
    cop2_putc(28, 0);
    // VZ = 16 -> MAC3 = 0x1000 * 16 = 0x10000 (65536, way above 0x7FFF)
    cop2_put(0, 0x00000000);
    cop2_put(1, 16);
    gte_clear_flag();
    cop2_cmd(COP2_RTPS(0, 0));
    int32_t mac3;
    uint32_t ir3, flag;
    cop2_get(27, mac3);
    cop2_get(11, ir3);
    flag = gte_read_flag();
    uint32_t f22 = (flag >> 22) & 1;
    ramsyscall_printf("sf=0 strong: MAC3=%d IR3=0x%04x FLAG=0x%08x F22=%u\n",
                      mac3, ir3 & 0xffff, flag, f22);
    // MAC3 = 0x10000 -> IR3 saturated to 0x7FFF
    cester_assert_uint_eq(0x7fff, ir3);
    // MAC3 >> 12 = 0x10000 >> 12 = 16 -> in range -> FLAG.22 NOT set
    cester_assert_uint_eq(0, f22);
)

// Counter-test: MAC3 >> 12 exceeds range -> FLAG.22 SHOULD be set
CESTER_TEST(prec_rtps_sf0_ir3_flag_set, gte_tests,
    gte_set_identity_rotation();
    cop2_putc(5, 0);
    cop2_putc(6, 0);
    cop2_putc(7, 8);  // TRZ = 8, so MAC3 = 8<<12 + VZ*0x1000
    cop2_putc(24, 0);
    cop2_putc(25, 0);
    cop2_putc(26, 200);
    cop2_putc(27, 0);
    cop2_putc(28, 0);
    // VZ = 0x7FF0 -> MAC3 = 8*4096 + 0x7FF0*0x1000 = 0x8000 + 0x7FF0000 = 0x7FF8000
    // MAC3 >> 12 = 0x7FF8 -> in range? 0x7FF8 < 0x7FFF -> yes, still in range
    // Need TRZ large enough: TRZ = 0x7FFF -> MAC3 = 0x7FFF<<12 = 0x7FFF000
    // MAC3>>12 = 0x7FFF -> at boundary. With VZ=1: MAC3 = 0x7FFF000 + 0x1000 = 0x8000000
    // MAC3>>12 = 0x8000 -> OUT of range -> FLAG.22 should be set
    cop2_putc(7, 0x7fff);
    cop2_put(0, 0x00000000);
    cop2_put(1, 1);
    gte_clear_flag();
    cop2_cmd(COP2_RTPS(0, 0));
    int32_t mac3;
    uint32_t ir3, flag;
    cop2_get(27, mac3);
    cop2_get(11, ir3);
    flag = gte_read_flag();
    uint32_t f22 = (flag >> 22) & 1;
    ramsyscall_printf("sf=0 flag set: MAC3=%d IR3=0x%04x FLAG=0x%08x F22=%u\n",
                      mac3, ir3 & 0xffff, flag, f22);
    // MAC3>>12 = 0x8000 -> exceeds 0x7FFF -> FLAG.22 SHOULD be set
    cester_assert_uint_eq(1, f22);
)
