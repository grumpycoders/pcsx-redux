// GTE instruction encoding tests: systematic sweep of bitfield parameters.
//
// Helper macros for unrolled MVMVA sweeps. Defined at file scope so they
// survive cester's double-include of __BASE_FILE__.

#define MVMVA_T(mx, v, cv) do { \
    if ((v) == 3) { cop2_put(9, 0x100); cop2_put(10, 0x200); cop2_put(11, 0x300); } \
    gte_clear_flag(); \
    cop2_cmd(COP2_MVMVA(1, mx, v, cv, 0)); \
} while (0)

#define MVMVA_MX3_V(v) do { \
    if ((v) == 3) { cop2_put(9, 0x400); cop2_put(10, 0x500); cop2_put(11, 0x600); } \
    gte_clear_flag(); \
    cop2_cmd(COP2_MVMVA(1, 3, v, 3, 0)); \
    int32_t _m1, _m2, _m3; \
    cop2_get(25, _m1); cop2_get(26, _m2); cop2_get(27, _m3); \
    ramsyscall_printf("MVMVA mx=3 v=%d: MAC=(%d,%d,%d)\n", v, _m1, _m2, _m3); \
} while (0)

#define MVMVA_CV2_MX(mx) do { \
    cop2_put(9, 0x100); cop2_put(10, 0x200); cop2_put(11, 0x300); \
    gte_clear_flag(); \
    cop2_cmd(COP2_MVMVA(1, mx, 0, 2, 0)); \
    int32_t _m1, _m2, _m3; uint32_t _fl; \
    cop2_get(25, _m1); cop2_get(26, _m2); cop2_get(27, _m3); _fl = gte_read_flag(); \
    ramsyscall_printf("MVMVA mx=%d cv=2: MAC=(%d,%d,%d) FLAG=0x%08x\n", mx, _m1, _m2, _m3, _fl); \
} while (0)
//
// The GTE command word is a 25-bit immediate with fields:
//   [fake:5][sf:1][mx:2][v:2][cv:2][pad:2][lm:1][pad:4][fn:6]
//
// These tests verify:
// 1. The "fake" field (bits 24-20) is ignored by hardware
// 2. sf=0 vs sf=1 behavior for each function code
// 3. lm=0 vs lm=1 behavior for each function code
// 4. All MVMVA mx/v/cv combinations produce results
// 5. Unused bitfield values don't crash

// ==========================================================================
// Fake field is ignored by hardware
// ==========================================================================

// Run RTPS with fake=0 (non-standard) and verify same result as fake=1
CESTER_TEST(enc_fake_field_ignored_rtps, gte_tests,
    gte_set_identity_rotation();
    gte_set_translation(0, 0, 1000);
    gte_set_screen(160 << 16, 120 << 16, 200);
    cop2_put(0, 0);
    cop2_put(1, 0);

    // Standard encoding: fake=1, sf=1
    gte_clear_flag();
    cop2_cmd(COP2_RTPS(1, 0));
    uint32_t sxy2_std;
    cop2_get(14, sxy2_std);

    // Non-standard: fake=0, same sf/fn
    cop2_put(0, 0);
    cop2_put(1, 0);
    gte_clear_flag();
    cop2_cmd(COP2_OP(0, 1, 0, 0, 0, 0, COP2_FN_RTPS));
    uint32_t sxy2_alt;
    cop2_get(14, sxy2_alt);

    cester_assert_uint_eq(sxy2_std, sxy2_alt);
)

// Run GPF with fake=31 (max) vs standard fake=25
CESTER_TEST(enc_fake_field_ignored_gpf, gte_tests,
    cop2_put(8, 0x1000);
    cop2_put(9, 100);
    cop2_put(10, 200);
    cop2_put(11, 300);
    cop2_put(6, 0x00808080);

    gte_clear_flag();
    cop2_cmd(COP2_GPF(1, 0));
    int32_t mac1_std;
    cop2_get(25, mac1_std);

    cop2_put(8, 0x1000);
    cop2_put(9, 100);
    cop2_put(10, 200);
    cop2_put(11, 300);
    cop2_put(6, 0x00808080);
    gte_clear_flag();
    cop2_cmd(COP2_OP(31, 1, 0, 0, 0, 0, COP2_FN_GPF));
    int32_t mac1_alt;
    cop2_get(25, mac1_alt);

    cester_assert_int_eq(mac1_std, mac1_alt);
)

// ==========================================================================
// sf=0 vs sf=1 for each instruction
// ==========================================================================

// GPF: sf changes shift behavior
CESTER_TEST(enc_gpf_sf_difference, gte_tests,
    cop2_put(8, 0x1000);
    cop2_put(9, 0x1000);
    cop2_put(10, 0x1000);
    cop2_put(11, 0x1000);
    cop2_put(6, 0x00808080);

    // sf=1: MAC = (IR0*IR) >> 12 = (0x1000*0x1000)>>12 = 0x1000
    gte_clear_flag();
    cop2_cmd(COP2_GPF(1, 0));
    int32_t mac1_sf1;
    cop2_get(25, mac1_sf1);

    cop2_put(8, 0x1000);
    cop2_put(9, 0x1000);
    cop2_put(10, 0x1000);
    cop2_put(11, 0x1000);
    cop2_put(6, 0x00808080);

    // sf=0: MAC = IR0*IR = 0x1000*0x1000 = 0x1000000
    gte_clear_flag();
    cop2_cmd(COP2_GPF(0, 0));
    int32_t mac1_sf0;
    cop2_get(25, mac1_sf0);

    cester_assert_int_eq(0x1000, mac1_sf1);
    cester_assert_int_eq(0x1000000, mac1_sf0);
)

// SQR: sf changes shift
CESTER_TEST(enc_sqr_sf_difference, gte_tests,
    cop2_put(9, 0x100);
    cop2_put(10, 0x100);
    cop2_put(11, 0x100);

    gte_clear_flag();
    cop2_cmd(COP2_SQR(1, 0));
    int32_t mac1_sf1;
    cop2_get(25, mac1_sf1);

    cop2_put(9, 0x100);
    cop2_put(10, 0x100);
    cop2_put(11, 0x100);
    gte_clear_flag();
    cop2_cmd(COP2_SQR(0, 0));
    int32_t mac1_sf0;
    cop2_get(25, mac1_sf0);

    // sf=1: (0x100*0x100)>>12 = 0x10000>>12 = 0x10
    // sf=0: 0x100*0x100 = 0x10000
    cester_assert_int_eq(0x10, mac1_sf1);
    cester_assert_int_eq(0x10000, mac1_sf0);
)

// OP: sf changes shift
CESTER_TEST(enc_op_sf_difference, gte_tests,
    cop2_putc(0, 0x00001000);
    cop2_putc(2, 0x00002000);
    cop2_putc(4, 0x1000);
    cop2_put(9, 100);
    cop2_put(10, 0);
    cop2_put(11, 0);

    gte_clear_flag();
    cop2_cmd(COP2_OP_CP(1, 0));
    int32_t mac2_sf1;
    cop2_get(26, mac2_sf1);

    cop2_put(9, 100);
    cop2_put(10, 0);
    cop2_put(11, 0);
    gte_clear_flag();
    cop2_cmd(COP2_OP_CP(0, 0));
    int32_t mac2_sf0;
    cop2_get(26, mac2_sf0);

    // sf=1: MAC2 = (R33*IR1 - R11*IR3)>>12 = (0x1000*100 - 0x1000*0)>>12 = 100
    // sf=0: MAC2 = R33*IR1 - R11*IR3 = 0x1000*100 = 409600
    cester_assert_int_eq(100, mac2_sf1);
    cester_assert_int_eq(409600, mac2_sf0);
)

// ==========================================================================
// lm=0 vs lm=1 for each instruction
// ==========================================================================

// SQR: lm=1 clamps IR to [0, 0x7fff]
CESTER_TEST(enc_sqr_lm_difference, gte_tests,
    cop2_put(9, 0x2000);  // 2.0
    cop2_put(10, 0x2000);
    cop2_put(11, 0x2000);

    // sf=1, lm=0: 2.0^2 = 4.0 = 0x4000 (in range for signed)
    gte_clear_flag();
    cop2_cmd(COP2_SQR(1, 0));
    uint32_t ir1_lm0;
    cop2_get(9, ir1_lm0);

    cop2_put(9, 0x2000);
    cop2_put(10, 0x2000);
    cop2_put(11, 0x2000);

    // sf=1, lm=1: same result since 0x4000 > 0 (lm=1 only clamps negative to 0)
    gte_clear_flag();
    cop2_cmd(COP2_SQR(1, 1));
    uint32_t ir1_lm1;
    cop2_get(9, ir1_lm1);

    // Both should be 0x4000 since result is positive
    cester_assert_uint_eq(0x4000, ir1_lm0);
    cester_assert_uint_eq(0x4000, ir1_lm1);
)

// ==========================================================================
// MVMVA: all mx/v/cv combinations (4 x 4 x 4 = 64 combos)
// ==========================================================================

// Sweep all 64 MVMVA parameter combinations and verify no crash.
// Log MAC results for ground truth capture.
CESTER_TEST(enc_mvmva_full_sweep, gte_tests,
    // Set up all matrices and vectors with known non-zero values
    // RT matrix
    cop2_putc(0, 0x08001000);
    cop2_putc(1, 0x02000400);
    cop2_putc(2, 0x08001000);
    cop2_putc(3, 0x02000400);
    cop2_putc(4, 0x1000);
    // LL matrix
    cop2_putc(8, 0x04000800);
    cop2_putc(9, 0x01000200);
    cop2_putc(10, 0x04000800);
    cop2_putc(11, 0x01000200);
    cop2_putc(12, 0x0800);
    // LC matrix
    cop2_putc(16, 0x02000400);
    cop2_putc(17, 0x00800100);
    cop2_putc(18, 0x02000400);
    cop2_putc(19, 0x00800100);
    cop2_putc(20, 0x0400);
    // Vectors
    cop2_put(0, (0x200 << 16) | 0x100);  // V0
    cop2_put(1, 0x300);
    cop2_put(2, (0x500 << 16) | 0x400);  // V1
    cop2_put(3, 0x600);
    cop2_put(4, (0x800 << 16) | 0x700);  // V2
    cop2_put(5, 0x900);
    cop2_put(9, 0x100);   // IR1
    cop2_put(10, 0x200);  // IR2
    cop2_put(11, 0x300);  // IR3
    cop2_put(8, 0x0800);  // IR0
    // Control vectors
    gte_set_translation(100, 200, 300);
    cop2_putc(13, 400);
    cop2_putc(14, 500);
    cop2_putc(15, 600);
    gte_set_far_color(700, 800, 900);

    // All 64 MVMVA combos unrolled (cop2_cmd requires compile-time constants).
    MVMVA_T(0,0,0); MVMVA_T(0,0,1); MVMVA_T(0,0,2); MVMVA_T(0,0,3);
    MVMVA_T(0,1,0); MVMVA_T(0,1,1); MVMVA_T(0,1,2); MVMVA_T(0,1,3);
    MVMVA_T(0,2,0); MVMVA_T(0,2,1); MVMVA_T(0,2,2); MVMVA_T(0,2,3);
    MVMVA_T(0,3,0); MVMVA_T(0,3,1); MVMVA_T(0,3,2); MVMVA_T(0,3,3);
    MVMVA_T(1,0,0); MVMVA_T(1,0,1); MVMVA_T(1,0,2); MVMVA_T(1,0,3);
    MVMVA_T(1,1,0); MVMVA_T(1,1,1); MVMVA_T(1,1,2); MVMVA_T(1,1,3);
    MVMVA_T(1,2,0); MVMVA_T(1,2,1); MVMVA_T(1,2,2); MVMVA_T(1,2,3);
    MVMVA_T(1,3,0); MVMVA_T(1,3,1); MVMVA_T(1,3,2); MVMVA_T(1,3,3);
    MVMVA_T(2,0,0); MVMVA_T(2,0,1); MVMVA_T(2,0,2); MVMVA_T(2,0,3);
    MVMVA_T(2,1,0); MVMVA_T(2,1,1); MVMVA_T(2,1,2); MVMVA_T(2,1,3);
    MVMVA_T(2,2,0); MVMVA_T(2,2,1); MVMVA_T(2,2,2); MVMVA_T(2,2,3);
    MVMVA_T(2,3,0); MVMVA_T(2,3,1); MVMVA_T(2,3,2); MVMVA_T(2,3,3);
    MVMVA_T(3,0,0); MVMVA_T(3,0,1); MVMVA_T(3,0,2); MVMVA_T(3,0,3);
    MVMVA_T(3,1,0); MVMVA_T(3,1,1); MVMVA_T(3,1,2); MVMVA_T(3,1,3);
    MVMVA_T(3,2,0); MVMVA_T(3,2,1); MVMVA_T(3,2,2); MVMVA_T(3,2,3);
    MVMVA_T(3,3,0); MVMVA_T(3,3,1); MVMVA_T(3,3,2); MVMVA_T(3,3,3);
    cester_assert_int_eq(1, 1); // if we got here, none crashed
)

// ==========================================================================
// MVMVA mx=3 (garbage matrix) with all vector/cv combinations
// ==========================================================================

CESTER_TEST(enc_mvmva_mx3_all_vectors, gte_tests,
    cop2_putc(0, 0x20001000);
    cop2_putc(1, 0x40003000);
    cop2_putc(2, 0x60005000);
    cop2_putc(3, 0x80007000);
    cop2_putc(4, 0x1000);
    cop2_put(8, 0x0800);
    cop2_put(0, (0x100 << 16) | 0x100);
    cop2_put(1, 0x100);
    cop2_put(2, (0x200 << 16) | 0x200);
    cop2_put(3, 0x200);
    cop2_put(4, (0x300 << 16) | 0x300);
    cop2_put(5, 0x300);
    cop2_put(9, 0x400);
    cop2_put(10, 0x500);
    cop2_put(11, 0x600);

    MVMVA_MX3_V(0); MVMVA_MX3_V(1); MVMVA_MX3_V(2); MVMVA_MX3_V(3);
    cester_assert_int_eq(1, 1);
)

// ==========================================================================
// MVMVA cv=2 (FC bug) with all matrix/vector combinations
// ==========================================================================

CESTER_TEST(enc_mvmva_cv2_all_matrices, gte_tests,
    gte_set_identity_rotation();
    gte_set_simple_light();
    gte_set_white_light_color();
    gte_set_far_color(0x1000, 0x2000, 0x3000);
    cop2_put(0, (0x200 << 16) | 0x100);
    cop2_put(1, 0x300);
    cop2_put(9, 0x100);
    cop2_put(10, 0x200);
    cop2_put(11, 0x300);

    MVMVA_CV2_MX(0); MVMVA_CV2_MX(1); MVMVA_CV2_MX(2);
    cester_assert_int_eq(1, 1);
)

// ==========================================================================
// Instructions that ignore sf/lm should produce identical results
// ==========================================================================

// NCLIP ignores sf and lm
CESTER_TEST(enc_nclip_ignores_sf_lm, gte_tests,
    cop2_put(12, 0x00000000);
    cop2_put(13, 0x00000064);
    cop2_put(14, 0x00640000);

    gte_clear_flag();
    cop2_cmd(COP2_OP(20, 0, 0, 0, 0, 0, COP2_FN_NCLIP));  // standard
    int32_t mac0_std;
    cop2_get(24, mac0_std);

    cop2_put(12, 0x00000000);
    cop2_put(13, 0x00000064);
    cop2_put(14, 0x00640000);
    gte_clear_flag();
    cop2_cmd(COP2_OP(0, 1, 3, 3, 3, 1, COP2_FN_NCLIP));   // all bits set
    int32_t mac0_alt;
    cop2_get(24, mac0_alt);

    cester_assert_int_eq(mac0_std, mac0_alt);
)

// AVSZ3 ignores sf and lm (uses fixed >>12)
CESTER_TEST(enc_avsz3_ignores_sf_lm, gte_tests,
    cop2_put(17, 100);
    cop2_put(18, 200);
    cop2_put(19, 300);
    cop2_putc(29, 0x555);

    gte_clear_flag();
    cop2_cmd(COP2_AVSZ3);
    int32_t mac0_std;
    cop2_get(24, mac0_std);

    cop2_put(17, 100);
    cop2_put(18, 200);
    cop2_put(19, 300);
    cop2_putc(29, 0x555);
    gte_clear_flag();
    cop2_cmd(COP2_OP(0, 0, 3, 3, 3, 1, COP2_FN_AVSZ3));
    int32_t mac0_alt;
    cop2_get(24, mac0_alt);

    cester_assert_int_eq(mac0_std, mac0_alt);
)
