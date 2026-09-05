// GTE register I/O tests: data/control register read/write, sign extension,
// SXY FIFO, IRGB/ORGB, LZCS/LZCR, FLAG register, CTC2 sign extension.

// ==========================================================================
// Data register roundtrip and sign/zero extension
// ==========================================================================

CESTER_TEST(regio_mac0_roundtrip, gte_tests,
    cop2_put(24, 0x12345678);
    uint32_t out;
    cop2_get(24, out);
    cester_assert_uint_eq(0x12345678, out);
)

CESTER_TEST(regio_mac1_roundtrip, gte_tests,
    cop2_put(25, 0xdeadbeef);
    uint32_t out;
    cop2_get(25, out);
    cester_assert_uint_eq(0xdeadbeef, out);
)

CESTER_TEST(regio_ir0_sign_extend, gte_tests,
    cop2_put(8, 0x0000ffff);
    uint32_t out;
    cop2_get(8, out);
    cester_assert_uint_eq(0xffffffff, out);
)

CESTER_TEST(regio_ir1_sign_extend, gte_tests,
    cop2_put(9, 0x00008000);
    uint32_t out;
    cop2_get(9, out);
    cester_assert_uint_eq(0xffff8000, out);
)

CESTER_TEST(regio_ir2_positive, gte_tests,
    cop2_put(10, 0x00001234);
    uint32_t out;
    cop2_get(10, out);
    cester_assert_uint_eq(0x00001234, out);
)

CESTER_TEST(regio_ir3_positive, gte_tests,
    cop2_put(11, 0x00007fff);
    uint32_t out;
    cop2_get(11, out);
    cester_assert_uint_eq(0x00007fff, out);
)

CESTER_TEST(regio_vz0_sign_extend, gte_tests,
    cop2_put(1, 0x0000ff00);
    uint32_t out;
    cop2_get(1, out);
    cester_assert_uint_eq(0xffffff00, out);
)

CESTER_TEST(regio_vxy0_packed, gte_tests,
    cop2_put(0, 0x00640032);
    uint32_t out;
    cop2_get(0, out);
    cester_assert_uint_eq(0x00640032, out);
)

CESTER_TEST(regio_otz_zero_extend, gte_tests,
    cop2_put(7, 0xffffffff);
    uint32_t out;
    cop2_get(7, out);
    cester_assert_uint_eq(0x0000ffff, out);
)

CESTER_TEST(regio_sz_zero_extend, gte_tests,
    cop2_put(16, 0xdeadbeef);
    uint32_t out;
    cop2_get(16, out);
    cester_assert_uint_eq(0x0000beef, out);
)

CESTER_TEST(regio_rgbc_roundtrip, gte_tests,
    cop2_put(6, 0xaa554080);
    uint32_t out;
    cop2_get(6, out);
    cester_assert_uint_eq(0xaa554080, out);
)

CESTER_TEST(regio_res1_readwrite, gte_tests,
    cop2_put(23, 0xdeadbeef);
    uint32_t out;
    cop2_get(23, out);
    cester_assert_uint_eq(0xdeadbeef, out);
)

// ==========================================================================
// SXY FIFO
// ==========================================================================

CESTER_TEST(regio_sxy_fifo_push, gte_tests,
    cop2_put(12, 0x00010002);
    cop2_put(13, 0x00030004);
    cop2_put(14, 0x00050006);
    cop2_put(15, 0x00070008);
    uint32_t sxy0, sxy1, sxy2;
    cop2_get(12, sxy0);
    cop2_get(13, sxy1);
    cop2_get(14, sxy2);
    cester_assert_uint_eq(0x00030004, sxy0);
    cester_assert_uint_eq(0x00050006, sxy1);
    cester_assert_uint_eq(0x00070008, sxy2);
)

CESTER_TEST(regio_sxyp_read_returns_sxy2, gte_tests,
    cop2_put(14, 0xaabbccdd);
    uint32_t sxyp;
    cop2_get(15, sxyp);
    cester_assert_uint_eq(0xaabbccdd, sxyp);
)

CESTER_TEST(regio_sxy_fifo_triple_push, gte_tests,
    cop2_put(15, 0x11111111);
    cop2_put(15, 0x22222222);
    cop2_put(15, 0x33333333);
    uint32_t sxy0, sxy1, sxy2;
    cop2_get(12, sxy0);
    cop2_get(13, sxy1);
    cop2_get(14, sxy2);
    cester_assert_uint_eq(0x11111111, sxy0);
    cester_assert_uint_eq(0x22222222, sxy1);
    cester_assert_uint_eq(0x33333333, sxy2);
)

// ==========================================================================
// IRGB / ORGB
// ==========================================================================

CESTER_TEST(regio_irgb_expand, gte_tests,
    cop2_put(28, 0x7fff);
    __asm__ volatile("nop; nop; nop; nop");
    uint32_t ir1, ir2, ir3;
    cop2_get(9, ir1);
    cop2_get(10, ir2);
    cop2_get(11, ir3);
    cester_assert_uint_eq(0x00000f80, ir1);
    cester_assert_uint_eq(0x00000f80, ir2);
    cester_assert_uint_eq(0x00000f80, ir3);
)

CESTER_TEST(regio_irgb_individual, gte_tests,
    cop2_put(28, 0x000a);  // R=10, G=0, B=0
    __asm__ volatile("nop; nop; nop; nop");
    uint32_t ir1, ir2, ir3;
    cop2_get(9, ir1);
    cop2_get(10, ir2);
    cop2_get(11, ir3);
    cester_assert_uint_eq(0x00000500, ir1);  // 10 << 7
    cester_assert_uint_eq(0x00000000, ir2);
    cester_assert_uint_eq(0x00000000, ir3);
)

CESTER_TEST(regio_orgb_pack, gte_tests,
    cop2_put(9, 0x0f80);
    cop2_put(10, 0x0f80);
    cop2_put(11, 0x0f80);
    uint32_t orgb;
    cop2_get(29, orgb);
    cester_assert_uint_eq(0x7fff, orgb);
)

// ORGB saturates, not truncates (psx-spx correct, Sony SDK wrong)
CESTER_TEST(regio_orgb_saturate_negative, gte_tests,
    cop2_put(9, 0xffff8000);  // IR1 = -32768 (negative)
    cop2_put(10, 0x00002000); // IR2 = 8192 (large positive)
    cop2_put(11, 0x00000380); // IR3 = 896 (normal)
    uint32_t orgb;
    cop2_get(29, orgb);
    uint32_t r = orgb & 0x1f;
    uint32_t g = (orgb >> 5) & 0x1f;
    uint32_t b = (orgb >> 10) & 0x1f;
    cester_assert_uint_eq(0, r);    // negative saturated to 0
    cester_assert_uint_eq(31, g);   // large saturated to 0x1f
    cester_assert_uint_eq(7, b);    // 896 >> 7 = 7
)

CESTER_TEST(regio_orgb_saturate_large, gte_tests,
    cop2_put(9, 0x1000);
    cop2_put(10, 0x1000);
    cop2_put(11, 0x1000);
    uint32_t orgb;
    cop2_get(29, orgb);
    // 0x1000>>7 = 0x20 = 32, saturated to 31
    cester_assert_uint_eq(0x7fff, orgb);
)

// ==========================================================================
// LZCS / LZCR
// ==========================================================================

CESTER_TEST(regio_lzcr_zero, gte_tests,
    cop2_put(30, 0x00000000);
    uint32_t lzcr;
    cop2_get(31, lzcr);
    cester_assert_uint_eq(32, lzcr);
)

CESTER_TEST(regio_lzcr_all_ones, gte_tests,
    cop2_put(30, 0xffffffff);
    uint32_t lzcr;
    cop2_get(31, lzcr);
    cester_assert_uint_eq(32, lzcr);
)

CESTER_TEST(regio_lzcr_one, gte_tests,
    cop2_put(30, 0x00000001);
    uint32_t lzcr;
    cop2_get(31, lzcr);
    cester_assert_uint_eq(31, lzcr);
)

CESTER_TEST(regio_lzcr_msb_set, gte_tests,
    cop2_put(30, 0x80000000);
    uint32_t lzcr;
    cop2_get(31, lzcr);
    cester_assert_uint_eq(1, lzcr);
)

CESTER_TEST(regio_lzcr_positive_mid, gte_tests,
    cop2_put(30, 0x00010000);
    uint32_t lzcr;
    cop2_get(31, lzcr);
    cester_assert_uint_eq(15, lzcr);
)

CESTER_TEST(regio_lzcr_negative_mid, gte_tests,
    cop2_put(30, 0xfffe0000);
    uint32_t lzcr;
    cop2_get(31, lzcr);
    cester_assert_uint_eq(15, lzcr);
)

// ==========================================================================
// FLAG register
// ==========================================================================

CESTER_TEST(regio_flag_write_mask, gte_tests,
    cop2_putc(31, 0xffffffff);
    uint32_t flag = gte_read_flag();
    cester_assert_uint_eq(0xfffff000, flag);
)

CESTER_TEST(regio_flag_low_bits_masked, gte_tests,
    cop2_putc(31, 0x00000fff);
    uint32_t flag = gte_read_flag();
    cester_assert_uint_eq(0, flag);
)

CESTER_TEST(regio_flag_bit12_no_summary, gte_tests,
    cop2_putc(31, (1 << 12));
    uint32_t flag = gte_read_flag();
    cester_assert_uint_eq((1 << 12), flag);
)

CESTER_TEST(regio_flag_bits19_22_no_summary, gte_tests,
    uint32_t flag;
    int ok = 1;
    int i;
    for (i = 19; i <= 22; i++) {
        cop2_putc(31, (1u << i));
        flag = gte_read_flag();
        if (flag != (1u << i)) ok = 0;
    }
    cester_assert_int_eq(1, ok);
)

CESTER_TEST(regio_flag_bits13_18_set_summary, gte_tests,
    uint32_t flag;
    int ok = 1;
    int i;
    for (i = 13; i <= 18; i++) {
        cop2_putc(31, (1u << i));
        flag = gte_read_flag();
        if (flag != ((1u << i) | (1u << 31))) ok = 0;
    }
    cester_assert_int_eq(1, ok);
)

CESTER_TEST(regio_flag_bits23_30_set_summary, gte_tests,
    uint32_t flag;
    int ok = 1;
    int i;
    for (i = 23; i <= 30; i++) {
        cop2_putc(31, (1u << i));
        flag = gte_read_flag();
        if (flag != ((1u << i) | (1u << 31))) ok = 0;
    }
    cester_assert_int_eq(1, ok);
)

// ==========================================================================
// Control register sign extension
// ==========================================================================

CESTER_TEST(regio_ctrl_r33_sign_extend, gte_tests,
    cop2_putc(4, 0x00008000);
    uint32_t out;
    cop2_getc(4, out);
    cester_assert_uint_eq(0xffff8000, out);
)

CESTER_TEST(regio_ctrl_zsf3_sign_extend, gte_tests,
    cop2_putc(29, 0x0000ffff);
    uint32_t out;
    cop2_getc(29, out);
    cester_assert_uint_eq(0xffffffff, out);
)

// H register sign-extension bug (psx-spx documented, Sony omitted)
CESTER_TEST(regio_h_sign_extension_bug, gte_tests,
    cop2_putc(26, 0x8000);
    uint32_t h;
    cop2_getc(26, h);
    cester_assert_uint_eq(0xffff8000, h);
)

CESTER_TEST(regio_h_positive, gte_tests,
    cop2_putc(26, 0x7fff);
    uint32_t h;
    cop2_getc(26, h);
    cester_assert_uint_eq(0x00007fff, h);
)

// All single-16bit control regs sign-extend
CESTER_TEST(regio_ctc2_sign_extend_all, gte_tests,
    uint32_t out;
    int ok = 1;
    // R33(4), L33(12), LB3(20), H(26), DQA(27), ZSF3(29), ZSF4(30)
    cop2_putc(4, 0x8000);  cop2_getc(4, out);  if (out != 0xffff8000) ok = 0;
    cop2_putc(12, 0x8000); cop2_getc(12, out); if (out != 0xffff8000) ok = 0;
    cop2_putc(20, 0x8000); cop2_getc(20, out); if (out != 0xffff8000) ok = 0;
    cop2_putc(26, 0x8000); cop2_getc(26, out); if (out != 0xffff8000) ok = 0;
    cop2_putc(27, 0x8000); cop2_getc(27, out); if (out != 0xffff8000) ok = 0;
    cop2_putc(29, 0x8000); cop2_getc(29, out); if (out != 0xffff8000) ok = 0;
    cop2_putc(30, 0x8000); cop2_getc(30, out); if (out != 0xffff8000) ok = 0;
    cester_assert_int_eq(1, ok);
)

// lm flag clamp behavior
CESTER_TEST(regio_lm_clamp, gte_tests,
    // GPF sf=1 lm=0: IR clamp -0x8000..0x7fff
    cop2_put(8, 0x1000);
    cop2_put(9, 0xffff8000);
    cop2_put(10, 0x100);
    cop2_put(11, 0x7fff);
    cop2_put(6, 0x00808080);
    gte_clear_flag();
    cop2_cmd(COP2_GPF(1, 0));
    int32_t mac1_lm0;
    uint32_t ir1_lm0;
    cop2_get(25, mac1_lm0);
    cop2_get(9, ir1_lm0);
    // GPF sf=1 lm=1
    cop2_put(8, 0x1000);
    cop2_put(9, 0xffff8000);
    cop2_put(10, 0x100);
    cop2_put(11, 0x7fff);
    cop2_put(6, 0x00808080);
    gte_clear_flag();
    cop2_cmd(COP2_GPF(1, 1));
    int32_t mac1_lm1;
    uint32_t ir1_lm1;
    cop2_get(25, mac1_lm1);
    cop2_get(9, ir1_lm1);
    cester_assert_int_eq(-32768, mac1_lm0);
    cester_assert_int_eq(-32768, mac1_lm1);
    cester_assert_uint_eq(0xffff8000, ir1_lm0);  // lm=0: stays -32768
    cester_assert_uint_eq(0x00000000, ir1_lm1);  // lm=1: clamped to 0
)
