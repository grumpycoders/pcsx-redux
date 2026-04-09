// GPF: general purpose interpolation (IR0 * IR -> MAC/IR, push color)
// GPL: general purpose interpolation with base (MAC + IR0 * IR -> MAC/IR, push color)

CESTER_TEST(gpf_shifted_unity, gte_tests,
    GTE_WRITE_DATA(8, 0x1000);  // IR0 = 1.0
    GTE_WRITE_DATA(9, 100);
    GTE_WRITE_DATA(10, 200);
    GTE_WRITE_DATA(11, 300);
    GTE_WRITE_DATA(6, 0x00204060);  // RGBC
    gte_clear_flag();
    GTE_EXEC(GTE_CMD_GPF_SF);
    int32_t mac1, mac2, mac3;
    GTE_READ_DATA(25, mac1);
    GTE_READ_DATA(26, mac2);
    GTE_READ_DATA(27, mac3);
    cester_assert_int_eq(100, mac1);
    cester_assert_int_eq(200, mac2);
    cester_assert_int_eq(300, mac3);
)

CESTER_TEST(gpf_shifted_half, gte_tests,
    GTE_WRITE_DATA(8, 0x0800);  // IR0 = 0.5
    GTE_WRITE_DATA(9, 1000);
    GTE_WRITE_DATA(10, 2000);
    GTE_WRITE_DATA(11, 4000);
    GTE_WRITE_DATA(6, 0x00808080);
    gte_clear_flag();
    GTE_EXEC(GTE_CMD_GPF_SF);
    int32_t mac1, mac2, mac3;
    GTE_READ_DATA(25, mac1);
    GTE_READ_DATA(26, mac2);
    GTE_READ_DATA(27, mac3);
    // IR0*IR >> 12 = 0x800*IR >> 12 = IR/2
    cester_assert_int_eq(500, mac1);
    cester_assert_int_eq(1000, mac2);
    cester_assert_int_eq(2000, mac3);
)

// GPF pushes color FIFO
CESTER_TEST(gpf_color_fifo_push, gte_tests,
    GTE_WRITE_DATA(8, 0x1000);  // IR0 = 1.0
    GTE_WRITE_DATA(9, 0x0800);  // IR1 -> MAC1=0x800, /16=128
    GTE_WRITE_DATA(10, 0x0400); // IR2 -> MAC2=0x400, /16=64
    GTE_WRITE_DATA(11, 0x0200); // IR3 -> MAC3=0x200, /16=32
    GTE_WRITE_DATA(6, 0xaa000000);  // RGBC: CODE=0xaa
    gte_clear_flag();
    GTE_EXEC(GTE_CMD_GPF_SF);
    uint32_t rgb2;
    GTE_READ_DATA(22, rgb2);
    uint8_t r = rgb2 & 0xff;
    uint8_t g = (rgb2 >> 8) & 0xff;
    uint8_t b = (rgb2 >> 16) & 0xff;
    uint8_t cd = (rgb2 >> 24) & 0xff;
    ramsyscall_printf("GPF color: R=%u G=%u B=%u CD=0x%02x\n", r, g, b, cd);
    cester_assert_uint_eq(0xaa, cd);  // CODE byte preserved
    // R = MAC1/16 = 0x800/16 = 128
    cester_assert_uint_eq(128, r);
    cester_assert_uint_eq(64, g);
    cester_assert_uint_eq(32, b);
)

// GPF unshifted (sf=0)
CESTER_TEST(gpf_unshifted, gte_tests,
    GTE_WRITE_DATA(8, 2);  // IR0 = 2
    GTE_WRITE_DATA(9, 100);
    GTE_WRITE_DATA(10, 200);
    GTE_WRITE_DATA(11, 300);
    GTE_WRITE_DATA(6, 0x00808080);
    gte_clear_flag();
    GTE_EXEC(GTE_CMD_GPF);
    int32_t mac1, mac2, mac3;
    GTE_READ_DATA(25, mac1);
    GTE_READ_DATA(26, mac2);
    GTE_READ_DATA(27, mac3);
    // sf=0: no shift, MAC = IR0*IR
    cester_assert_int_eq(200, mac1);
    cester_assert_int_eq(400, mac2);
    cester_assert_int_eq(600, mac3);
)

// GPL shifted with base
CESTER_TEST(gpl_shifted, gte_tests,
    GTE_WRITE_DATA(25, 1000);  // MAC1 base
    GTE_WRITE_DATA(26, 2000);  // MAC2 base
    GTE_WRITE_DATA(27, 3000);  // MAC3 base
    GTE_WRITE_DATA(8, 0x1000); // IR0 = 1.0
    GTE_WRITE_DATA(9, 100);
    GTE_WRITE_DATA(10, 200);
    GTE_WRITE_DATA(11, 300);
    GTE_WRITE_DATA(6, 0x00808080);
    gte_clear_flag();
    GTE_EXEC(GTE_CMD_GPL_SF);
    int32_t mac1, mac2, mac3;
    GTE_READ_DATA(25, mac1);
    GTE_READ_DATA(26, mac2);
    GTE_READ_DATA(27, mac3);
    // GPL sf=1: MAC_new = (MAC_old << 12 + IR0 * IR) >> 12
    // = ((1000<<12) + 4096*100) >> 12 = (4096000+409600)>>12 = 1100
    cester_assert_int_eq(1100, mac1);
    cester_assert_int_eq(2200, mac2);
    cester_assert_int_eq(3300, mac3);
)

// GPL unshifted (sf=0): MAC base used as-is, no shift
CESTER_TEST(gpl_unshifted, gte_tests,
    GTE_WRITE_DATA(25, 100);
    GTE_WRITE_DATA(26, 200);
    GTE_WRITE_DATA(27, 300);
    GTE_WRITE_DATA(8, 3);  // IR0 = 3
    GTE_WRITE_DATA(9, 10);
    GTE_WRITE_DATA(10, 20);
    GTE_WRITE_DATA(11, 30);
    GTE_WRITE_DATA(6, 0x00808080);
    gte_clear_flag();
    GTE_EXEC(GTE_CMD_GPL);
    int32_t mac1, mac2, mac3;
    GTE_READ_DATA(25, mac1);
    GTE_READ_DATA(26, mac2);
    GTE_READ_DATA(27, mac3);
    // sf=0: MAC_new = MAC_old + IR0*IR = 100+30=130, 200+60=260, 300+90=390
    cester_assert_int_eq(130, mac1);
    cester_assert_int_eq(260, mac2);
    cester_assert_int_eq(390, mac3);
)

// GPL pushes color FIFO
CESTER_TEST(gpl_color_fifo, gte_tests,
    GTE_WRITE_DATA(25, 0);
    GTE_WRITE_DATA(26, 0);
    GTE_WRITE_DATA(27, 0);
    GTE_WRITE_DATA(8, 0x1000);
    GTE_WRITE_DATA(9, 0x0ff0);  // /16 = 255
    GTE_WRITE_DATA(10, 0x0800); // /16 = 128
    GTE_WRITE_DATA(11, 0x0010); // /16 = 1
    GTE_WRITE_DATA(6, 0x55000000);  // CODE=0x55
    gte_clear_flag();
    GTE_EXEC(GTE_CMD_GPL_SF);
    uint32_t rgb2;
    GTE_READ_DATA(22, rgb2);
    uint8_t r = rgb2 & 0xff;
    uint8_t g = (rgb2 >> 8) & 0xff;
    uint8_t b = (rgb2 >> 16) & 0xff;
    uint8_t cd = (rgb2 >> 24) & 0xff;
    cester_assert_uint_eq(0x55, cd);
    cester_assert_uint_eq(255, r);
    cester_assert_uint_eq(128, g);
    cester_assert_uint_eq(1, b);
)
