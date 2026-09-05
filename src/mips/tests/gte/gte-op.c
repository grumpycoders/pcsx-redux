// OP: outer product / cross product
// Uses rotation matrix diagonal (R11, R22, R33) as D vector
// Result = D x IR

CESTER_TEST(op_identity_diagonal, gte_tests,
    gte_set_identity_rotation();
    cop2_put(9, 1000);
    cop2_put(10, 2000);
    cop2_put(11, 3000);
    gte_clear_flag();
    cop2_cmd(COP2_OP_CP(1, 0));
    int32_t ir1, ir2, ir3;
    cop2_get(9, ir1);
    cop2_get(10, ir2);
    cop2_get(11, ir3);
    // D=(1,1,1), IR=(1000,2000,3000)
    // cross = (1*3000-1*2000, 1*1000-1*3000, 1*2000-1*1000) = (1000,-2000,1000)
    cester_assert_int_eq(1000, ir1);
    cester_assert_int_eq(-2000, ir2);
    cester_assert_int_eq(1000, ir3);
)

CESTER_TEST(op_unshifted, gte_tests,
    gte_set_identity_rotation();
    cop2_put(9, 10);
    cop2_put(10, 20);
    cop2_put(11, 30);
    gte_clear_flag();
    cop2_cmd(COP2_OP_CP(0, 0));  // sf=0
    int32_t mac1, mac2, mac3;
    cop2_get(25, mac1);
    cop2_get(26, mac2);
    cop2_get(27, mac3);
    // sf=0: no shift. D=(0x1000,0x1000,0x1000), IR=(10,20,30)
    // MAC1 = R22*IR3 - R33*IR2 = 0x1000*30 - 0x1000*20 = 4096*(30-20) = 40960
    cester_assert_int_eq(40960, mac1);
    cester_assert_int_eq(-81920, mac2);
    cester_assert_int_eq(40960, mac3);
)

// OP with asymmetric diagonal
CESTER_TEST(op_asymmetric, gte_tests,
    cop2_putc(0, 0x00000800);  // R11=0x800 (0.5)
    cop2_putc(1, 0x00000000);
    cop2_putc(2, 0x00001000);  // R22=0x1000 (1.0)
    cop2_putc(3, 0x00000000);
    cop2_putc(4, 0x2000);      // R33=0x2000 (2.0)
    cop2_put(9, 100);
    cop2_put(10, 200);
    cop2_put(11, 300);
    gte_clear_flag();
    cop2_cmd(COP2_OP_CP(1, 0));
    int32_t ir1, ir2, ir3;
    cop2_get(9, ir1);
    cop2_get(10, ir2);
    cop2_get(11, ir3);
    // D=(0.5, 1.0, 2.0), IR=(100,200,300)
    // cross.x = D.y*IR.z - D.z*IR.y = 1.0*300 - 2.0*200 = 300 - 400 = -100
    // cross.y = D.z*IR.x - D.x*IR.z = 2.0*100 - 0.5*300 = 200 - 150 = 50
    // cross.z = D.x*IR.y - D.y*IR.x = 0.5*200 - 1.0*100 = 100 - 100 = 0
    cester_assert_int_eq(-100, ir1);
    cester_assert_int_eq(50, ir2);
    cester_assert_int_eq(0, ir3);
)

// OP with overflow - large values that exceed 44-bit accumulator
CESTER_TEST(op_overflow_flag, gte_tests,
    cop2_putc(0, 0x00007fff);  // R11=0x7fff
    cop2_putc(2, 0x00007fff);  // R22=0x7fff
    cop2_putc(4, 0x7fff);      // R33=0x7fff
    cop2_put(9, 0x7fff);
    cop2_put(10, 0x7fff);
    cop2_put(11, 0x7fff);
    gte_clear_flag();
    cop2_cmd(COP2_OP_CP(0, 0));  // sf=0, no shift -> large products
    uint32_t flag;
    flag = gte_read_flag();
    ramsyscall_printf("OP overflow: FLAG=0x%08x\n", flag);
    // With sf=0: MAC = 0x7fff*0x7fff - 0x7fff*0x7fff = 0 for all
    // Actually this produces zero cross product since all components are equal
    cester_assert_uint_eq(0x00000000, flag);
)
