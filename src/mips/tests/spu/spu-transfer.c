// ==========================================================================
// Validate DMA transfer between Main Memory and SPU
// ==========================================================================

CESTER_TEST(transfer_via_dma, spu_tests,
    int fail_count = 0;
    const uint32_t addrs[3] = { 0x01040, 0x40000, 0x7fec0 };
    const uint8_t seeds[3]  = { 0x11, 0x22, 0x33 };

    for (int t = 0; t < 3; t++) {
        spu_reset_quiet();

        for (int i = 0; i < 256; i++) s_readback[i] = (uint8_t)(seeds[t] ^ (i * 7));
        for (int i = 256; i < 320; i++) s_readback[i] = 0xaa;
        spu_write_sync(addrs[t], s_readback, 320);

        for (int i = 0; i < 256; i++) s_readback[i] = 0xCC;
        spu_read_sync(addrs[t], s_readback, 256);

        int local_fail = 0;
        for (int i = 0; i < 256; i++) {
            uint8_t expected = (uint8_t)(seeds[t] ^ (i * 7));
            if (s_readback[i] != expected) local_fail++;
        }
        fail_count += local_fail;
    }
    cester_assert_int_eq(fail_count, 0);
)

CESTER_TEST(transfer_to_reserved_sdk_region, spu_tests,
    // PSY-Q SDK claims 0x1000-0x100F is reserved
    spu_reset_quiet();
    for (int i = 0; i < 128; i++) s_upload[i] = (uint8_t)(0xa5 ^ i);
    spu_write_sync(0x1000, s_upload, 128);
    spu_busy_wait(500000);
    spu_read_sync(0x1000, s_readback, 0x80);

    int matches_reserved = 0;
    for (int i = 0; i < 0x10; i++)
        if (s_readback[i] == s_upload[i]) matches_reserved++;
    int matches_after = 0;
    for (int i = 0x10; i < 0x40; i++)
        if (s_readback[i] == s_upload[i]) matches_after++;
    cester_assert_int_eq(matches_reserved, 16);
    cester_assert_int_eq(matches_after, 48);
)

CESTER_TEST(transfer_to_capture_region, spu_tests,
    spu_reset_quiet();
    spu_busy_wait(2000000);

    spu_read_sync(0x0000, s_readback, 0x1000);
    unsigned nonzero_silenced = 0;
    for (int i = 0; i < 0x1000; i++) if (s_readback[i] != 0) nonzero_silenced++;
    cester_assert_uint_eq(0, nonzero_silenced);

    for (int i = 0; i < 0x1000; i++) s_readback[i] = (uint8_t)(0x55 ^ (i & 0xff));
    spu_write_sync(0x0000, s_readback, 0x1000);
    spu_busy_wait(2000000);

    static uint8_t s_phase3[0x1000] __attribute__((aligned(4)));
    spu_read_sync(0x0000, s_phase3, 0x1000);
    unsigned matches = 0;
    for (int i = 0; i < 0x1000; i++)
        if (s_phase3[i] == (uint8_t)(0x55 ^ (i & 0xff))) matches++;
    cester_assert_uint_le(16, matches);
)
