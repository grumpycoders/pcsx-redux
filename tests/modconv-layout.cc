/*
 * Tests for modconv's SPU layout of MOD samples.
 *
 * The SPU loops on whole 28-sample ADPCM blocks, so a loop period that is not
 * a multiple of 28 samples is rounded to the nearest whole block, never
 * unrolled, and the conversion warns about the pitch change.
 */

#include "gtest/gtest.h"
#include "tools/modconv/layout.h"

using PCSX::ModConv::computeLayout;
using PCSX::ModConv::loopWarning;

// The two looped samples of a synthetic MOD, header fields in words.
// Long loop: 3412 samples, rounds to 3416, 0.12% off.
TEST(ModConvLayout, LongLoopIsRounded) {
    auto l = computeLayout(4000, 294, 1706);
    EXPECT_TRUE(l.hasLoop);
    EXPECT_EQ(l.loopLength, 3412u);
    EXPECT_EQ(l.body, 3416u);
    EXPECT_FALSE(l.exact);
    EXPECT_EQ((l.pad + l.loopStart - l.skip) % 28, 0u);
    EXPECT_EQ(l.encodedLength, (l.pad + l.loopStart - l.skip + 3416) / 28 * 16);
    EXPECT_EQ(loopWarning(1, "long", l), "  Sample  1 [long]: loop 3412 -> 3416 samples, -2.0 cents\n");
}

// Short loop: 182 samples, rounds to 196, 7.7% off. Still rounded, not unrolled.
TEST(ModConvLayout, ShortLoopIsRounded) {
    auto l = computeLayout(200, 109, 91);
    EXPECT_TRUE(l.hasLoop);
    EXPECT_EQ(l.loopLength, 182u);
    EXPECT_EQ(l.body, 196u);
    EXPECT_FALSE(l.exact);
    EXPECT_EQ(loopWarning(2, "short", l), "  Sample  2 [short]: loop 182 -> 196 samples, -128.3 cents\n");
}

// A loop shorter than half a block rounds up to one block.
TEST(ModConvLayout, TinyLoopIsOneBlock) {
    auto l = computeLayout(100, 0, 4);
    EXPECT_EQ(l.loopLength, 8u);
    EXPECT_EQ(l.body, 28u);
    EXPECT_EQ(l.encodedLength, 16u);
}

// A loop already made of whole blocks is kept as is, and gets no warning.
TEST(ModConvLayout, BlockAlignedLoopIsExact) {
    auto l = computeLayout(1000, 100, 280);
    EXPECT_EQ(l.body, 560u);
    EXPECT_TRUE(l.exact);
}
