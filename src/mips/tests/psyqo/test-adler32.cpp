#include "psyqo/adler32.hh"

#include "snitch_all.hpp"

using namespace psyqo;

// --- Basic checksums ---

TEST_CASE("Adler32 empty buffer") {
    uint32_t sum = adler32(nullptr, 0);
    REQUIRE(sum == 1);
}

TEST_CASE("Adler32 single byte") {
    uint8_t data[] = {0x01};
    uint32_t sum = adler32(data, 1);
    // Initial: a=1, b=0. After byte 1: a = 1+1 = 2, b = 0+2 = 2.
    REQUIRE(sum == ((2 << 16) | 2));
}

TEST_CASE("Adler32 known vector: 123456789") {
    // RFC 1950 test vector
    uint8_t data[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9'};
    uint32_t sum = adler32(data, 9);
    REQUIRE(sum == 0x091e01de);
}

TEST_CASE("Adler32 all zeros") {
    uint8_t data[10] = {};
    uint32_t sum = adler32(data, 10);
    // Initial: a=1, b=0. Each zero byte: a stays 1, b += a = b+1.
    // After 10 zeros: a=1, b=10.
    REQUIRE(sum == ((10 << 16) | 1));
}

// --- Chaining ---

TEST_CASE("Adler32 chaining produces same result") {
    uint8_t data[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9'};
    uint32_t whole = adler32(data, 9);

    // Compute in two chunks
    uint32_t partial = adler32(data, 4);
    uint32_t chained = adler32(data + 4, 5, partial);
    REQUIRE(chained == whole);
}

TEST_CASE("Adler32 chaining three chunks") {
    uint8_t data[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9'};
    uint32_t whole = adler32(data, 9);

    uint32_t s1 = adler32(data, 3);
    uint32_t s2 = adler32(data + 3, 3, s1);
    uint32_t s3 = adler32(data + 6, 3, s2);
    REQUIRE(s3 == whole);
}

// --- Byte vs word consistency ---

TEST_CASE("Adler32 byte and word variants match") {
    // Word-aligned data
    uint32_t words[] = {0x04030201, 0x08070605};
    uint8_t *bytes = reinterpret_cast<uint8_t *>(words);

    uint32_t byte_sum = adler32_bytes(bytes, 8);
    uint32_t word_sum = adler32_words(words, 2);
    REQUIRE(byte_sum == word_sum);
}

// --- Larger buffer ---

TEST_CASE("Adler32 sequential byte pattern") {
    uint8_t data[256];
    for (int i = 0; i < 256; i++) data[i] = i;
    uint32_t sum = adler32(data, 256);
    // Just verify it's non-trivial and deterministic
    REQUIRE(sum != 0);
    REQUIRE(sum != 1);
    // Re-compute to verify determinism
    uint32_t sum2 = adler32(data, 256);
    REQUIRE(sum == sum2);
}
