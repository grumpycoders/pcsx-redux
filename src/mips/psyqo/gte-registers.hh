/*

MIT License

Copyright (c) 2023 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

#include <stdint.h>

#include "psyqo/fixed-point.hh"
#include "psyqo/matrix.hh"
#include "psyqo/vector.hh"

namespace psyqo {

namespace GTE {

/**
 * @brief A GTE-compatible 32-bits fixed point number.
 */
typedef FixedPoint<12> Long;

/**
 * @brief A GTE-compatible 16-bits fixed point number.
 */
typedef FixedPoint<12, int16_t> Short;

/**
 * @brief A GTE-compatible short vector.
 */
struct PackedVec3 {
    Short x, y, z;
    PackedVec3() = default;
    explicit PackedVec3(Short x_, Short y_, Short z_) : x(x_), y(y_), z(z_) {}
    explicit PackedVec3(const Vec3& v) {
        x = Short(v.x);
        y = Short(v.y);
        z = Short(v.z);
    }
    operator Vec3() const {
        Vec3 ret;
        ret.x = FixedPoint<>(x);
        ret.y = FixedPoint<>(y);
        ret.z = FixedPoint<>(z);
        return ret;
    }
};

/**
 * @brief The list of available GTE registers.
 */
enum class Register {
    VXY0,
    VZ0,
    VXY1,
    VZ1,
    VXY2,
    VZ2,
    RGB,
    OTZ,
    IR0,
    IR1,
    IR2,
    IR3,
    SXY0,
    SXY1,
    SXY2,
    SXYP,
    SZ0,
    SZ1,
    SZ2,
    SZ3,
    RGB0,
    RGB1,
    RGB2,
    RES1,
    MAC0,
    MAC1,
    MAC2,
    MAC3,
    IRGB,
    ORGB,
    LZCS,
    LZCR,
    R11R12,
    R13R21,
    R22R23,
    R31R32,
    R33,
    TRX,
    TRY,
    TRZ,
    L11L12,
    L13L21,
    L22L23,
    L31L32,
    L33,
    RBK,
    GBK,
    BBK,
    LR1LR2,
    LR3LG1,
    LG2LG3,
    LB1LB2,
    LB3,
    RFC,
    GFC,
    BFC,
    OFX,
    OFY,
    H,
    DQA,
    DQB,
    ZSF3,
    ZSF4,
    FLAG,
};

/**
 * @brief Whether to insert nops after register operations.
 * @details The GTE is a coprocessor, and as such, register operations are not
 * guaranteed to be completed before the next instruction. This means that
 * triggering a GTE operations right after writing to a register may result in
 * the operation using the old value of the register. To avoid this, nops can be
 * inserted after register operations to ensure that the register is updated
 * before the next GTE operation. Use the `Safe` option to insert nops, or the
 * `Unsafe` option to avoid them, if you are sure that the register will not be
 * used immediately after the operation.
 */
enum Safety {
    Unsafe,
    Safe,
};

/**
 * @brief Clear a GTE register.
 *
 * @tparam reg The register to clear.
 * @tparam safety Whether to insert nops after the operation.
 */
template <Register reg, Safety safety = Safe>
static inline void clear() {
    if constexpr (reg < Register::R11R12) {
        asm volatile("mtc2 $0, $%0" ::"i"(static_cast<uint32_t>(reg)));
    } else if constexpr (reg >= Register::R11R12) {
        asm volatile("ctc2 $0, $%0" ::"i"(static_cast<uint32_t>(reg) - 32));
    }
    if constexpr (safety == Safe) {
        asm volatile("nop; nop");
    }
}

/**
 * @brief Write a 32-bits value to a GTE register.
 *
 * @tparam reg The register to write to.
 * @tparam safety Whether to insert nops after the operation.
 * @param value The value to write.
 */
template <Register reg, Safety safety = Safe>
static inline void write(uint32_t value) {
    if (__builtin_constant_p(value) && (value == 0)) {
        clear<reg, safety>();
    } else {
        if constexpr (reg < Register::R11R12) {
            asm volatile("mtc2 %0, $%1" ::"r"(value), "i"(static_cast<uint32_t>(reg)));
        } else if constexpr (reg >= Register::R11R12) {
            asm volatile("ctc2 %0, $%1" ::"r"(value), "i"(static_cast<uint32_t>(reg) - 32));
        }
        if constexpr (safety == Safe) {
            asm volatile("nop; nop");
        }
    }
}

/**
 * @brief Writes a 16-bits fixed point number to a GTE register, adding nops
 * after the operation.
 *
 * @tparam reg The register to write to.
 * @param fp The fixed point number to write.
 */
template <Register reg, bool valid = false>
static inline void writeSafe(Short fp) {
    static_assert(valid, "Unable to write single fixed point to register");
}

/**
 * @brief Writes a 16-bits fixed point number to a GTE register, without adding
 * nops after the operation.
 *
 * @tparam reg The register to write to.
 * @param fp The fixed point number to write.
 */
template <Register reg, bool valid = false>
static inline void writeUnsafe(Short fp) {
    static_assert(valid, "Unable to write single fixed point to register");
}

/**
 * @brief Writes two 16-bits fixed point numbers to a GTE register, adding nops
 * after the operation.
 * @tparam reg The register to write to.
 * @param low The value to write to the lower 16 bits of the register.
 * @param hi The value to write to the higher 16 bits of the register.
 */
template <Register reg, bool valid = false>
static inline void writeSafe(Short low, Short hi) {
    static_assert(valid, "Unable to write double fixed point to register");
}

/**
 * @brief Writes two 16-bits fixed point numbers to a GTE register, without
 * adding nops after the operation.
 *
 * @tparam reg The register to write to.
 * @param low The value to write to the lower 16 bits of the register.
 * @param hi The value to write to the higher 16 bits of the register.
 */
template <Register reg, bool valid = false>
static inline void writeUnsafe(Short low, Short hi) {
    static_assert(valid, "Unable to write double fixed point to register");
}

/**
 * @brief The list of available GTE pseudo registers.
 */
enum class PseudoRegister { Rotation, Light, Color, V0, V1, V2, SV, LV };

/**
 * @brief Write a 3x3 matrix to a GTE pseudo register, adding nops after the
 * operation.
 *
 * @tparam reg The pseudo register to write to.
 * @param in The matrix to write.
 */
template <PseudoRegister reg, bool valid = false>
static inline void writeSafe(const Matrix33& in) {
    static_assert(valid, "Unable to write matrix to pseudo register");
}

/**
 * @brief Write a 3x3 matrix to a GTE pseudo register, without adding nops
 * after the operation.
 *
 * @tparam reg The pseudo register to write to.
 * @param in The matrix to write.
 */
template <PseudoRegister reg, bool valid = false>
static inline void writeUnsafe(const Matrix33& in) {
    static_assert(valid, "Unable to write matrix to pseudo register");
}

/**
 * @brief Write a 3D vector to a GTE pseudo register, adding nops after the
 * operation.
 *
 * @tparam reg The pseudo register to write to.
 * @param in The vector to write.
 */
template <PseudoRegister reg, bool valid = false>
static inline void writeSafe(const Vec3& in) {
    static_assert(valid, "Unable to write vector to pseudo register");
}

/**
 * @brief Write a 3D vector to a GTE pseudo register, without adding nops after
 * the operation.
 *
 * @tparam reg The pseudo register to write to.
 * @param in The vector to write.
 */
template <PseudoRegister reg, bool valid = false>
static inline void writeUnsafe(const Vec3& in) {
    static_assert(valid, "Unable to write vector to pseudo register");
}

/**
 * @brief Writes a 32-bits value to a GTE register from memory.
 *
 * @tparam reg The register to write to.
 * @tparam safety Whether to insert nops after the operation.
 * @param ptr The pointer to the value to write.
 */
template <Register reg, Safety safety = Safe>
static inline void write(const uint32_t* ptr) {
    static_assert(reg < Register::R11R12, "Unable to write to register from memory directly");
    if constexpr (reg < Register::R11R12) {
        asm volatile("lwc2 $%1, 0(%0)" ::"r"(ptr), "i"(static_cast<uint32_t>(reg)));
    }

    if constexpr (safety == Safe) {
        asm volatile("nop; nop");
    }
}

/**
 * @brief Reads a 32-bits value from a GTE register.
 *
 * @tparam reg The register to read from.
 * @tparam safety Whether to insert nops after the operation.
 * @return uint32_t The value read from the register.
 */
template <Register reg, Safety safety = Safe>
static inline uint32_t readRaw() {
    uint32_t value;
    if constexpr (reg < Register::R11R12) {
        if constexpr (safety == Safe) {
            asm volatile("mfc2 %0, $%1; nop" : "=r"(value) : "i"(static_cast<uint32_t>(reg)));
        } else if constexpr (safety == Unsafe) {
            asm volatile("mfc2 %0, $%1" : "=r"(value) : "i"(static_cast<uint32_t>(reg)));
        }
    } else if constexpr (reg >= Register::R11R12) {
        if constexpr (safety == Safe) {
            asm volatile("cfc2 %0, $%1; nop" : "=r"(value) : "i"(static_cast<uint32_t>(reg) - 32));
        } else if constexpr (safety == Unsafe) {
            asm volatile("cfc2 %0, $%1" : "=r"(value) : "i"(static_cast<uint32_t>(reg) - 32));
        }
    }
    return value;
}

/**
 * @brief Read a 32-bits value from a GTE register to memory.
 *
 * @tparam reg The register to read from.
 * @param ptr The pointer to the memory location to write to.
 */
template <Register reg>
static inline void read(uint32_t* ptr) {
    static_assert(reg < Register::R11R12, "Unable to read from register to memory directly");
    if constexpr (reg < Register::R11R12) {
        asm volatile("swc2 $%1, 0(%0)" ::"r"(ptr), "i"(static_cast<uint32_t>(reg)));
    }
}

/**
 * @brief Reads a short vector from a GTE pseudo register, adding nops after
 * the operation.
 *
 * @tparam reg The pseudo register to read from.
 * @return PackedVec3 The vector read from the pseudo register.
 */
template <PseudoRegister reg, bool valid = false>
static inline PackedVec3 readSafe() {
    static_assert(valid, "Unable to read pseudo register as vector");
    __builtin_unreachable();
}

/**
 * @brief Reads a short vector from a GTE pseudo register, without adding nops
 * after the operation.
 *
 * @tparam reg The pseudo register to read from.
 * @return PackedVec3 The vector read from the pseudo register.
 */
template <PseudoRegister reg, bool valid = false>
static inline PackedVec3 readUnsafe() {
    static_assert(valid, "Unable to read pseudo register as vector");
    __builtin_unreachable();
}

template <PseudoRegister reg, bool valid = false>
static inline void read(Vec3* ptr) {
    static_assert(valid, "Unable to read pseudo register as vector");
    __builtin_unreachable();
}

// The following are template specializations for the various GTE registers.
template <>
inline void writeSafe<Register::VXY0>(Short x_, Short y_) {
    uint32_t x = uint16_t(x_.raw());
    uint32_t y = uint16_t(y_.raw());
    write<Register::VXY0, Safe>(x | (y << 16));
}

template <>
inline void writeSafe<Register::VZ0>(Short z_) {
    uint32_t z = uint16_t(z_.raw());
    write<Register::VZ0, Safe>(z);
}

template <>
inline void writeSafe<Register::VXY1>(Short x_, Short y_) {
    uint32_t x = uint16_t(x_.raw());
    uint32_t y = uint16_t(y_.raw());
    write<Register::VXY1, Safe>(x | (y << 16));
}

template <>
inline void writeSafe<Register::VZ1>(Short z_) {
    uint32_t z = uint16_t(z_.raw());
    write<Register::VZ1, Safe>(z);
}

template <>
inline void writeSafe<Register::VXY2>(Short x_, Short y_) {
    uint32_t x = uint16_t(x_.raw());
    uint32_t y = uint16_t(y_.raw());
    write<Register::VXY2, Safe>(x | (y << 16));
}

template <>
inline void writeSafe<Register::VZ2>(Short z_) {
    uint32_t z = uint16_t(z_.raw());
    write<Register::VZ2, Safe>(z);
}

template <>
inline void writeSafe<Register::OTZ>(Short z_) {
    uint32_t z = uint16_t(z_.raw());
    write<Register::OTZ, Safe>(z);
}

template <>
inline void writeSafe<Register::IR0>(Short x_) {
    uint32_t x = uint16_t(x_.raw());
    write<Register::IR0, Safe>(x);
}

template <>
inline void writeSafe<Register::IR1>(Short x_) {
    uint32_t x = uint16_t(x_.raw());
    write<Register::IR1, Safe>(x);
}

template <>
inline void writeSafe<Register::IR2>(Short x_) {
    uint32_t x = uint16_t(x_.raw());
    write<Register::IR2, Safe>(x);
}

template <>
inline void writeSafe<Register::IR3>(Short x_) {
    uint32_t x = uint16_t(x_.raw());
    write<Register::IR3, Safe>(x);
}

template <>
inline void writeSafe<Register::R11R12>(Short x_, Short y_) {
    uint32_t x = uint16_t(x_.raw());
    uint32_t y = uint16_t(y_.raw());
    write<Register::R11R12, Safe>(x | (y << 16));
}

template <>
inline void writeSafe<Register::R13R21>(Short x_, Short y_) {
    uint32_t x = uint16_t(x_.raw());
    uint32_t y = uint16_t(y_.raw());
    write<Register::R13R21, Safe>(x | (y << 16));
}

template <>
inline void writeSafe<Register::R22R23>(Short x_, Short y_) {
    uint32_t x = uint16_t(x_.raw());
    uint32_t y = uint16_t(y_.raw());
    write<Register::R22R23, Safe>(x | (y << 16));
}

template <>
inline void writeSafe<Register::R31R32>(Short x_, Short y_) {
    uint32_t x = uint16_t(x_.raw());
    uint32_t y = uint16_t(y_.raw());
    write<Register::R31R32, Safe>(x | (y << 16));
}

template <>
inline void writeSafe<Register::R33>(Short z_) {
    uint32_t z = uint16_t(z_.raw());
    write<Register::R33, Safe>(z);
}

template <>
inline void writeSafe<Register::L11L12>(Short x_, Short y_) {
    uint32_t x = uint16_t(x_.raw());
    uint32_t y = uint16_t(y_.raw());
    write<Register::L11L12, Safe>(x | (y << 16));
}

template <>
inline void writeSafe<Register::L13L21>(Short x_, Short y_) {
    uint32_t x = uint16_t(x_.raw());
    uint32_t y = uint16_t(y_.raw());
    write<Register::L13L21, Safe>(x | (y << 16));
}

template <>
inline void writeSafe<Register::L22L23>(Short x_, Short y_) {
    uint32_t x = uint16_t(x_.raw());
    uint32_t y = uint16_t(y_.raw());
    write<Register::L22L23, Safe>(x | (y << 16));
}

template <>
inline void writeSafe<Register::L31L32>(Short x_, Short y_) {
    uint32_t x = uint16_t(x_.raw());
    uint32_t y = uint16_t(y_.raw());
    write<Register::L31L32, Safe>(x | (y << 16));
}

template <>
inline void writeSafe<Register::L33>(Short z_) {
    uint32_t z = uint16_t(z_.raw());
    write<Register::L33, Safe>(z);
}

template <>
inline void writeSafe<Register::LR1LR2>(Short x_, Short y_) {
    uint32_t x = uint16_t(x_.raw());
    uint32_t y = uint16_t(y_.raw());
    write<Register::LR1LR2, Safe>(x | (y << 16));
}

template <>
inline void writeSafe<Register::LR3LG1>(Short x_, Short y_) {
    uint32_t x = uint16_t(x_.raw());
    uint32_t y = uint16_t(y_.raw());
    write<Register::LR3LG1, Safe>(x | (y << 16));
}

template <>
inline void writeSafe<Register::LG2LG3>(Short x_, Short y_) {
    uint32_t x = uint16_t(x_.raw());
    uint32_t y = uint16_t(y_.raw());
    write<Register::LG2LG3, Safe>(x | (y << 16));
}

template <>
inline void writeSafe<Register::LB1LB2>(Short x_, Short y_) {
    uint32_t x = uint16_t(x_.raw());
    uint32_t y = uint16_t(y_.raw());
    write<Register::LB1LB2, Safe>(x | (y << 16));
}

template <>
inline void writeSafe<Register::LB3>(Short z_) {
    uint32_t z = uint16_t(z_.raw());
    write<Register::LB3, Safe>(z);
}

template <>
inline void writeSafe<Register::ZSF3>(Short z_) {
    uint32_t z = uint16_t(z_.raw());
    write<Register::ZSF3, Safe>(z);
}

template <>
inline void writeSafe<Register::ZSF4>(Short z_) {
    uint32_t z = uint16_t(z_.raw());
    write<Register::ZSF4, Safe>(z);
}

template <>
inline void writeUnsafe<Register::VXY0>(Short x_, Short y_) {
    uint32_t x = uint16_t(x_.raw());
    uint32_t y = uint16_t(y_.raw());
    write<Register::VXY0, Unsafe>(x | (y << 16));
}

template <>
inline void writeUnsafe<Register::VZ0>(Short z_) {
    uint32_t z = uint16_t(z_.raw());
    write<Register::VZ0, Unsafe>(z);
}

template <>
inline void writeUnsafe<Register::VXY1>(Short x_, Short y_) {
    uint32_t x = uint16_t(x_.raw());
    uint32_t y = uint16_t(y_.raw());
    write<Register::VXY1, Unsafe>(x | (y << 16));
}

template <>
inline void writeUnsafe<Register::VZ1>(Short z_) {
    uint32_t z = uint16_t(z_.raw());
    write<Register::VZ1, Unsafe>(z);
}

template <>
inline void writeUnsafe<Register::VXY2>(Short x_, Short y_) {
    uint32_t x = uint16_t(x_.raw());
    uint32_t y = uint16_t(y_.raw());
    write<Register::VXY2, Unsafe>(x | (y << 16));
}

template <>
inline void writeUnsafe<Register::VZ2>(Short z_) {
    uint32_t z = uint16_t(z_.raw());
    write<Register::VZ2, Unsafe>(z);
}

template <>
inline void writeUnsafe<Register::OTZ>(Short z_) {
    uint32_t z = uint16_t(z_.raw());
    write<Register::OTZ, Unsafe>(z);
}

template <>
inline void writeUnsafe<Register::IR0>(Short x_) {
    uint32_t x = uint16_t(x_.raw());
    write<Register::IR0, Unsafe>(x);
}

template <>
inline void writeUnsafe<Register::IR1>(Short x_) {
    uint32_t x = uint16_t(x_.raw());
    write<Register::IR1, Unsafe>(x);
}

template <>
inline void writeUnsafe<Register::IR2>(Short x_) {
    uint32_t x = uint16_t(x_.raw());
    write<Register::IR2, Unsafe>(x);
}

template <>
inline void writeUnsafe<Register::IR3>(Short x_) {
    uint32_t x = uint16_t(x_.raw());
    write<Register::IR3, Unsafe>(x);
}

template <>
inline void writeUnsafe<Register::R11R12>(Short x_, Short y_) {
    uint32_t x = uint16_t(x_.raw());
    uint32_t y = uint16_t(y_.raw());
    write<Register::R11R12, Unsafe>(x | (y << 16));
}

template <>
inline void writeUnsafe<Register::R13R21>(Short x_, Short y_) {
    uint32_t x = uint16_t(x_.raw());
    uint32_t y = uint16_t(y_.raw());
    write<Register::R13R21, Unsafe>(x | (y << 16));
}

template <>
inline void writeUnsafe<Register::R22R23>(Short x_, Short y_) {
    uint32_t x = uint16_t(x_.raw());
    uint32_t y = uint16_t(y_.raw());
    write<Register::R22R23, Unsafe>(x | (y << 16));
}

template <>
inline void writeUnsafe<Register::R31R32>(Short x_, Short y_) {
    uint32_t x = uint16_t(x_.raw());
    uint32_t y = uint16_t(y_.raw());
    write<Register::R31R32, Unsafe>(x | (y << 16));
}

template <>
inline void writeUnsafe<Register::R33>(Short z_) {
    uint32_t z = uint16_t(z_.raw());
    write<Register::R33, Unsafe>(z);
}

template <>
inline void writeUnsafe<Register::L11L12>(Short x_, Short y_) {
    uint32_t x = uint16_t(x_.raw());
    uint32_t y = uint16_t(y_.raw());
    write<Register::L11L12, Unsafe>(x | (y << 16));
}

template <>
inline void writeUnsafe<Register::L13L21>(Short x_, Short y_) {
    uint32_t x = uint16_t(x_.raw());
    uint32_t y = uint16_t(y_.raw());
    write<Register::L13L21, Unsafe>(x | (y << 16));
}

template <>
inline void writeUnsafe<Register::L22L23>(Short x_, Short y_) {
    uint32_t x = uint16_t(x_.raw());
    uint32_t y = uint16_t(y_.raw());
    write<Register::L22L23, Unsafe>(x | (y << 16));
}

template <>
inline void writeUnsafe<Register::L31L32>(Short x_, Short y_) {
    uint32_t x = uint16_t(x_.raw());
    uint32_t y = uint16_t(y_.raw());
    write<Register::L31L32, Unsafe>(x | (y << 16));
}

template <>
inline void writeUnsafe<Register::L33>(Short z_) {
    uint32_t z = uint16_t(z_.raw());
    write<Register::L33, Unsafe>(z);
}

template <>
inline void writeUnsafe<Register::LR1LR2>(Short x_, Short y_) {
    uint32_t x = uint16_t(x_.raw());
    uint32_t y = uint16_t(y_.raw());
    write<Register::LR1LR2, Unsafe>(x | (y << 16));
}

template <>
inline void writeUnsafe<Register::LR3LG1>(Short x_, Short y_) {
    uint32_t x = uint16_t(x_.raw());
    uint32_t y = uint16_t(y_.raw());
    write<Register::LR3LG1, Unsafe>(x | (y << 16));
}

template <>
inline void writeUnsafe<Register::LG2LG3>(Short x_, Short y_) {
    uint32_t x = uint16_t(x_.raw());
    uint32_t y = uint16_t(y_.raw());
    write<Register::LG2LG3, Unsafe>(x | (y << 16));
}

template <>
inline void writeUnsafe<Register::LB1LB2>(Short x_, Short y_) {
    uint32_t x = uint16_t(x_.raw());
    uint32_t y = uint16_t(y_.raw());
    write<Register::LB1LB2, Unsafe>(x | (y << 16));
}

template <>
inline void writeUnsafe<Register::LB3>(Short z_) {
    uint32_t z = uint16_t(z_.raw());
    write<Register::LB3, Unsafe>(z);
}

template <>
inline void writeUnsafe<Register::ZSF3>(Short z_) {
    uint32_t z = uint16_t(z_.raw());
    write<Register::ZSF3, Unsafe>(z);
}

template <>
inline void writeUnsafe<Register::ZSF4>(Short z_) {
    uint32_t z = uint16_t(z_.raw());
    write<Register::ZSF4, Unsafe>(z);
}

template <>
inline void writeSafe<PseudoRegister::Rotation>(const Matrix33& in) {
    writeUnsafe<Register::R11R12>(Short(in.vs[0].x), Short(in.vs[0].y));
    writeUnsafe<Register::R13R21>(Short(in.vs[0].z), Short(in.vs[1].x));
    writeUnsafe<Register::R22R23>(Short(in.vs[1].y), Short(in.vs[1].z));
    writeUnsafe<Register::R31R32>(Short(in.vs[2].x), Short(in.vs[2].y));
    writeSafe<Register::R33>(Short(in.vs[2].z));
}

template <>
inline void writeSafe<PseudoRegister::Light>(const Matrix33& in) {
    writeUnsafe<Register::L11L12>(Short(in.vs[0].x), Short(in.vs[0].y));
    writeUnsafe<Register::L13L21>(Short(in.vs[0].z), Short(in.vs[1].x));
    writeUnsafe<Register::L22L23>(Short(in.vs[1].y), Short(in.vs[1].z));
    writeUnsafe<Register::L31L32>(Short(in.vs[2].x), Short(in.vs[2].y));
    writeSafe<Register::L33>(Short(in.vs[2].z));
}

template <>
inline void writeSafe<PseudoRegister::Color>(const Matrix33& in) {
    writeUnsafe<Register::LR1LR2>(Short(in.vs[0].x), Short(in.vs[0].y));
    writeUnsafe<Register::LR3LG1>(Short(in.vs[0].z), Short(in.vs[1].x));
    writeUnsafe<Register::LG2LG3>(Short(in.vs[1].y), Short(in.vs[1].z));
    writeUnsafe<Register::LB1LB2>(Short(in.vs[2].x), Short(in.vs[2].y));
    writeSafe<Register::LB3>(Short(in.vs[2].z));
}

template <>
inline void writeSafe<PseudoRegister::V0>(const Vec3& in) {
    writeUnsafe<Register::VXY0>(Short(in.x), Short(in.y));
    writeSafe<Register::VZ0>(Short(in.z));
}

template <>
inline void writeSafe<PseudoRegister::V1>(const Vec3& in) {
    writeUnsafe<Register::VXY1>(Short(in.x), Short(in.y));
    writeSafe<Register::VZ1>(Short(in.z));
}

template <>
inline void writeSafe<PseudoRegister::V2>(const Vec3& in) {
    writeUnsafe<Register::VXY2>(Short(in.x), Short(in.y));
    writeSafe<Register::VZ2>(Short(in.z));
}

template <>
inline void writeUnsafe<PseudoRegister::Rotation>(const Matrix33& in) {
    writeUnsafe<Register::R11R12>(Short(in.vs[0].x), Short(in.vs[0].y));
    writeUnsafe<Register::R13R21>(Short(in.vs[0].z), Short(in.vs[1].x));
    writeUnsafe<Register::R22R23>(Short(in.vs[1].y), Short(in.vs[1].z));
    writeUnsafe<Register::R31R32>(Short(in.vs[2].x), Short(in.vs[2].y));
    writeUnsafe<Register::R33>(Short(in.vs[2].z));
}

template <>
inline void writeUnsafe<PseudoRegister::Light>(const Matrix33& in) {
    writeUnsafe<Register::L11L12>(Short(in.vs[0].x), Short(in.vs[0].y));
    writeUnsafe<Register::L13L21>(Short(in.vs[0].z), Short(in.vs[1].x));
    writeUnsafe<Register::L22L23>(Short(in.vs[1].y), Short(in.vs[1].z));
    writeUnsafe<Register::L31L32>(Short(in.vs[2].x), Short(in.vs[2].y));
    writeUnsafe<Register::L33>(Short(in.vs[2].z));
}

template <>
inline void writeUnsafe<PseudoRegister::Color>(const Matrix33& in) {
    writeUnsafe<Register::LR1LR2>(Short(in.vs[0].x), Short(in.vs[0].y));
    writeUnsafe<Register::LR3LG1>(Short(in.vs[0].z), Short(in.vs[1].x));
    writeUnsafe<Register::LG2LG3>(Short(in.vs[1].y), Short(in.vs[1].z));
    writeUnsafe<Register::LB1LB2>(Short(in.vs[2].x), Short(in.vs[2].y));
    writeUnsafe<Register::LB3>(Short(in.vs[2].z));
}

template <>
inline void writeUnsafe<PseudoRegister::V0>(const Vec3& in) {
    writeUnsafe<Register::VXY0>(Short(in.x), Short(in.y));
    writeUnsafe<Register::VZ0>(Short(in.z));
}

template <>
inline void writeUnsafe<PseudoRegister::V1>(const Vec3& in) {
    writeUnsafe<Register::VXY1>(Short(in.x), Short(in.y));
    writeUnsafe<Register::VZ1>(Short(in.z));
}

template <>
inline void writeUnsafe<PseudoRegister::V2>(const Vec3& in) {
    writeUnsafe<Register::VXY2>(Short(in.x), Short(in.y));
    writeUnsafe<Register::VZ2>(Short(in.z));
}

template <>
inline PackedVec3 readSafe<PseudoRegister::SV>() {
    return PackedVec3(Short(readRaw<Register::IR1, Safe>(), Short::RAW),
                      Short(readRaw<Register::IR2, Safe>(), Short::RAW),
                      Short(readRaw<Register::IR3, Safe>(), Short::RAW));
}

template <>
inline PackedVec3 readSafe<PseudoRegister::LV>() {
    return PackedVec3(Short(readRaw<Register::MAC1, Safe>(), Short::RAW),
                      Short(readRaw<Register::MAC2, Safe>(), Short::RAW),
                      Short(readRaw<Register::MAC3, Safe>(), Short::RAW));
}

template <>
inline PackedVec3 readUnsafe<PseudoRegister::SV>() {
    return PackedVec3(Short(readRaw<Register::IR1, Unsafe>(), Short::RAW),
                      Short(readRaw<Register::IR2, Unsafe>(), Short::RAW),
                      Short(readRaw<Register::IR3, Unsafe>(), Short::RAW));
}

template <>
inline PackedVec3 readUnsafe<PseudoRegister::LV>() {
    return PackedVec3(Short(readRaw<Register::MAC1, Unsafe>(), Short::RAW),
                      Short(readRaw<Register::MAC2, Unsafe>(), Short::RAW),
                      Short(readRaw<Register::MAC3, Unsafe>(), Short::RAW));
}

template <>
inline void read<PseudoRegister::LV>(Vec3* ptr) {
    read<Register::MAC1>(reinterpret_cast<uint32_t*>(&ptr->x));
    read<Register::MAC2>(reinterpret_cast<uint32_t*>(&ptr->y));
    read<Register::MAC3>(reinterpret_cast<uint32_t*>(&ptr->z));
}

}  // namespace GTE

}  // namespace psyqo
