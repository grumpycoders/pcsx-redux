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

#pragma once

#include "psyqo/matrix.hh"
#include "psyqo/trigonometry.hh"
#include "psyqo/vector.hh"

namespace psyqo {

namespace SoftMath {

enum class Axis { X, Y, Z };
/**
 * @brief Generate a rotation matrix for a given angle and axis.
 * @param m The matrix to store the result in.
 * @param t The angle to rotate by.
 * @param a The axis to rotate around.
 * @param trig A trigonometry object to use for sine and cosine calculations.
 */
void generateRotationMatrix33(Matrix33 *m, Angle t, Axis a, Trig<> *trig);

/**
 * @brief Generate a rotation matrix for a given angle and axis.
 * @param t The angle to rotate by.
 * @param a The axis to rotate around.
 * @param trig A trigonometry object to use for sine and cosine calculations.
 * @return Matrix33 The rotation matrix.
 */
[[nodiscard]] Matrix33 generateRotationMatrix33(Angle t, Axis a, Trig<> *trig);

/**
 * @brief Multiply two 3x3 matrices.
 *
 * @param m1 The first matrix.
 * @param m2 The second matrix.
 * @param out The matrix to store the result in. May be the same as m1 or m2.
 */
void multiplyMatrix33(const Matrix33 *m1, const Matrix33 *m2, Matrix33 *out);

/**
 * @brief Multiply two 3x3 matrices.
 *
 * @param m1 The first matrix.
 * @param m2 The second matrix.
 * @param out The matrix to store the result in. May be the same as m1 or m2.
 */
[[nodiscard]] Matrix33 multiplyMatrix33(const Matrix33 *m1, const Matrix33 *m2);

/**
 * @brief Scale a 3x3 matrix by a scalar.
 *
 * @param m The matrix to scale.
 * @param s The scalar to scale by.
 */
void scaleMatrix33(Matrix33 *m, FixedPoint<> s);

/**
 * @brief Multiply a 3x3 matrix by a 3D vector.
 *
 * @param m The matrix.
 * @param v The vector.
 * @param out The vector to store the result in. May be the same as v.
 */
void matrixVecMul3(const Matrix33 *m, const Vec3 *v, Vec3 *out);

/**
 * @brief Multiply a 3x3 matrix by a 3D vector, returning only the x and y components.
 *
 * @param m The matrix.
 * @param v The vector.
 * @param out The vector to store the result in.
 */
void matrixVecMul3xy(const Matrix33 *m, const Vec3 *v, Vec2 *out);

/**
 * @brief Multiply a 3x3 matrix by a 3D vector, returning only the z component.
 *
 * @param m The matrix.
 * @param v The vector.
 * @return FixedPoint<> The z component of the result.
 */
[[nodiscard]] FixedPoint<> matrixVecMul3z(const Matrix33 *m, const Vec3 *v);

/**
 * @brief Compute the cross product of two 3D vectors.
 *
 * @param v1 The first vector.
 * @param v2 The second vector.
 * @param out The vector to store the result in. May be the same as v1 or v2.
 */
void crossProductVec3(const Vec3 *v1, const Vec3 *v2, Vec3 *out);

/**
 * @brief Compute the cross product of two 3D vectors.
 *
 * @param v1 The first vector.
 * @param v2 The second vector.
 * @return Vec3 The cross product.
 */
[[nodiscard]] Vec3 crossProductVec3(const Vec3 *v1, const Vec3 *v2);

/**
 * @brief Compute the determinant of a 3x3 matrix.
 *
 * @param m The matrix.
 * @return FixedPoint<> The determinant.
 */
[[nodiscard]] FixedPoint<> matrixDeterminant3(const Matrix33 *m);

/** @brief Computes the square root of a fixed point number, given an approximative hint.
 *
 * @param x The number to compute the square root of.
 * @param y The approximative hint of the result.
 * @return psyqo::FixedPoint<> The square root.
 */
[[nodiscard]] FixedPoint<> squareRoot(FixedPoint<> x, FixedPoint<> y);

/**
 * @brief Computes the square root of a fixed point number.
 *
 * @param x The number to compute the square root of.
 * @return psyqo::FixedPoint<> The square root.
 */
[[nodiscard]] static inline FixedPoint<> squareRoot(FixedPoint<> x) { return squareRoot(x, x / 2); }

/**
 * @brief Computes the inverse square root of a fixed point number, given an
 * approximative hint.
 *
 * @param x The number to compute the inverse square root of.
 * @param y The approximative hint of the result.
 * @return psyqo::FixedPoint<> The inverse square root.
 */
[[nodiscard]] FixedPoint<> inverseSquareRoot(FixedPoint<> x, FixedPoint<> y);

/**
 * @brief Computes the inverse square root of a fixed point number.
 *
 * @param x The number to compute the inverse square root of.
 * @return psyqo::FixedPoint<> The inverse square root.
 */
[[nodiscard]] static inline FixedPoint<> inverseSquareRoot(FixedPoint<> x) { return inverseSquareRoot(x, x * 2); }

/**
 * @brief Computes the norm of a 3D vector.
 *
 * @param v The vector.
 * @return psyqo::FixedPoint<> The norm.
 */
[[nodiscard]] FixedPoint<> normOfVec3(const Vec3 *v);

/**
 * @brief Normalizes a 3D vector.
 *
 * @param v The vector to normalize.
 */
void normalizeVec3(Vec3 *v);

/**
 * @brief Normalizes a 3D vector, using a faster but less accurate algorithm.
 *
 * @param v The vector to normalize.
 */
void fastNormalizeVec3(Vec3 *v);

/**
 * @brief Projects a 3D point onto a 2D plane.
 *
 * @param v The vector to project.
 * @param h The height of the plane.
 * @param out The vector to store the result in.
 */
void project(const Vec3 *v, FixedPoint<> h, Vec2 *out);

}  // namespace SoftMath

}  // namespace psyqo
