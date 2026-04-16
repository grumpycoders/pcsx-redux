#include "psyqo/soft-math.hh"

#include "snitch_all.hpp"

using namespace psyqo;
using namespace psyqo::trig_literals;

static Trig<> trig;

// --- Rotation matrices ---

TEST_CASE("Rotation matrix at angle 0 is identity") {
    auto m = SoftMath::generateRotationMatrix33(0.0_pi, SoftMath::Axis::X, trig);
    // Diagonal should be 1, off-diagonal 0
    REQUIRE(m.vs[0].x.integer() == 1);
    REQUIRE(m.vs[1].y.integer() == 1);
    REQUIRE(m.vs[2].z.integer() == 1);
    REQUIRE(m.vs[0].y.raw() == 0);
    REQUIRE(m.vs[0].z.raw() == 0);
    REQUIRE(m.vs[1].x.raw() == 0);
}

TEST_CASE("Rotation matrix Y-axis at 0 is identity") {
    auto m = SoftMath::generateRotationMatrix33(0.0_pi, SoftMath::Axis::Y, trig);
    REQUIRE(m.vs[0].x.integer() == 1);
    REQUIRE(m.vs[1].y.integer() == 1);
    REQUIRE(m.vs[2].z.integer() == 1);
}

TEST_CASE("Rotation matrix Z-axis at 0 is identity") {
    auto m = SoftMath::generateRotationMatrix33(0.0_pi, SoftMath::Axis::Z, trig);
    REQUIRE(m.vs[0].x.integer() == 1);
    REQUIRE(m.vs[1].y.integer() == 1);
    REQUIRE(m.vs[2].z.integer() == 1);
}

// --- Matrix multiplication ---

TEST_CASE("Matrix multiply with identity") {
    auto id = SoftMath::generateRotationMatrix33(0.0_pi, SoftMath::Axis::X, trig);
    auto rot = SoftMath::generateRotationMatrix33(0.25_pi, SoftMath::Axis::Z, trig);
    auto result = SoftMath::multiplyMatrix33(id, rot);
    // Result should equal rot
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 3; j++) {
            auto diff = result.vs[i].get(j).raw() - rot.vs[i].get(j).raw();
            REQUIRE(diff >= -2);
            REQUIRE(diff <= 2);
        }
    }
}

// --- Matrix-vector multiplication ---

TEST_CASE("Identity matrix * vector = vector") {
    auto id = SoftMath::generateRotationMatrix33(0.0_pi, SoftMath::Axis::X, trig);
    Vec3 v;
    v.x = 3.0; v.y = 4.0; v.z = 5.0;
    Vec3 out;
    SoftMath::matrixVecMul3(id, v, &out);
    REQUIRE(out.x.integer() == 3);
    REQUIRE(out.y.integer() == 4);
    REQUIRE(out.z.integer() == 5);
}

TEST_CASE("Matrix-vector XY extraction") {
    auto id = SoftMath::generateRotationMatrix33(0.0_pi, SoftMath::Axis::X, trig);
    Vec3 v;
    v.x = 7.0; v.y = 11.0; v.z = 13.0;
    Vec2 out;
    SoftMath::matrixVecMul3xy(id, v, &out);
    REQUIRE(out.x.integer() == 7);
    REQUIRE(out.y.integer() == 11);
}

TEST_CASE("Matrix-vector Z extraction") {
    auto id = SoftMath::generateRotationMatrix33(0.0_pi, SoftMath::Axis::X, trig);
    Vec3 v;
    v.x = 7.0; v.y = 11.0; v.z = 13.0;
    auto z = SoftMath::matrixVecMul3z(id, v);
    REQUIRE(z.integer() == 13);
}

// --- Cross product ---

TEST_CASE("Cross product of basis vectors") {
    // X x Y = Z
    auto result = SoftMath::crossProductVec3(Vec3::RIGHT(), Vec3::UP());
    REQUIRE(result.x.raw() == 0);
    REQUIRE(result.y.raw() == 0);
    REQUIRE(result.z.integer() == 1);
}

TEST_CASE("Cross product anti-commutativity") {
    Vec3 a; a.x = 1.0; a.y = 2.0; a.z = 3.0;
    Vec3 b; b.x = 4.0; b.y = 5.0; b.z = 6.0;
    auto ab = SoftMath::crossProductVec3(a, b);
    auto ba = SoftMath::crossProductVec3(b, a);
    // a x b = -(b x a)
    REQUIRE(ab.x.raw() == -ba.x.raw());
    REQUIRE(ab.y.raw() == -ba.y.raw());
    REQUIRE(ab.z.raw() == -ba.z.raw());
}

TEST_CASE("Cross product of parallel vectors is zero") {
    Vec3 a; a.x = 1.0; a.y = 2.0; a.z = 3.0;
    Vec3 b; b.x = 2.0; b.y = 4.0; b.z = 6.0;
    auto result = SoftMath::crossProductVec3(a, b);
    REQUIRE(result.x.raw() == 0);
    REQUIRE(result.y.raw() == 0);
    REQUIRE(result.z.raw() == 0);
}

// --- Determinant ---

TEST_CASE("Identity matrix determinant is 1") {
    auto id = SoftMath::generateRotationMatrix33(0.0_pi, SoftMath::Axis::X, trig);
    auto det = SoftMath::matrixDeterminant3(id);
    REQUIRE(det.integer() == 1);
}

TEST_CASE("Rotation matrix determinant is 1") {
    auto m = SoftMath::generateRotationMatrix33(0.25_pi, SoftMath::Axis::Z, trig);
    auto det = SoftMath::matrixDeterminant3(m);
    auto diff = det.raw() - (1 << 12);
    // Allow some fixed-point error
    REQUIRE(diff >= -20);
    REQUIRE(diff <= 20);
}

// --- Square root ---

TEST_CASE("Square root of 4 is 2") {
    FixedPoint<> x = 4.0;
    auto r = SoftMath::squareRoot(x);
    auto diff = r.raw() - FixedPoint<>(2.0).raw();
    REQUIRE(diff >= -5);
    REQUIRE(diff <= 5);
}

TEST_CASE("Square root of 1 is 1") {
    FixedPoint<> x = 1.0;
    auto r = SoftMath::squareRoot(x);
    auto diff = r.raw() - FixedPoint<>(1.0).raw();
    REQUIRE(diff >= -2);
    REQUIRE(diff <= 2);
}

TEST_CASE("Square root of 9 is 3") {
    FixedPoint<> x = 9.0;
    auto r = SoftMath::squareRoot(x);
    auto diff = r.raw() - FixedPoint<>(3.0).raw();
    REQUIRE(diff >= -5);
    REQUIRE(diff <= 5);
}

// --- Norm ---

TEST_CASE("Norm of unit vectors is 1") {
    auto n = SoftMath::normOfVec3(Vec3::RIGHT());
    auto diff = n.raw() - (1 << 12);
    REQUIRE(diff >= -5);
    REQUIRE(diff <= 5);
}

TEST_CASE("Norm of (3, 4, 0) is 5") {
    Vec3 v; v.x = 3.0; v.y = 4.0; v.z = 0.0;
    auto n = SoftMath::normOfVec3(v);
    auto diff = n.raw() - FixedPoint<>(5.0).raw();
    REQUIRE(diff >= -10);
    REQUIRE(diff <= 10);
}

// --- Normalization ---

TEST_CASE("Normalized vector has unit length") {
    Vec3 v; v.x = 3.0; v.y = 4.0; v.z = 0.0;
    SoftMath::normalizeVec3(&v);
    auto n = SoftMath::normOfVec3(v);
    auto diff = n.raw() - (1 << 12);
    REQUIRE(diff >= -20);
    REQUIRE(diff <= 20);
}

// --- Scale ---

TEST_CASE("Matrix scale") {
    auto m = SoftMath::generateRotationMatrix33(0.0_pi, SoftMath::Axis::X, trig);
    SoftMath::scaleMatrix33(&m, FixedPoint<>(2.0));
    REQUIRE(m.vs[0].x.integer() == 2);
    REQUIRE(m.vs[1].y.integer() == 2);
    REQUIRE(m.vs[2].z.integer() == 2);
}

// --- Projection ---

TEST_CASE("Perspective projection") {
    Vec3 v; v.x = 10.0; v.y = 20.0; v.z = 5.0;
    FixedPoint<> h = 1.0;
    Vec2 out;
    SoftMath::project(&v, h, &out);
    // out.x = v.x * h / v.z = 10/5 = 2
    // out.y = v.y * h / v.z = 20/5 = 4
    REQUIRE(out.x.integer() == 2);
    REQUIRE(out.y.integer() == 4);
}
