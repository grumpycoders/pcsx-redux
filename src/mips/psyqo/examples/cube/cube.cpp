/*

MIT License

Copyright (c) 2024 PCSX-Redux authors

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

#include "psyqo/application.hh"
#include "psyqo/gpu.hh"
#include "psyqo/trigonometry.hh"
#include "psyqo/gte-registers.hh"
#include "psyqo/gte-kernels.hh"
#include "psyqo/fixed-point.hh"
#include "psyqo/fragments.hh"
#include "psyqo/primitives/common.hh"
#include "psyqo/primitives/quads.hh"
#include "psyqo/vector.hh"
#include "psyqo/soft-math.hh"
#include "psyqo/scene.hh"

using namespace psyqo::fixed_point_literals;
using namespace psyqo::trig_literals;

static constexpr unsigned NUM_CUBE_VERTICES = 8;
static constexpr unsigned NUM_CUBE_FACES = 6;
static constexpr unsigned ORDERING_TABLE_SIZE = 240;

typedef struct {
	uint8_t  vertices[4];
	psyqo::Color color;
} Face;


static constexpr psyqo::Matrix33 identity = {{
        {1.0_fp, 0.0_fp, 0.0_fp},
        {0.0_fp, 1.0_fp, 0.0_fp},
        {0.0_fp, 0.0_fp, 1.0_fp},
}};

class Cube final : public psyqo::Application {
    void prepare() override;
    void createScene() override;

    public:
        psyqo::Trig<> m_trig;
};

class CubeScene final : public psyqo::Scene {

    void start(StartReason reason) override;
    void frame() override;

    psyqo::Angle m_rot = 0;

    // We need to create 2 OrderingTable objects since we can't reuse a single one for both
    // framebuffers, as the previous one may not finish transfering in time.
    psyqo::OrderingTable<ORDERING_TABLE_SIZE> m_ots[2];
    
    // Since we're using an ordering table, we need to sort fill commands as well, 
    // otherwise they'll draw over our beautiful cube.
    psyqo::Fragments::SimpleFragment<psyqo::Prim::FastFill> m_clear[2];

    eastl::array<psyqo::Fragments::SimpleFragment<psyqo::Prim::Quad>, 6> m_quads;

    static constexpr psyqo::Color c_bg = {.r = 63, .g = 63, .b = 63};


    static constexpr psyqo::Vec3 c_cubeVertices[NUM_CUBE_VERTICES] = {
        { .x = -0.05, .y = -0.05, .z = -0.05 },
        { .x =  0.05, .y = -0.05, .z = -0.05 },
        { .x = -0.05, .y =  0.05, .z = -0.05 },
        { .x =  0.05, .y =  0.05, .z = -0.05 },
        { .x = -0.05, .y = -0.05, .z =  0.05 },
        { .x =  0.05, .y = -0.05, .z =  0.05 },
        { .x = -0.05, .y =  0.05, .z =  0.05 },
        { .x =  0.05, .y =  0.05, .z =  0.05 }
    };


    static constexpr Face c_cubeFaces[NUM_CUBE_FACES] = {
        { .vertices = { 0, 1, 2, 3 }, .color = {0,0,255} },
        { .vertices = { 6, 7, 4, 5 }, .color = {0,255,0} },
        { .vertices = { 4, 5, 0, 1 }, .color = {0,255,255} },
        { .vertices = { 7, 6, 3, 2 }, .color = {255,0,0} },
        { .vertices = { 6, 4, 2, 0 }, .color = {255,0,255}},
        { .vertices = { 5, 7, 1, 3 }, .color = {255,255,0} }
    };
};

static Cube cube;
static CubeScene cubeScene;

void Cube::prepare() {
  psyqo::GPU::Configuration config;
  config.set(psyqo::GPU::Resolution::W320)
      .set(psyqo::GPU::VideoMode::AUTO)
      .set(psyqo::GPU::ColorMode::C15BITS)
      .set(psyqo::GPU::Interlace::PROGRESSIVE);

  gpu().initialize(config);
}

void Cube::createScene() {
    pushScene(&cubeScene);
}

void CubeScene::start(StartReason reason) {

    // Clear the translation registers
    psyqo::GTE::clear<psyqo::GTE::Register::TRX, psyqo::GTE::Unsafe>();
    psyqo::GTE::clear<psyqo::GTE::Register::TRY, psyqo::GTE::Unsafe>();
    psyqo::GTE::clear<psyqo::GTE::Register::TRZ, psyqo::GTE::Unsafe>();


    // Set the screen offset in the GTE. (this is half the X and Y resolutions as standard)
    psyqo::GTE::write<psyqo::GTE::Register::OFX, psyqo::GTE::Unsafe>(psyqo::FixedPoint<16>(160.0).raw());
    psyqo::GTE::write<psyqo::GTE::Register::OFY, psyqo::GTE::Unsafe>(psyqo::FixedPoint<16>(120.0).raw());


    // Write the projection plane distance.
    psyqo::GTE::write<psyqo::GTE::Register::H, psyqo::GTE::Unsafe>(120);


    // Set the scaling for Z averaging.
    psyqo::GTE::write<psyqo::GTE::Register::ZSF3, psyqo::GTE::Unsafe>(ORDERING_TABLE_SIZE / 3);
    psyqo::GTE::write<psyqo::GTE::Register::ZSF4, psyqo::GTE::Unsafe>(ORDERING_TABLE_SIZE / 4);

}

void CubeScene::frame() {

    eastl::array<psyqo::Vertex, 4> projected;

    // Get which frame we're currently drawing
    int parity = gpu().getParity();

    // Get our current ordering table and fill command
    auto& ot = m_ots[parity];
    auto& clear = m_clear[parity];

    // Chain the fill command accordingly to clear the buffer
    gpu().getNextClear(clear.primitive, c_bg);
    gpu().chain(clear);
    

    // We want the cube to appear slightly further away, so we translate it by 512 on the Z-axis.
    psyqo::GTE::write<psyqo::GTE::Register::TRZ, psyqo::GTE::Unsafe>(512);
    
    // Here we're setting up the rotation for the spinning cube
    // First, generate a rotation matrix for the X-axis and Y-axis
    auto transform = psyqo::SoftMath::generateRotationMatrix33(m_rot, psyqo::SoftMath::Axis::X, cube.m_trig);
    auto rot = psyqo::SoftMath::generateRotationMatrix33(m_rot, psyqo::SoftMath::Axis::Y, cube.m_trig);

    // Multiply the X and Y rotation matrices together
    psyqo::SoftMath::multiplyMatrix33(transform, rot, &transform);

    // Generate a Z-axis rotation matrix (Empty, but it's here for your use)
    psyqo::SoftMath::generateRotationMatrix33(0, 0, psyqo::SoftMath::Axis::Z, cube.m_trig);

    // Apply the combined rotation and write it to the pseudo register for the cube's rotation
    psyqo::SoftMath::multiplyMatrix33(transform, rot, &transform);
    psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::Rotation>(transform);
    


    int faceNum = 0;

    for(auto face : c_cubeFaces) {

        // We load the first 3 vertices into the GTE. We can't do all 4 at once because the GTE 
        // handles only 3 at a time...
        psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::V0>(c_cubeVertices[face.vertices[0]]);
        psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::V1>(c_cubeVertices[face.vertices[1]]);
        psyqo::GTE::writeUnsafe<psyqo::GTE::PseudoRegister::V2>(c_cubeVertices[face.vertices[2]]);
        
        // We perform rtpt (Perspective transformation) to the three verticies.
        psyqo::GTE::Kernels::rtpt();

        // Nclip determines the winding of the vertices, used to check which direction the face is pointing.
        // Clockwise winding means the face is oriented towards us.
        psyqo::GTE::Kernels::nclip();

        // Read the result of nclip and skip rendering this face if it's not facing us
        uint32_t mac0 = 0;
        psyqo::GTE::read<psyqo::GTE::Register::MAC0>(&mac0);
        if(mac0 <= 0)
            continue;

        // Since the GTE can only handle 3 vertices at a time, we need to store our first vertex 
        // so we can write our last one.
        psyqo::GTE::read<psyqo::GTE::Register::SXY0>(&projected[0].packed);

        // Write the last vertex
        psyqo::GTE::writeSafe<psyqo::GTE::PseudoRegister::V0>(c_cubeVertices[face.vertices[3]]);

        // Perform rtps (Perspective transformation) to the last vertice (rtpS - single, rtpT - triple).
        psyqo::GTE::Kernels::rtps();
        
        // Calculate the average Z for the z-Index to be put in the ordering table
        psyqo::GTE::Kernels::avsz4();
        uint32_t zIndex = 0;
        psyqo::GTE::read<psyqo::GTE::Register::OTZ>(&zIndex);


        // If the Z-index is out of bounds for our ordering table, we skip rendering this face.
        if(zIndex < 0 || zIndex >= ORDERING_TABLE_SIZE) 
            continue;
        
        // Read the 3 remaining vertices from the GTE
        psyqo::GTE::read<psyqo::GTE::Register::SXY0>(&projected[1].packed);
        psyqo::GTE::read<psyqo::GTE::Register::SXY1>(&projected[2].packed);
        psyqo::GTE::read<psyqo::GTE::Register::SXY2>(&projected[3].packed);

        // Take a Quad fragment from our array, set its vertices, color and make it opaque
        auto& quad = m_quads[faceNum];
        quad.primitive.setPointA(projected[0]);
        quad.primitive.setPointB(projected[1]);
        quad.primitive.setPointC(projected[2]);
        quad.primitive.setPointD(projected[3]);
        quad.primitive.setColor(face.color);
        quad.primitive.setOpaque();

        // Insert the Quad fragment into the ordering table at the calculated Z-index.
        ot.insert(quad, zIndex);
        faceNum++;
    }
    
    // Send the entire ordering table as a DMA chain to the GPU.    
    gpu().chain(ot);
    m_rot += 0.005_pi;
}


int main() {return cube.run();}

