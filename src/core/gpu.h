/***************************************************************************
 *   Copyright (C) 2019 PCSX-Redux authors                                 *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.           *
 ***************************************************************************/

#pragma once

#include <memory>
#include <stdexcept>
#include <type_traits>
#include <utility>

#include "core/display.h"
#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "magic_enum/include/magic_enum.hpp"
#include "support/file.h"
#include "support/list.h"
#include "support/slice.h"

namespace PCSX {
class GUI;
struct SaveStateWrapper;

class GPU {
  public:
    template <typename T, unsigned bits>
    static constexpr T signExtend(const T value) {
        struct {
            T value : bits;
        } t;
        return t.value = value;
    }

    uint32_t readStatus();
    void dma(uint32_t madr, uint32_t bcr, uint32_t chcr);
    static void gpuInterrupt();

    // These functions do not touch GPUSTAT. GPU backends should mirror the IRQ status into GPUSTAT
    // when readStatus is called
    void requestIRQ1() { psxHu32ref(0x1070) |= SWAP_LEu32(0x2); }
    void acknowledgeIRQ1() { psxHu32ref(0x1070) &= ~SWAP_LEu32(0x2); }

    bool m_showCfg = false;
    bool m_showDebug = false;
    Display m_display;

    virtual bool configure() = 0;
    virtual void debug() = 0;
    virtual ~GPU() {}

    void serialize(SaveStateWrapper *);
    void deserialize(const SaveStateWrapper *);

  private:
    // Taken from PEOPS SOFTGPU
    uint32_t s_lUsedAddr[3];

    bool CheckForEndlessLoop(uint32_t laddr);
    uint32_t gpuDmaChainSize(uint32_t addr);

  public:
    GPU();
    int init(GUI *);
    virtual int initBackend(GUI *) = 0;
    virtual int shutdown() = 0;
    void startDump() { throw std::runtime_error("Not yet implemented"); }
    void stopDump() { throw std::runtime_error("Not yet implemented"); }
    uint32_t readData();
    virtual uint32_t readStatusInternal() = 0;
    void writeData(uint32_t gdata);
    void directDMAWrite(const uint32_t *feed, int transferSize, uint32_t hwAddr);
    void directDMARead(uint32_t *dest, int transferSize, uint32_t hwAddr);
    void chainedDMAWrite(const uint32_t *memory, uint32_t hwAddr);
    void writeStatus(uint32_t gdata);
    virtual void writeStatusInternal(uint32_t gdata) = 0;
    virtual void setOpenGLContext() {}

    virtual void restoreStatus(uint32_t status) = 0;

    virtual void vblank() = 0;
    virtual void addVertex(short sx, short sy, int64_t fx, int64_t fy, int64_t fz) {
        throw std::runtime_error("Not yet implemented");
    }
    virtual void pgxpMemory(unsigned int addr, unsigned char *pVRAM) {}
    virtual void pgxpCacheVertex(short sx, short sy, const unsigned char *_pVertex) {
        throw std::runtime_error("Not yet implemented");
    }

    virtual void setDither(int setting) = 0;
    virtual void reset() = 0;
    virtual void clearVRAM() = 0;
    virtual GLuint getVRAMTexture() = 0;
    virtual void setLinearFiltering() = 0;

    static std::unique_ptr<GPU> getSoft();
    static std::unique_ptr<GPU> getOpenGL();

    virtual Slice getVRAM() = 0;
    virtual void partialUpdateVRAM(int x, int y, int w, int h, const uint16_t *pixels) = 0;

    struct ScreenShot {
        Slice data;
        uint16_t width, height;
        enum { BPP_16, BPP_24 } bpp;
    };
    virtual ScreenShot takeScreenShot() { throw std::runtime_error("Not yet implemented"); }

  private:
    uint32_t m_statusControl[256];

    class Command {
      public:
        Command() : m_gpu(nullptr) {}
        Command(GPU *parent) : m_gpu(parent) {}
        virtual ~Command() {}
        virtual void processWrite(uint32_t value);
        void setActive() { m_gpu->m_processor = this; }

      protected:
        GPU *m_gpu;

      private:
        void setGPU(GPU *gpu) { m_gpu = gpu; }

        friend class GPU;
    };

  public:
    class Logged;
    typedef Intrusive::List<Logged> LoggedList;
    class Logged : public LoggedList::Node {};

    enum class Shading { Flat, Gouraud };
    enum class Shape { Tri, Quad };
    enum class Textured { No, Yes };
    enum class Blend { Off, Semi };
    enum class Modulation { On, Off };
    enum class LineType { Simple, Poly };
    enum class Size { Variable, S1, S8, S16 };

    enum class BlendFunction {
        HalfBackAndHalfFront,
        FullBackAndFullFront,
        FullBackSubFullFront,
        FullBackAndQuarterFront
    };
    enum class TexDepth { Tex4Bits, Tex8Bits, Tex16Bits };

    struct FastFill final : public Command, public Logged {
        FastFill(GPU *parent) : Command(parent) {}
        virtual void processWrite(uint32_t value) override;

        uint32_t color;
        unsigned x, y, w, h;

      private:
        enum { READ_COLOR, READ_XY, READ_WH } m_state = READ_COLOR;
    };

    struct BlitVramVram final : public Command, public Logged {
        BlitVramVram(GPU *parent) : Command(parent) {}
        virtual void processWrite(uint32_t value) override;

        unsigned sX, sY, dX, dY, w, h;

      private:
        enum { READ_COMMAND, READ_SRC_XY, READ_DST_XY, READ_HW } m_state = READ_COMMAND;
    };

    struct BlitRamVram final : public Command, public Logged {
        BlitRamVram() {}
        BlitRamVram(GPU *parent) : Command(parent) {}
        BlitRamVram(const BlitRamVram &other) {
            x = other.x;
            y = other.y;
            w = other.w;
            h = other.h;
        }
        BlitRamVram(BlitRamVram &&) = delete;
        virtual void processWrite(uint32_t value) override;

        unsigned x, y, w, h;
        Slice data;

      private:
        enum { READ_COMMAND, READ_XY, READ_HW, READ_PIXELS } m_state = READ_COMMAND;
        std::string m_data;
    };

    struct BlitVramRam final : public Command, public Logged {
        BlitVramRam(GPU *parent) : Command(parent) {}
        virtual void processWrite(uint32_t value) override;

        unsigned x, y, w, h;

      private:
        enum { READ_COMMAND, READ_XY, READ_HW } m_state = READ_COMMAND;
    };

    struct TPage : public Logged {
        TPage() {}
        TPage(uint32_t value);
        TPage(const TPage &other) = default;
        TPage(TPage &&other) = default;
        TPage &operator=(const TPage &other) = default;
        uint32_t raw;
        unsigned tx, ty;
        BlendFunction blendFunction;
        TexDepth texDepth;
        bool dither;
        bool drawToDisplay;
        bool texDisable;
        bool xflip;
        bool yflip;
    };

    struct TWindow : public Logged {
        TWindow(uint32_t value);
        TWindow(const TWindow &other) = default;
        TWindow(TWindow &&other) = default;
        TWindow &operator=(const TWindow &other) = default;
        unsigned x, y, w, h;
        uint32_t raw;
    };

    struct DrawingAreaStart : public Logged {
        DrawingAreaStart(uint32_t value);
        DrawingAreaStart(const DrawingAreaStart &other) = default;
        DrawingAreaStart(DrawingAreaStart &&other) = default;
        DrawingAreaStart &operator=(const DrawingAreaStart &other) = default;
        unsigned x, y;
        uint32_t raw;
    };

    struct DrawingAreaEnd : public Logged {
        DrawingAreaEnd(uint32_t value);
        DrawingAreaEnd(const DrawingAreaEnd &other) = default;
        DrawingAreaEnd(DrawingAreaEnd &&other) = default;
        DrawingAreaEnd &operator=(const DrawingAreaEnd &other) = default;
        unsigned x, y;
        uint32_t raw;
    };

    struct DrawingOffset : public Logged {
        DrawingOffset(uint32_t value);
        DrawingOffset(const DrawingOffset &other) = default;
        DrawingOffset(DrawingOffset &&other) = default;
        DrawingOffset &operator=(const DrawingOffset &other) = default;
        int x, y;
        uint32_t raw;
    };

    struct MaskBit : public Logged {
        MaskBit(uint32_t value);
        MaskBit(const MaskBit &other) = default;
        MaskBit(MaskBit &&other) = default;
        MaskBit &operator=(const MaskBit &other) = default;
        bool set, check;
    };

    template <Shading shading_, Shape shape_, Textured textured_, Blend blend_, Modulation modulation_>
    struct Poly final : public Command, public Logged {
        static constexpr Shading shading = shading_;
        static constexpr Shape shape = shape_;
        static constexpr Textured textured = textured_;
        static constexpr Blend blend = blend_;
        static constexpr Modulation modulation = modulation_;
        static constexpr unsigned count = shape == Shape::Tri ? 3 : 4;

        Poly() {}
        void processWrite(uint32_t value) override;
        uint32_t colors[count];
        int x[count], y[count];
        struct Empty {};
        typedef std::conditional<textured == Textured::Yes, unsigned, Empty>::type TextureUnitType;
        [[no_unique_address]] TextureUnitType u[count];
        [[no_unique_address]] TextureUnitType v[count];
        [[no_unique_address]] TextureUnitType clutX;
        [[no_unique_address]] TextureUnitType clutY;
        [[no_unique_address]] std::conditional<textured == Textured::Yes, TPage, Empty>::type tpage;

      private:
        unsigned m_count = 0;
        enum { READ_COLOR, READ_XY, READ_UV } m_state = READ_COLOR;
    };

    template <Shading shading_, LineType lineType_, Blend blend_>
    struct Line final : public Command, public Logged {
        static constexpr Shading shading = shading_;
        static constexpr LineType lineType = lineType_;
        static constexpr Blend blend = blend_;

        Line() {
            if constexpr (lineType == LineType::Simple) m_count = 0;
        }
        void processWrite(uint32_t value) override;

        template <typename T>
        using Storage = std::conditional<lineType == LineType::Poly, std::vector<T>, std::array<T, 2>>::type;

        Storage<int> x, y;
        Storage<uint32_t> colors;

      private:
        struct Empty {};
        [[no_unique_address]] std::conditional<lineType == LineType::Simple, unsigned, Empty>::type m_count;
        enum { READ_COLOR, READ_XY } m_state = READ_COLOR;
    };

    template <Size size_, Textured textured_, Blend blend_, Modulation modulation_>
    struct Rect final : public Command, public Logged {
        static constexpr Size size = size_;
        static constexpr Textured textured = textured_;
        static constexpr Blend blend = blend_;
        static constexpr Modulation modulation = modulation_;

        Rect() {}
        void processWrite(uint32_t value) override;

        struct Empty {};
        int x, y, w, h;
        typedef std::conditional<textured == Textured::Yes, unsigned, Empty>::type TextureUnitType;
        [[no_unique_address]] std::conditional<(textured == Textured::No) || (modulation == Modulation::On), uint32_t,
                                               Empty>::type color;
        [[no_unique_address]] TextureUnitType u;
        [[no_unique_address]] TextureUnitType v;
        [[no_unique_address]] TextureUnitType clutX;
        [[no_unique_address]] TextureUnitType clutY;

      private:
        enum { READ_COLOR, READ_XY, READ_UV, READ_HW } m_state = READ_COLOR;
    };

  private:
    Command m_defaultProcessor = {this};

    FastFill m_fastFill = {this};
    Command *m_polygons[32];
    Command *m_lines[32];
    Command *m_rects[32];
    BlitVramVram m_blitVramVram = {this};
    BlitRamVram m_blitRamVram = {this};
    BlitVramRam m_blitVramRam = {this};

    Command *m_processor = &m_defaultProcessor;

    IO<Fifo> m_readFifo = new Fifo();
    Slice m_vramReadSlice;

    virtual void write0(FastFill *) = 0;

    virtual void write0(Poly<Shading::Flat, Shape::Tri, Textured::No, Blend::Off, Modulation::Off> *) = 0;
    virtual void write0(Poly<Shading::Flat, Shape::Tri, Textured::No, Blend::Off, Modulation::On> *) = 0;
    virtual void write0(Poly<Shading::Flat, Shape::Tri, Textured::No, Blend::Semi, Modulation::Off> *) = 0;
    virtual void write0(Poly<Shading::Flat, Shape::Tri, Textured::No, Blend::Semi, Modulation::On> *) = 0;
    virtual void write0(Poly<Shading::Flat, Shape::Tri, Textured::Yes, Blend::Off, Modulation::Off> *) = 0;
    virtual void write0(Poly<Shading::Flat, Shape::Tri, Textured::Yes, Blend::Off, Modulation::On> *) = 0;
    virtual void write0(Poly<Shading::Flat, Shape::Tri, Textured::Yes, Blend::Semi, Modulation::Off> *) = 0;
    virtual void write0(Poly<Shading::Flat, Shape::Tri, Textured::Yes, Blend::Semi, Modulation::On> *) = 0;
    virtual void write0(Poly<Shading::Flat, Shape::Quad, Textured::No, Blend::Off, Modulation::Off> *) = 0;
    virtual void write0(Poly<Shading::Flat, Shape::Quad, Textured::No, Blend::Off, Modulation::On> *) = 0;
    virtual void write0(Poly<Shading::Flat, Shape::Quad, Textured::No, Blend::Semi, Modulation::Off> *) = 0;
    virtual void write0(Poly<Shading::Flat, Shape::Quad, Textured::No, Blend::Semi, Modulation::On> *) = 0;
    virtual void write0(Poly<Shading::Flat, Shape::Quad, Textured::Yes, Blend::Off, Modulation::Off> *) = 0;
    virtual void write0(Poly<Shading::Flat, Shape::Quad, Textured::Yes, Blend::Off, Modulation::On> *) = 0;
    virtual void write0(Poly<Shading::Flat, Shape::Quad, Textured::Yes, Blend::Semi, Modulation::Off> *) = 0;
    virtual void write0(Poly<Shading::Flat, Shape::Quad, Textured::Yes, Blend::Semi, Modulation::On> *) = 0;
    virtual void write0(Poly<Shading::Gouraud, Shape::Tri, Textured::No, Blend::Off, Modulation::Off> *) = 0;
    virtual void write0(Poly<Shading::Gouraud, Shape::Tri, Textured::No, Blend::Off, Modulation::On> *) = 0;
    virtual void write0(Poly<Shading::Gouraud, Shape::Tri, Textured::No, Blend::Semi, Modulation::Off> *) = 0;
    virtual void write0(Poly<Shading::Gouraud, Shape::Tri, Textured::No, Blend::Semi, Modulation::On> *) = 0;
    virtual void write0(Poly<Shading::Gouraud, Shape::Tri, Textured::Yes, Blend::Off, Modulation::Off> *) = 0;
    virtual void write0(Poly<Shading::Gouraud, Shape::Tri, Textured::Yes, Blend::Off, Modulation::On> *) = 0;
    virtual void write0(Poly<Shading::Gouraud, Shape::Tri, Textured::Yes, Blend::Semi, Modulation::Off> *) = 0;
    virtual void write0(Poly<Shading::Gouraud, Shape::Tri, Textured::Yes, Blend::Semi, Modulation::On> *) = 0;
    virtual void write0(Poly<Shading::Gouraud, Shape::Quad, Textured::No, Blend::Off, Modulation::Off> *) = 0;
    virtual void write0(Poly<Shading::Gouraud, Shape::Quad, Textured::No, Blend::Off, Modulation::On> *) = 0;
    virtual void write0(Poly<Shading::Gouraud, Shape::Quad, Textured::No, Blend::Semi, Modulation::Off> *) = 0;
    virtual void write0(Poly<Shading::Gouraud, Shape::Quad, Textured::No, Blend::Semi, Modulation::On> *) = 0;
    virtual void write0(Poly<Shading::Gouraud, Shape::Quad, Textured::Yes, Blend::Off, Modulation::Off> *) = 0;
    virtual void write0(Poly<Shading::Gouraud, Shape::Quad, Textured::Yes, Blend::Off, Modulation::On> *) = 0;
    virtual void write0(Poly<Shading::Gouraud, Shape::Quad, Textured::Yes, Blend::Semi, Modulation::Off> *) = 0;
    virtual void write0(Poly<Shading::Gouraud, Shape::Quad, Textured::Yes, Blend::Semi, Modulation::On> *) = 0;

    virtual void write0(Line<Shading::Flat, LineType::Simple, Blend::Off> *) = 0;
    virtual void write0(Line<Shading::Flat, LineType::Simple, Blend::Semi> *) = 0;
    virtual void write0(Line<Shading::Flat, LineType::Poly, Blend::Off> *) = 0;
    virtual void write0(Line<Shading::Flat, LineType::Poly, Blend::Semi> *) = 0;
    virtual void write0(Line<Shading::Gouraud, LineType::Simple, Blend::Off> *) = 0;
    virtual void write0(Line<Shading::Gouraud, LineType::Simple, Blend::Semi> *) = 0;
    virtual void write0(Line<Shading::Gouraud, LineType::Poly, Blend::Off> *) = 0;
    virtual void write0(Line<Shading::Gouraud, LineType::Poly, Blend::Semi> *) = 0;

    virtual void write0(Rect<Size::Variable, Textured::No, Blend::Off, Modulation::Off> *) = 0;
    virtual void write0(Rect<Size::Variable, Textured::No, Blend::Semi, Modulation::Off> *) = 0;
    virtual void write0(Rect<Size::Variable, Textured::Yes, Blend::Off, Modulation::Off> *) = 0;
    virtual void write0(Rect<Size::Variable, Textured::Yes, Blend::Semi, Modulation::Off> *) = 0;
    virtual void write0(Rect<Size::S1, Textured::No, Blend::Off, Modulation::Off> *) = 0;
    virtual void write0(Rect<Size::S1, Textured::No, Blend::Semi, Modulation::Off> *) = 0;
    virtual void write0(Rect<Size::S1, Textured::Yes, Blend::Off, Modulation::Off> *) = 0;
    virtual void write0(Rect<Size::S1, Textured::Yes, Blend::Semi, Modulation::Off> *) = 0;
    virtual void write0(Rect<Size::S8, Textured::No, Blend::Off, Modulation::Off> *) = 0;
    virtual void write0(Rect<Size::S8, Textured::No, Blend::Semi, Modulation::Off> *) = 0;
    virtual void write0(Rect<Size::S8, Textured::Yes, Blend::Off, Modulation::Off> *) = 0;
    virtual void write0(Rect<Size::S8, Textured::Yes, Blend::Semi, Modulation::Off> *) = 0;
    virtual void write0(Rect<Size::S16, Textured::No, Blend::Off, Modulation::Off> *) = 0;
    virtual void write0(Rect<Size::S16, Textured::No, Blend::Semi, Modulation::Off> *) = 0;
    virtual void write0(Rect<Size::S16, Textured::Yes, Blend::Off, Modulation::Off> *) = 0;
    virtual void write0(Rect<Size::S16, Textured::Yes, Blend::Semi, Modulation::Off> *) = 0;
    virtual void write0(Rect<Size::Variable, Textured::No, Blend::Off, Modulation::On> *) = 0;
    virtual void write0(Rect<Size::Variable, Textured::No, Blend::Semi, Modulation::On> *) = 0;
    virtual void write0(Rect<Size::Variable, Textured::Yes, Blend::Off, Modulation::On> *) = 0;
    virtual void write0(Rect<Size::Variable, Textured::Yes, Blend::Semi, Modulation::On> *) = 0;
    virtual void write0(Rect<Size::S1, Textured::No, Blend::Off, Modulation::On> *) = 0;
    virtual void write0(Rect<Size::S1, Textured::No, Blend::Semi, Modulation::On> *) = 0;
    virtual void write0(Rect<Size::S1, Textured::Yes, Blend::Off, Modulation::On> *) = 0;
    virtual void write0(Rect<Size::S1, Textured::Yes, Blend::Semi, Modulation::On> *) = 0;
    virtual void write0(Rect<Size::S8, Textured::No, Blend::Off, Modulation::On> *) = 0;
    virtual void write0(Rect<Size::S8, Textured::No, Blend::Semi, Modulation::On> *) = 0;
    virtual void write0(Rect<Size::S8, Textured::Yes, Blend::Off, Modulation::On> *) = 0;
    virtual void write0(Rect<Size::S8, Textured::Yes, Blend::Semi, Modulation::On> *) = 0;
    virtual void write0(Rect<Size::S16, Textured::No, Blend::Off, Modulation::On> *) = 0;
    virtual void write0(Rect<Size::S16, Textured::No, Blend::Semi, Modulation::On> *) = 0;
    virtual void write0(Rect<Size::S16, Textured::Yes, Blend::Off, Modulation::On> *) = 0;
    virtual void write0(Rect<Size::S16, Textured::Yes, Blend::Semi, Modulation::On> *) = 0;

    virtual void write0(BlitVramVram *);

    virtual void write0(TPage *) = 0;
    virtual void write0(TWindow *) = 0;
    virtual void write0(DrawingAreaStart *) = 0;
    virtual void write0(DrawingAreaEnd *) = 0;
    virtual void write0(DrawingOffset *) = 0;
    virtual void write0(MaskBit *) = 0;
};

}  // namespace PCSX
