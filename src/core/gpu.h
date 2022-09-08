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
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

#include "core/psxemulator.h"
#include "core/psxmem.h"
#include "magic_enum/include/magic_enum.hpp"
#include "support/eventbus.h"
#include "support/file.h"
#include "support/list.h"
#include "support/opengl.h"
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
    virtual bool configure() = 0;
    virtual void debug() = 0;
    virtual ~GPU() {}

    void serialize(SaveStateWrapper *);
    void deserialize(const SaveStateWrapper *);

  private:
    uint32_t s_usedAddr[3];
    bool CheckForEndlessLoop(uint32_t laddr);
    uint32_t gpuDmaChainSize(uint32_t addr);
    virtual void resetBackend() = 0;

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
    virtual void setOpenGLContext() {}

    virtual void restoreStatus(uint32_t status) = 0;

    virtual void vblank(bool fromGui = false) = 0;
    virtual void addVertex(short sx, short sy, int64_t fx, int64_t fy, int64_t fz) {
        throw std::runtime_error("Not yet implemented");
    }
    virtual void pgxpMemory(unsigned int addr, unsigned char *pVRAM) {}
    virtual void pgxpCacheVertex(short sx, short sy, const unsigned char *_pVertex) {
        throw std::runtime_error("Not yet implemented");
    }

    virtual void setDither(int setting) = 0;
    void reset() {
        resetBackend();
        m_readFifo->reset();
        m_processor->reset();
        m_defaultProcessor.setActive();
    }
    virtual void clearVRAM() = 0;
    virtual GLuint getVRAMTexture() = 0;
    virtual void setLinearFiltering() = 0;

    static std::unique_ptr<GPU> getSoft();
    static std::unique_ptr<GPU> getOpenGL();

    enum class Ownership { BORROW, ACQUIRE };
    virtual Slice getVRAM(Ownership = Ownership::BORROW) = 0;
    virtual void partialUpdateVRAM(int x, int y, int w, int h, const uint16_t *pixels) = 0;

    struct ScreenShot {
        Slice data;
        uint16_t width, height;
        enum { BPP_16, BPP_24 } bpp;
    };
    virtual ScreenShot takeScreenShot() { throw std::runtime_error("Not yet implemented"); }

    struct GPUStats {
        unsigned triangles = 0;
        unsigned texturedTriangles = 0;
        unsigned rectangles = 0;
        unsigned sprites = 0;
        unsigned pixelWrites = 0;
        unsigned pixelReads = 0;
        unsigned texelReads = 0;
        GPUStats &operator+=(const GPUStats &stats) {
            triangles += stats.triangles;
            texturedTriangles += stats.texturedTriangles;
            rectangles += stats.rectangles;
            sprites += stats.sprites;
            pixelWrites += stats.pixelWrites;
            pixelReads += stats.pixelReads;
            texelReads += stats.texelReads;
            return *this;
        }
    };

    struct Logged;
    typedef Intrusive::List<Logged> LoggedList;
    struct Logged : public LoggedList::Node {
        virtual ~Logged() {}
        virtual std::string_view getName() = 0;
        virtual void drawLogNode() = 0;
        virtual void execute(GPU *) = 0;
        virtual void generateStatsInfo() = 0;
        virtual void cumulateStats(GPUStats *) = 0;

        enum class Origin { DATAWRITE, CTRLWRITE, DIRECT_DMA, CHAIN_DMA, REPLAY };
        uint64_t frame;
        uint32_t value, length;
        uint32_t pc;

        Origin origin;

        bool enabled = true;
        bool highlight = false;
    };

  private:
    uint32_t m_statusControl[256];

    class Buffer {
      public:
        Buffer(uint32_t value) : m_value(SWAP_LE32(value)) {
            m_data = &m_value;
            m_size = 1;
        }
        Buffer(const uint32_t *ptr, size_t size) : m_size(size), m_data(ptr) {}
        Buffer(const Buffer &other) = delete;
        Buffer(Buffer &&other) = delete;
        Buffer &operator=(const Buffer &other) = delete;
        Buffer &operator=(Buffer &&other) = delete;
        bool isEmpty() const { return m_size == 0; }
        void rewind() {
            m_data--;
            m_size++;
        }
        void consume(size_t size) {
            m_data += size;
            m_size -= size;
        }
        uint32_t get() {
            if (isEmpty()) return 0;
            m_size--;
            return SWAP_LE32(*m_data++);
        }
        size_t size() { return m_size; }
        const uint32_t *data() { return m_data; }

      private:
        uint32_t m_value;
        size_t m_size;
        const uint32_t *m_data;
    };

    class Command {
      public:
        Command() : m_gpu(nullptr) {}
        Command(GPU *parent) : m_gpu(parent) {}
        virtual ~Command() {}
        virtual void processWrite(Buffer &, Logged::Origin, uint32_t value, uint32_t length);
        virtual void reset() {}
        void setActive() { m_gpu->m_processor = this; }

      protected:
        GPU *m_gpu;

      private:
        void setGPU(GPU *gpu) { m_gpu = gpu; }

        friend class GPU;
    };

  public:
    template <typename T, T wMax = 1024, T hMax = 512>
    static bool clip(T &x, T &y, T &w, T &h) {
        bool clipped = false;
        if (x >= wMax || y >= hMax) {
            x = wMax;
            y = hMax;
            if ((w != 0) || (h != 0)) {
                w = h = 0;
                return true;
            }
            return false;
        }
        if (x < 0) {
            clipped = true;
            w += x;
            x = 0;
        }
        if (y < 0) {
            clipped = true;
            h += y;
            y = 0;
        }
        if (w < 0 || h < 0) {
            h = w = 0;
            return true;
        }
        if (x + w > wMax) {
            clipped = true;
            w = wMax - x;
        }
        if (y + h > hMax) {
            clipped = true;
            h = hMax - y;
        }
        return clipped;
    }

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

    struct ClearCache final : public Logged {
        std::string_view getName() override { return "Clear Cache"; }
        void drawLogNode() override;
        void execute(GPU *gpu) override { gpu->write0(this); }
        void generateStatsInfo() override {}
        void cumulateStats(GPUStats *) override {}
    };

    struct FastFill final : public Command, public Logged {
        std::string_view getName() override { return "Fast Fill"; }
        void drawLogNode() override;
        void execute(GPU *gpu) override { gpu->write0(this); }
        void generateStatsInfo() override {}
        void cumulateStats(GPUStats *) override;
        FastFill(GPU *parent) : Command(parent) {}
        void processWrite(Buffer &, Logged::Origin, uint32_t value, uint32_t length) override;
        void reset() override { m_state = READ_COLOR; }

        uint32_t color;
        unsigned x, y, w, h;

        struct {
            unsigned x, y, w, h;
        } raw;

        bool clipped = false;

      private:
        enum { READ_COLOR, READ_XY, READ_WH } m_state = READ_COLOR;
    };

    struct BlitVramVram final : public Command, public Logged {
        std::string_view getName() override { return "VRAM to VRAM blit"; }
        void drawLogNode() override;
        void execute(GPU *gpu) override { gpu->write0(this); }
        void generateStatsInfo() override {}
        void cumulateStats(GPUStats *) override;
        BlitVramVram(GPU *parent) : Command(parent) {}
        void processWrite(Buffer &, Logged::Origin, uint32_t value, uint32_t length) override;
        void reset() override { m_state = READ_COMMAND; }

        unsigned sX, sY, dX, dY, w, h;

        struct {
            unsigned sX, sY, dX, dY, w, h;
        } raw;

        bool clipped = false;

      private:
        enum { READ_COMMAND, READ_SRC_XY, READ_DST_XY, READ_HW } m_state = READ_COMMAND;
    };

    struct BlitRamVram final : public Command, public Logged {
        std::string_view getName() override { return "RAM to VRAM blit"; }
        void drawLogNode() override;
        void execute(GPU *gpu) override;
        void generateStatsInfo() override {}
        void cumulateStats(GPUStats *) override;
        BlitRamVram() {}
        BlitRamVram(GPU *parent) : Command(parent) {}
        BlitRamVram(const BlitRamVram &other) {
            x = other.x;
            y = other.y;
            w = other.w;
            h = other.h;
            data.copy(other.data);
        }
        BlitRamVram(BlitRamVram &&) = delete;
        void processWrite(Buffer &, Logged::Origin, uint32_t value, uint32_t length) override;
        void reset() override {
            m_state = READ_COMMAND;
            m_data.clear();
        }

        unsigned x, y, w, h;
        Slice data;

        struct {
            unsigned x, y, w, h;
        } raw;

        bool clipped = false;

      private:
        enum { READ_COMMAND, READ_XY, READ_HW, READ_PIXELS } m_state = READ_COMMAND;
        std::string m_data;
    };

    struct BlitVramRam final : public Command, public Logged {
        std::string_view getName() override { return "VRAM to RAM blit"; }
        void drawLogNode() override;
        void execute(GPU *gpu) override {}
        void generateStatsInfo() override {}
        void cumulateStats(GPUStats *) override;
        BlitVramRam(GPU *parent) : Command(parent) {}
        void processWrite(Buffer &, Logged::Origin, uint32_t value, uint32_t length) override;

        unsigned x, y, w, h;

        struct {
            unsigned x, y, w, h;
        } raw;

        bool clipped = false;

      private:
        enum { READ_COMMAND, READ_XY, READ_HW } m_state = READ_COMMAND;
    };

    struct TPage : public Logged {
        std::string_view getName() override { return "Texture Page"; }
        void drawLogNode() override;
        void drawLogNodeCommon();
        void execute(GPU *gpu) override { gpu->write0(this); }
        void generateStatsInfo() override {}
        void cumulateStats(GPUStats *) override {}
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
        std::string_view getName() override { return "Texture Window"; }
        void drawLogNode() override;
        void execute(GPU *gpu) override { gpu->write0(this); }
        void generateStatsInfo() override {}
        void cumulateStats(GPUStats *) override {}
        TWindow(uint32_t value);
        TWindow(const TWindow &other) = default;
        TWindow(TWindow &&other) = default;
        TWindow &operator=(const TWindow &other) = default;
        unsigned x, y, w, h;
        uint32_t raw;
    };

    struct DrawingAreaStart : public Logged {
        std::string_view getName() override { return "Drawing Area Start"; }
        void drawLogNode() override;
        void execute(GPU *gpu) override { gpu->write0(this); }
        void generateStatsInfo() override {}
        void cumulateStats(GPUStats *) override {}
        DrawingAreaStart(uint32_t value);
        DrawingAreaStart(const DrawingAreaStart &other) = default;
        DrawingAreaStart(DrawingAreaStart &&other) = default;
        DrawingAreaStart &operator=(const DrawingAreaStart &other) = default;
        unsigned x, y;
        uint32_t raw;
    };

    struct DrawingAreaEnd : public Logged {
        std::string_view getName() override { return "Drawing Area End"; }
        void drawLogNode() override;
        void execute(GPU *gpu) override { gpu->write0(this); }
        void generateStatsInfo() override {}
        void cumulateStats(GPUStats *) override {}
        DrawingAreaEnd(uint32_t value);
        DrawingAreaEnd(const DrawingAreaEnd &other) = default;
        DrawingAreaEnd(DrawingAreaEnd &&other) = default;
        DrawingAreaEnd &operator=(const DrawingAreaEnd &other) = default;
        unsigned x, y;
        uint32_t raw;
    };

    struct DrawingOffset : public Logged {
        std::string_view getName() override { return "Drawing Offset"; }
        void drawLogNode() override;
        void execute(GPU *gpu) override { gpu->write0(this); }
        void generateStatsInfo() override {}
        void cumulateStats(GPUStats *) override {}
        DrawingOffset(uint32_t value);
        DrawingOffset(const DrawingOffset &other) = default;
        DrawingOffset(DrawingOffset &&other) = default;
        DrawingOffset &operator=(const DrawingOffset &other) = default;
        int x, y;
        uint32_t raw;
    };

    struct MaskBit : public Logged {
        std::string_view getName() override { return "Mask Bit"; }
        void drawLogNode() override;
        void execute(GPU *gpu) override { gpu->write0(this); }
        void generateStatsInfo() override {}
        void cumulateStats(GPUStats *) override {}
        MaskBit(uint32_t value);
        MaskBit(const MaskBit &other) = default;
        MaskBit(MaskBit &&other) = default;
        MaskBit &operator=(const MaskBit &other) = default;
        bool set, check;
    };

    template <Shading shading, Shape shape, Textured textured, Blend blend, Modulation modulation>
    struct Poly final : public Command, public Logged {
        static constexpr unsigned count = shape == Shape::Tri ? 3 : 4;

        std::string_view getName() override { return "Polygon"; }
        void drawLogNode() override;
        void execute(GPU *gpu) override { gpu->write0(this); }
        void generateStatsInfo() override;
        void cumulateStats(GPUStats *) override;
        Poly() {}
        void processWrite(Buffer &, Logged::Origin, uint32_t value, uint32_t length) override;
        void reset() override {
            m_state = READ_COLOR;
            m_count = 0;
        }
        uint32_t colors[count];
        int x[count], y[count];
        struct Empty {};
        typedef typename std::conditional<textured == Textured::Yes, unsigned, Empty>::type TextureUnitType;
        [[no_unique_address]] TextureUnitType u[count];
        [[no_unique_address]] TextureUnitType v[count];
        [[no_unique_address]] typename std::conditional<textured == Textured::Yes, TPage, Empty>::type tpage;
        [[no_unique_address]] typename std::conditional<textured == Textured::Yes, uint16_t, Empty>::type clutraw;
        TextureUnitType clutX() {
            if constexpr (textured == Textured::Yes) {
                return clutraw & 0x3f;
            } else {
                return {};
            }
        }
        TextureUnitType clutY() {
            if constexpr (textured == Textured::Yes) {
                return (clutraw >> 6) & 0x1ff;
            } else {
                return {};
            }
        }

      private:
        GPUStats stats;
        unsigned m_count = 0;
        enum { READ_COLOR, READ_XY, READ_UV } m_state = READ_COLOR;
    };

    template <Shading shading, LineType lineType, Blend blend>
    struct Line final : public Command, public Logged {
        std::string_view getName() override { return "Line"; }
        void drawLogNode() override;
        void execute(GPU *gpu) override { gpu->write0(this); }
        void generateStatsInfo() override;
        void cumulateStats(GPUStats *) override;
        Line() {
            if constexpr (lineType == LineType::Simple) m_count = 0;
        }
        void processWrite(Buffer &, Logged::Origin, uint32_t value, uint32_t length) override;
        void reset() override {
            m_state = READ_COLOR;
            if constexpr (lineType == LineType::Simple) {
                m_count = 0;
            } else if constexpr (lineType == LineType::Poly) {
                x.clear();
                y.clear();
                colors.clear();
            }
        }

        template <typename T>
        using Storage = typename std::conditional<lineType == LineType::Poly, std::vector<T>, std::array<T, 2>>::type;

        Storage<int> x, y;
        Storage<uint32_t> colors;

      private:
        GPUStats stats;
        struct Empty {};
        [[no_unique_address]] typename std::conditional<lineType == LineType::Simple, unsigned, Empty>::type m_count;
        enum { READ_COLOR, READ_XY } m_state = READ_COLOR;
    };

    template <Size size, Textured textured, Blend blend, Modulation modulation>
    struct Rect final : public Command, public Logged {
        std::string_view getName() override { return "Rectangle"; }
        void drawLogNode() override;
        void execute(GPU *gpu) override { gpu->write0(this); }
        void generateStatsInfo() override {}
        void cumulateStats(GPUStats *) override;
        Rect() {}
        void processWrite(Buffer &, Logged::Origin, uint32_t value, uint32_t length) override;
        void reset() override { m_state = READ_COLOR; }

        struct Empty {};
        int x, y, w, h;
        typedef typename std::conditional<textured == Textured::Yes, unsigned, Empty>::type TextureUnitType;
        [[no_unique_address]]
        typename std::conditional<(textured == Textured::No) || (modulation == Modulation::On), uint32_t, Empty>::type
            color;
        [[no_unique_address]] TextureUnitType u;
        [[no_unique_address]] TextureUnitType v;
        [[no_unique_address]] typename std::conditional<textured == Textured::Yes, uint16_t, Empty>::type clutraw;
        TextureUnitType clutX() {
            if constexpr (textured == Textured::Yes) {
                return clutraw & 0x3f;
            } else {
                return {};
            }
        }
        TextureUnitType clutY() {
            if constexpr (textured == Textured::Yes) {
                return (clutraw >> 6) & 0x1ff;
            } else {
                return {};
            }
        }

      private:
        enum { READ_COLOR, READ_XY, READ_UV, READ_HW } m_state = READ_COLOR;
    };

    struct CtrlReset : public Logged {
        std::string_view getName() override { return "Reset"; }
        void drawLogNode() override;
        void execute(GPU *gpu) override { gpu->write1(this); }
        void generateStatsInfo() override {}
        void cumulateStats(GPUStats *) override {}
    };
    struct CtrlClearFifo : public Logged {
        std::string_view getName() override { return "Clear Fifo"; }
        void drawLogNode() override;
        void execute(GPU *gpu) override { gpu->write1(this); }
        void generateStatsInfo() override {}
        void cumulateStats(GPUStats *) override {}
    };
    struct CtrlIrqAck : public Logged {
        std::string_view getName() override { return "IRQ Ack"; }
        void drawLogNode() override;
        void execute(GPU *gpu) override {}
        void generateStatsInfo() override {}
        void cumulateStats(GPUStats *) override {}
    };
    struct CtrlDisplayEnable : public Logged {
        std::string_view getName() override { return "Display Enable"; }
        void drawLogNode() override;
        void execute(GPU *gpu) override { gpu->write1(this); }
        void generateStatsInfo() override {}
        void cumulateStats(GPUStats *) override {}
        CtrlDisplayEnable(uint32_t value) : enable((value & 1) == 0) {}
        CtrlDisplayEnable(const CtrlDisplayEnable &other) = default;
        CtrlDisplayEnable(CtrlDisplayEnable &&other) = default;
        CtrlDisplayEnable &operator=(const CtrlDisplayEnable &other) = default;
        bool enable;
    };
    struct CtrlDmaSetting : public Logged {
        std::string_view getName() override { return "DMA Setting"; }
        void drawLogNode() override;
        void execute(GPU *gpu) override { gpu->write1(this); }
        void generateStatsInfo() override {}
        void cumulateStats(GPUStats *) override {}
        CtrlDmaSetting(uint32_t value) : dma(magic_enum::enum_cast<Dma>(value & 3).value()) {}
        CtrlDmaSetting(const CtrlDmaSetting &other) = default;
        CtrlDmaSetting(CtrlDmaSetting &&other) = default;
        CtrlDmaSetting &operator=(const CtrlDmaSetting &other) = default;
        enum class Dma { Off, FifoQuery, Write, Read } dma;
    };
    struct CtrlDisplayStart : public Logged {
        std::string_view getName() override { return "Display Start"; }
        void drawLogNode() override;
        void execute(GPU *gpu) override { gpu->write1(this); }
        void generateStatsInfo() override {}
        void cumulateStats(GPUStats *) override {}
        CtrlDisplayStart(uint32_t value) : x(value & 0x3ff), y((value >> 10) & 0x1ff) {}
        CtrlDisplayStart(const CtrlDisplayStart &other) = default;
        CtrlDisplayStart(CtrlDisplayStart &&other) = default;
        CtrlDisplayStart &operator=(const CtrlDisplayStart &other) = default;
        unsigned x, y;
    };
    struct CtrlHorizontalDisplayRange : public Logged {
        std::string_view getName() override { return "Horizontal Display Range"; }
        void drawLogNode() override;
        void execute(GPU *gpu) override { gpu->write1(this); }
        void generateStatsInfo() override {}
        void cumulateStats(GPUStats *) override {}
        CtrlHorizontalDisplayRange(uint32_t value) : x0(value & 0xfff), x1((value >> 12) & 0xfff) {}
        CtrlHorizontalDisplayRange(const CtrlHorizontalDisplayRange &other) = default;
        CtrlHorizontalDisplayRange(CtrlHorizontalDisplayRange &&other) = default;
        CtrlHorizontalDisplayRange &operator=(const CtrlHorizontalDisplayRange &other) = default;
        unsigned x0, x1;
    };
    struct CtrlVerticalDisplayRange : public Logged {
        std::string_view getName() override { return "Vertical Display Range"; }
        void drawLogNode() override;
        void execute(GPU *gpu) override { gpu->write1(this); }
        void generateStatsInfo() override {}
        void cumulateStats(GPUStats *) override {}
        CtrlVerticalDisplayRange(uint32_t value) : y0(value & 0x3ff), y1((value >> 10) & 0x3ff) {}
        CtrlVerticalDisplayRange(const CtrlVerticalDisplayRange &other) = default;
        CtrlVerticalDisplayRange(CtrlVerticalDisplayRange &&other) = default;
        CtrlVerticalDisplayRange &operator=(const CtrlVerticalDisplayRange &other) = default;
        unsigned y0, y1;
    };
    struct CtrlDisplayMode : public Logged {
        std::string_view getName() override { return "Display Mode"; }
        void drawLogNode() override;
        void execute(GPU *gpu) override { gpu->write1(this); }
        void generateStatsInfo() override {}
        void cumulateStats(GPUStats *) override {}
        CtrlDisplayMode() : CtrlDisplayMode(0) {}
        CtrlDisplayMode(uint32_t value);
        CtrlDisplayMode(const CtrlDisplayMode &other) = default;
        CtrlDisplayMode(CtrlDisplayMode &&other) = default;
        CtrlDisplayMode &operator=(const CtrlDisplayMode &other) = default;
        bool equals(const CtrlDisplayMode &other) const {
            return (hres == other.hres) && (vres == other.vres) && (mode == other.mode) && (depth == other.depth) &&
                   (interlace == other.interlace);
        }
        uint32_t widthRaw;
        enum { HR_256, HR_320, HR_512, HR_640, HR_368, HR_384 } hres;
        enum { VR_240, VR_480 } vres;
        enum { VM_NTSC, VM_PAL } mode;
        enum { CD_15BITS, CD_24BITS } depth;
        bool interlace;
    };
    struct CtrlQuery : public Logged {
        std::string_view getName() override { return "Query"; }
        void drawLogNode() override;
        void execute(GPU *gpu) override { gpu->write1(this); }
        void generateStatsInfo() override {}
        void cumulateStats(GPUStats *) override {}
        CtrlQuery(uint32_t value) : query(value & 0x07) {}
        CtrlQuery(const CtrlQuery &other) = default;
        CtrlQuery(CtrlQuery &&other) = default;
        CtrlQuery &operator=(const CtrlQuery &other) = default;
        enum QueryType { TextureWindow, DrawAreaStart, DrawAreaEnd, DrawOffset, Unknown };
        QueryType type() {
            if ((query <= 1) || (query >= 6)) {
                return Unknown;
            }
            return magic_enum::enum_cast<QueryType>((query - 2) & 3).value();
        }
        uint8_t query;
    };
    struct Display {
        using ivec2 = OpenGL::ivec2;
        using vec2 = OpenGL::vec2;

        ivec2 start;           // Starting coords of the display area
        ivec2 size;            // Width and height of the display area
        vec2 startNormalized;  // Starting coords of the display area normalized in the [0, 1] range
        vec2 sizeNormalized;   // Width and height of the display area normalized in the [0, 1] range

        CtrlDisplayMode info;
        bool enabled;

        int x1, x2, y1, y2;  // Display area range variables

        void reset();
        void set(CtrlDisplayStart *);
        void set(CtrlHorizontalDisplayRange *);
        void set(CtrlVerticalDisplayRange *);
        void set(CtrlDisplayMode *);
        void setLinearFiltering();
        void updateDispArea();
    };
    Display m_display;

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

    virtual void write0(ClearCache *) = 0;
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

    virtual void write1(CtrlReset *) = 0;
    virtual void write1(CtrlClearFifo *) = 0;
    virtual void write1(CtrlIrqAck *) = 0;
    virtual void write1(CtrlDisplayEnable *) = 0;
    virtual void write1(CtrlDmaSetting *) = 0;
    virtual void write1(CtrlDisplayStart *) = 0;
    virtual void write1(CtrlHorizontalDisplayRange *) = 0;
    virtual void write1(CtrlVerticalDisplayRange *) = 0;
    virtual void write1(CtrlDisplayMode *) = 0;
    virtual void write1(CtrlQuery *) = 0;
};

}  // namespace PCSX
