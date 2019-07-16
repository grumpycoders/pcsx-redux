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

#include "core/gpu.h"
#include "gpu/debug.h"
#include "gpu/externals.h"
#include "gpu/prim.h"

namespace PCSX {

class GUI;

namespace GPU {

class impl : public GPUinterface {
    virtual void init() final;
    virtual void shutdown() final;
    virtual void open(GUI *) final;
    virtual void close() final;
    virtual uint32_t readData() final {
        uint32_t l;
        readDataMem(&l, 1, 0xffffffff);
        return lGPUdataRet;
    }
    virtual void readDataMem(uint32_t *pMem, int iSize, uint32_t hwAddr) final;
    virtual uint32_t readStatus() final;
    virtual void writeData(uint32_t gdata) final { writeDataMem(&gdata, 1, 0xffffffff); }
    virtual void writeDataMem(uint32_t *pMem, int iSize, uint32_t hwAddr) final;
    virtual void writeStatus(uint32_t gdata) final;
    virtual int32_t dmaChain(uint32_t *baseAddrL, uint32_t addr) final;
    virtual void updateLace() final;
    virtual bool configure() final {
        if (m_showCfg) {
            return m_prim.configure(&m_showCfg);
        } else {
            return false;
        }
    }

  private:
    class Command {
      public:
        Command(impl *parent) : m_parent(parent) {}
        virtual ~Command() {}
        virtual bool processWrite(uint32_t word);
        virtual bool wantsFullMemory() { return false; }
        void setActive() { m_parent->m_reader = this; }

      protected:
        impl *m_parent;

      private:
        uint8_t m_tx, m_ty;      // texture page
        uint8_t m_abr;           // semi transparent mode
                                 // 0: 0.5*B + 0.5*F
                                 // 1: 1.0*B + 1.0*F
                                 // 2: 1.0*B - 1.0*F
                                 // 3: 1.0*B + 0.25*F
        uint8_t m_tp;            // texture mode
                                 // 0: 4-bits clut
                                 // 1: 8-bit clut
                                 // 2: 15-bits direct
        bool m_dtd;              // dither
        bool m_dfe;              // display area enable
        bool m_td;               // texture disable
        bool m_txflip;           // texture flip on X
        bool m_tyflip;           // texture flip on Y
        uint8_t m_twmx, m_twmy;  // texture window mask
        uint8_t m_twox, m_twoy;  // texture window offset
        uint16_t m_tlx, m_tly;   // drawing area top left
        uint16_t m_brx, m_bry;   // drawing area bottom right;
        uint16_t m_ox, m_oy;     // drawing offset
        bool m_setMask, m_useMask;
    };

    class BlockFill : public Command {
      public:
        BlockFill(impl *parent) : Command(parent) {}
        void setActive(uint32_t color) {
            m_parent->m_reader = this;
            m_color = color;
            m_count = 0;
        }
        bool processWrite(uint32_t word) final;

      private:
        uint32_t m_color;
        unsigned m_count;
        int16_t m_x, m_y, m_w, m_h;
    };

    class Polygon : public Command {
      public:
        Polygon(impl *parent) : Command(parent) {}
        void setActive(uint32_t packetHead) {
            m_parent->m_reader = this;
            m_iip = (packetHead >> 28) & 1;  // flat shading or gouraud shading?
            m_vtx = (packetHead >> 27) & 1;  // 3 vertices or 4 vertices?
            m_tme = (packetHead >> 26) & 1;  // texture mapping?
            m_abe = (packetHead >> 25) & 1;  // semi transparency?
            m_tge = (packetHead >> 24) & 1;  // brightness calculation?
            m_clutID = 0;
            m_texturePage = 0;
            m_count = 0;
            m_state = GET_XY;
            m_colors[0] = packetHead & 0xffffff;
        }
        bool processWrite(uint32_t word) final;

      private:
        bool m_iip, m_vtx, m_tme, m_abe, m_tge;
        uint32_t m_colors[4];
        int16_t m_x[4];
        int16_t m_y[4];
        uint8_t m_u[4];
        uint8_t m_v[4];
        uint16_t m_clutID;
        uint16_t m_texturePage;
        unsigned m_count;
        enum { GET_COLOR, GET_XY, GET_UV } m_state;
    };

    class Line : public Command {
      public:
        Line(impl *parent) : Command(parent) {}
        void setActive(uint32_t packetHead) {
            m_parent->m_reader = this;
            m_iip = (packetHead >> 28) & 1;  // flat shading or gouraud shading?
            m_pll = (packetHead >> 27) & 1;  // polyline?
            m_abe = (packetHead >> 25) & 1;  // semi transparency?
            m_x.clear();
            m_y.clear();
            m_color.clear();
            m_count = 0;
            m_state = GET_COLOR;
            m_color0 = packetHead & 0xffffff;
        }
        bool processWrite(uint32_t word) final;

      private:
        bool m_iip, m_pll, m_abe;
        std::vector<int16_t> m_x;
        std::vector<int16_t> m_y;
        std::vector<uint32_t> m_color;
        unsigned m_count;
        uint32_t m_color0;
        enum { GET_COLOR, GET_XY } m_state;
    };

    class Sprite : public Command {
      public:
        Sprite(impl *parent) : Command(parent) {}
        void setActive(uint32_t packetHead) {
            m_size = (packetHead >> 27) & 3;  // 00 = free size
                                              // 01 = 1x1
                                              // 10 = 8x8
                                              // 11 = 8x8
            m_tme = (packetHead >> 26) & 1;   // texture mapping?
            m_abe = (packetHead >> 25) & 1;   // semi transparency?
            m_color = packetHead & 0xffffff;
            m_state = GET_XY;
        }
        bool processWrite(uint32_t word) final;

      private:
        bool m_tme, m_abe;
        uint32_t m_color;
        uint8_t m_size;
        int16_t m_x, m_y;
        uint8_t m_u, m_v;
        uint16_t m_clutID;
        int16_t m_w, m_h;
        enum { GET_XY, GET_UV, GET_WH } m_state;
    };

    class Blit : public Command {
      public:
        Blit(impl *parent) : Command(parent) {}
        void setActive(uint32_t packetHead) {
            m_color = packetHead & 0xffffff;
            m_state = GET_SRC;
        }
        bool processWrite(uint32_t word) final;

      private:
        uint32_t m_color;
        int16_t m_sx, m_sy, m_dx, m_dy, m_w, m_h;
        enum { GET_SRC, GET_DST, GET_HW } m_state;
    };

    class VRAMWrite : public Command {
      public:
        VRAMWrite(impl *parent) : Command(parent) {}
        void setActive(uint32_t packetHead) {
            m_color = packetHead & 0xffffff;
            m_state = GET_XY;
        }
        bool processWrite(uint32_t word) final;

      private:
        uint32_t m_color;
        int16_t m_x, m_y, m_w, m_h;
        enum { GET_XY, GET_HW } m_state;
    };

    class VRAMRead : public Command {
      public:
        VRAMRead(impl *parent) : Command(parent) {}
        void setActive(uint32_t packetHead) {
            m_color = packetHead & 0xffffff;
            m_state = GET_XY;
        }
        bool processWrite(uint32_t word) final;

      private:
        uint32_t m_color;
        int16_t m_x, m_y, m_w, m_h;
        enum { GET_XY, GET_HW } m_state;
    };

  public:
    Command m_defaultReader = {this};
    BlockFill m_blockFill = {this};
    Polygon m_polygon = {this};
    Line m_line = {this};
    Sprite m_sprite = {this};
    Blit m_blit = {this};
    VRAMWrite m_vramWrite = {this};
    VRAMRead m_vramRead = {this};
    Command *m_reader = &m_defaultReader;

    virtual void save(SaveStates::GPU &gpu) final;
    virtual void load(const SaveStates::GPU &gpu) final;

    virtual void debug() final {
        if (m_showDebug) m_debugger.show();
    }
    Prim m_prim;
    Debugger m_debugger = {m_showDebug};

    ////////////////////////////////////////////////////////////////////////
    // GPU globals
    ////////////////////////////////////////////////////////////////////////

    int32_t lGPUdataRet;
    int32_t lGPUstatusRet;
    uint32_t ulStatusControl[256];

    //    VRAMLoad_t VRAMWrite;
    //    VRAMLoad_t VRAMRead;
    //    DATAREGISTERMODES DataWriteMode;
    //    DATAREGISTERMODES DataReadMode;

    //    bool bSkipNextFrame = false;
    //    DWORD dwLaceCnt = 0;
    //    int iColDepth;
    //    int iWindowMode;
    //    int16_t sDispWidths[8] = {256, 320, 512, 640, 368, 384, 512, 640};
    //    PSXDisplay_t PSXDisplay;
    //    PSXDisplay_t PreviousPSXDisplay;
    //    int32_t lSelectedSlot = 0;
    //    bool bChangeWinMode = false;
    //    bool bDoLazyUpdate = false;
    uint32_t lGPUInfoVals[16];
    //    int iFakePrimBusy = 0;
    //    int iRumbleVal = 0;
    //    int iRumbleTime = 0;

    inline void GPUIsBusy() { lGPUstatusRet &= ~GPUSTATUS_IDLE; }
    inline void GPUIsIdle() { lGPUstatusRet |= GPUSTATUS_IDLE; }

    inline void GPUIsNotReadyForCommands() { lGPUstatusRet &= ~GPUSTATUS_READYFORCOMMANDS; }
    inline void GPUIsReadyForCommands() { lGPUstatusRet |= GPUSTATUS_READYFORCOMMANDS; }
};

}  // namespace GPU

}  // namespace PCSX
