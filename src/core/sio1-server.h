/***************************************************************************
 *   Copyright (C) 2022 PCSX-Redux authors                                 *
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

#include <queue>
#include <string>

#include "support/eventbus.h"
#include "support/uvfile.h"

namespace PCSX {
class SIO1Server {
  public:
    enum class SIO1ServerStatus {
        SERVER_STOPPED,
        SERVER_STOPPING,
        SERVER_STARTED,
    };

    SIO1ServerStatus getServerStatus() { return m_serverStatus; }

    SIO1Server();
    void startServer(uv_loop_t* loop, int port = 6699);
    void stopServer();

  private:
    EventBus::Listener m_listener;
    uv_async_t m_async;
    SIO1ServerStatus m_serverStatus = SIO1ServerStatus::SERVER_STOPPED;
    UvFifoListener m_fifoListener;
};

class SIO1Client {
  public:
    enum class SIO1ClientStatus {
        CLIENT_STOPPED,
        CLIENT_STOPPING,
        CLIENT_STARTED,
    };
    SIO1ClientStatus getClientStatus() { return m_clientStatus; }
    SIO1Client();
    void startClient(std::string_view address, unsigned port);
    void stopClient();
    void reconnect();

  private:
    EventBus::Listener m_listener;
    SIO1ClientStatus m_clientStatus = SIO1ClientStatus::CLIENT_STOPPED;
    std::string_view m_address;
    unsigned m_port;
};

}  // namespace PCSX
