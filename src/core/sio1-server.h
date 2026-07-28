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
#include "support/network.h"

namespace PCSX {

class SIO1Server : public Network::Server {
  public:
    SIO1Server();

  protected:
    void onStarting() override;
    void onConnection(IO<File> connection) override;
    void onStopped() override;

  private:
    EventBus::Listener m_listener;
};

class SIO1Client : public Network::Client {
  public:
    SIO1Client();
    void reconnect(std::string_view address, unsigned port);

  protected:
    void onStarting() override;
    void onStarted(IO<File> connection) override;
    void onStopped() override;

  private:
    EventBus::Listener m_listener;
};

}  // namespace PCSX
