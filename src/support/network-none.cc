/***************************************************************************
 *   Copyright (C) 2026 PCSX-Redux authors                                 *
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

// There are no sockets on wasm. A Server or Client remembers what it was asked
// to start, so the Network window can show the configured port, but it never
// leaves Stopped and never calls any of its hooks, because nothing started.
#ifdef __EMSCRIPTEN__

#include "support/network.h"

namespace PCSX::Network {

void Server::start(uv_loop_t* loop, int port) {
    m_loop = loop;
    m_port = port;
}

void Server::stop() { settled(); }

Status Server::status() const { return Status::Stopped; }

void Client::start(uv_loop_t* loop, std::string_view host, int port) {
    m_loop = loop;
    m_host = host;
    m_port = port;
}

void Client::stop() { settled(); }

Status Client::status() const { return Status::Stopped; }

const char* Client::lastError() const { return ""; }

}  // namespace PCSX::Network

#endif
