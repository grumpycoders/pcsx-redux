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

#include "support/network.h"

#include <uv.h>

#include <chrono>
#include <memory>
#include <thread>
#include <vector>

#include "gtest/gtest.h"

using namespace PCSX;

namespace {

constexpr int c_serverPort = 47841;
constexpr int c_busyPort = 47843;
constexpr int c_restartPort = 47845;
constexpr int c_deadPort = 47847;
constexpr int c_busyStopPort = 47849;
constexpr int c_doubleStartPort = 47851;
constexpr int c_undeliveredPort = 47853;
constexpr int c_oldPort = 47855;
constexpr int c_newPort = 47857;

void pump(uv_loop_t* loop, int milliseconds = 300) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(milliseconds);
    while (std::chrono::steady_clock::now() < deadline) {
        uv_run(loop, UV_RUN_NOWAIT);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}

// uv_loop_close returns EBUSY while any handle is still open or still closing,
// and ignoring that return leaks the loop's internals. Close everything first,
// then keep pumping until it actually takes.
int closeLoop(uv_loop_t* loop) {
    int result;
    for (int i = 0; (i < 200) && ((result = uv_loop_close(loop)) == UV_EBUSY); i++) {
        uv_run(loop, UV_RUN_NOWAIT);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return result;
}

// Holds a port so a Server's bind is guaranteed to fail. Releasable mid-test,
// so the restart case can watch a Failed endpoint recover.
struct Squatter {
    Squatter(uv_loop_t* loop, int port) {
        uv_tcp_init(loop, &m_tcp);
        struct sockaddr_in addr;
        EXPECT_EQ(uv_ip4_addr("0.0.0.0", port, &addr), 0);
        EXPECT_EQ(uv_tcp_bind(&m_tcp, reinterpret_cast<const sockaddr*>(&addr), 0), 0);
        EXPECT_EQ(uv_listen(reinterpret_cast<uv_stream_t*>(&m_tcp), 16, [](uv_stream_t*, int) {}), 0);
    }
    void release(uv_loop_t* loop) {
        if (m_released) return;
        m_released = true;
        uv_close(reinterpret_cast<uv_handle_t*>(&m_tcp), [](uv_handle_t*) {});
        pump(loop);
    }
    ~Squatter() {
        if (!m_released) uv_close(reinterpret_cast<uv_handle_t*>(&m_tcp), [](uv_handle_t*) {});
    }
    uv_tcp_t m_tcp = {};
    bool m_released = false;
};

// The whole point of the base class: a concrete endpoint says what to do with a
// connection and nothing else. No uv_tcp_init, no bind, no accept, no status
// enum of its own.
class TestServer : public Network::Server {
  public:
    TestServer() : Network::Server("test-server") {}
    std::vector<IO<File>> m_connections;
    int m_stoppedCount = 0;
    int m_failedCount = 0;
    int m_configuredPort = 0;

  protected:
    void onConnection(IO<File> connection) override { m_connections.push_back(connection); }
    void onStopped() override { m_stoppedCount++; }
    void onFailed() override { m_failedCount++; }
    int configuredPort() const override { return m_configuredPort ? m_configuredPort : Server::configuredPort(); }
};

class TestClient : public Network::Client {
  public:
    TestClient() : Network::Client("test-client") {}
};

}  // namespace

TEST(NetworkServer, AcceptsAndReportsRunning) {
    UvThreadOp::UvThread uvThread;
    uv_loop_t loop;
    uv_loop_init(&loop);

    TestServer server;
    EXPECT_EQ(server.status(), Network::Status::Stopped);

    server.start(&loop, c_serverPort);
    pump(&loop);
    EXPECT_EQ(server.status(), Network::Status::Running);
    EXPECT_TRUE(server.isRunning());
    EXPECT_STREQ(server.lastError(), "");
    EXPECT_EQ(server.port(), c_serverPort);

    IO<File> client(new UvFifo("127.0.0.1", c_serverPort));
    pump(&loop);
    ASSERT_EQ(server.m_connections.size(), 1u);

    // The connection is a plain File. That is the deletion: no per-server
    // WriteRequest queue, no alloc/read trampolines, no accept boilerplate.
    static const char c_payload[] = "ping";
    client->write(c_payload, sizeof(c_payload) - 1);
    pump(&loop);
    EXPECT_EQ(server.m_connections[0]->size(), sizeof(c_payload) - 1);

    client.reset();
    server.m_connections.clear();
    server.stop();
    pump(&loop);
    EXPECT_EQ(server.status(), Network::Status::Stopped);
    EXPECT_EQ(server.m_stoppedCount, 1);

    pump(&loop);
    closeLoop(&loop);
}

TEST(NetworkServer, BindFailureIsVisible) {
    UvThreadOp::UvThread uvThread;
    uv_loop_t loop;
    uv_loop_init(&loop);

    Squatter squatter(&loop, c_busyPort);

    TestServer server;
    server.start(&loop, c_busyPort);
    pump(&loop);

    EXPECT_EQ(server.status(), Network::Status::Failed);
    EXPECT_FALSE(server.isRunning());
    EXPECT_STREQ(server.lastError(), uv_strerror(UV_EADDRINUSE));
    // A failure is a teardown, so subclasses get told once and only once.
    EXPECT_EQ(server.m_stoppedCount, 1);

    squatter.release(&loop);
    pump(&loop);
    closeLoop(&loop);
}

// The restart button's actual job: recover an endpoint that is sitting in
// Failed. This exercises the path where stop() has nothing left to close and
// must settle synchronously - if it waited for a listener callback that is
// never coming, the restart would silently never happen.
TEST(NetworkServer, RestartRecoversFromFailure) {
    UvThreadOp::UvThread uvThread;
    uv_loop_t loop;
    uv_loop_init(&loop);

    auto squatter = std::make_unique<Squatter>(&loop, c_restartPort);

    TestServer server;
    server.start(&loop, c_restartPort);
    pump(&loop);
    ASSERT_EQ(server.status(), Network::Status::Failed);

    squatter->release(&loop);
    squatter.reset();

    server.restart();
    pump(&loop);

    EXPECT_EQ(server.status(), Network::Status::Running);
    EXPECT_STREQ(server.lastError(), "");

    server.stop();
    pump(&loop);
    EXPECT_EQ(server.status(), Network::Status::Stopped);

    pump(&loop);
    closeLoop(&loop);
}

// Switching a server on and straight back off on a busy port. Both requests
// reach the uv worker in the same drain, so stop() runs while the failed bind's
// uv_close is still in flight and the status still reads Starting. Closing
// m_server a second time aborts inside libuv.
TEST(NetworkServer, StartStopOnBusyPortDoesNotAbort) {
    UvThreadOp::UvThread uvThread;
    uv_loop_t loop;
    uv_loop_init(&loop);

    Squatter squatter(&loop, c_busyStopPort);

    TestServer server;
    server.start(&loop, c_busyStopPort);
    server.stop();
    server.stop();
    pump(&loop);

    EXPECT_EQ(server.status(), Network::Status::Failed);
    EXPECT_EQ(server.m_failedCount, 1);
    EXPECT_EQ(server.m_stoppedCount, 1);

    squatter.release(&loop);
    pump(&loop);
    EXPECT_EQ(closeLoop(&loop), 0);
}

// A second start() while the first bind is still in flight must not replace
// the listener's async: the first one would never be closed, and the loop
// could never be shut down.
TEST(NetworkServer, StartWhileStartingIsIgnored) {
    UvThreadOp::UvThread uvThread;
    uv_loop_t loop;
    uv_loop_init(&loop);

    TestServer server;
    server.start(&loop, c_doubleStartPort);
    ASSERT_EQ(server.status(), Network::Status::Starting);
    server.start(&loop, c_doubleStartPort);
    pump(&loop);
    EXPECT_EQ(server.status(), Network::Status::Running);

    IO<File> client(new UvFifo("127.0.0.1", c_doubleStartPort));
    pump(&loop);
    EXPECT_EQ(server.m_connections.size(), 1u);

    client.reset();
    server.m_connections.clear();
    server.stop();
    pump(&loop);
    EXPECT_EQ(server.status(), Network::Status::Stopped);
    EXPECT_EQ(server.m_stoppedCount, 1);

    pump(&loop);
    EXPECT_EQ(closeLoop(&loop), 0);
}

// The failed bind has reported Failed, but its nullptr is still sitting in the
// listener's queue because the consumer loop has not run yet. Neither stop()
// nor start() may tear down or replace the async in that window: the stale
// nullptr would then be delivered to the next listener and close its async
// from under it, which the connection below would trip over.
TEST(NetworkServer, StartBeforeFailureIsDelivered) {
    UvThreadOp::UvThread uvThread;
    uv_loop_t loop;
    uv_loop_init(&loop);
    // The squatter lives on its own loop so releasing it does not pump ours.
    uv_loop_t squatLoop;
    uv_loop_init(&squatLoop);
    Squatter squatter(&squatLoop, c_undeliveredPort);

    TestServer server;
    server.start(&loop, c_undeliveredPort);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while ((server.status() != Network::Status::Failed) && (std::chrono::steady_clock::now() < deadline)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    ASSERT_EQ(server.status(), Network::Status::Failed);

    server.stop();
    squatter.release(&squatLoop);
    server.start(&loop, c_undeliveredPort);
    pump(&loop);

    EXPECT_EQ(server.status(), Network::Status::Running);
    EXPECT_EQ(server.m_failedCount, 1);

    // The first connection is what would dequeue a stale nullptr, and the
    // second would then be announced through an async that is already gone.
    IO<File> client(new UvFifo("127.0.0.1", c_undeliveredPort));
    pump(&loop);
    EXPECT_EQ(server.m_connections.size(), 1u);
    EXPECT_EQ(server.m_stoppedCount, 1);
    IO<File> secondClient(new UvFifo("127.0.0.1", c_undeliveredPort));
    pump(&loop);
    EXPECT_EQ(server.m_connections.size(), 2u);
    EXPECT_EQ(server.status(), Network::Status::Running);

    secondClient.reset();
    client.reset();
    server.m_connections.clear();
    server.stop();
    pump(&loop);
    EXPECT_EQ(server.status(), Network::Status::Stopped);

    pump(&squatLoop);
    EXPECT_EQ(closeLoop(&squatLoop), 0);
    pump(&loop);
    EXPECT_EQ(closeLoop(&loop), 0);
}

// The Network window promises that a port change applies on the next restart.
TEST(NetworkServer, RestartPicksUpNewPort) {
    UvThreadOp::UvThread uvThread;
    uv_loop_t loop;
    uv_loop_init(&loop);

    TestServer server;
    server.m_configuredPort = c_oldPort;
    server.start(&loop, c_oldPort);
    pump(&loop);
    ASSERT_EQ(server.status(), Network::Status::Running);
    EXPECT_EQ(server.port(), c_oldPort);

    server.m_configuredPort = c_newPort;
    server.restart();
    pump(&loop);
    EXPECT_EQ(server.status(), Network::Status::Running);
    EXPECT_EQ(server.port(), c_newPort);

    IO<File> client(new UvFifo("127.0.0.1", c_newPort));
    pump(&loop);
    EXPECT_EQ(server.m_connections.size(), 1u);

    client.reset();
    server.m_connections.clear();
    server.stop();
    pump(&loop);
    EXPECT_EQ(server.status(), Network::Status::Stopped);

    pump(&loop);
    EXPECT_EQ(closeLoop(&loop), 0);
}

TEST(NetworkClient, ConnectFailureIsVisible) {
    UvThreadOp::UvThread uvThread;
    uv_loop_t loop;
    uv_loop_init(&loop);

    TestClient client;
    EXPECT_EQ(client.status(), Network::Status::Stopped);

    client.start(&loop, "127.0.0.1", c_deadPort);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while ((client.status() == Network::Status::Starting) && (std::chrono::steady_clock::now() < deadline)) {
        pump(&loop, 20);
    }

    EXPECT_EQ(client.status(), Network::Status::Failed);
    EXPECT_STREQ(client.lastError(), uv_strerror(UV_ECONNREFUSED));

    client.stop();
    EXPECT_EQ(client.status(), Network::Status::Stopped);

    pump(&loop);
    closeLoop(&loop);
}

// The UI iterates this instead of hard-coding a row per service, so an endpoint
// that forgets to register is an endpoint with no status bullet.
TEST(NetworkEndpoint, RegistersAndUnregisters) {
    const size_t before = Network::Endpoint::all().size();
    {
        TestServer server;
        TestClient client;
        const auto& all = Network::Endpoint::all();
        ASSERT_EQ(all.size(), before + 2);
        EXPECT_EQ(all[before]->name(), "test-server");
        EXPECT_EQ(all[before + 1]->name(), "test-client");
    }
    EXPECT_EQ(Network::Endpoint::all().size(), before);
}
