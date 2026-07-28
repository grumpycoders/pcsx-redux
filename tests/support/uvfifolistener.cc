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

#include <uv.h>

#include <chrono>
#include <thread>

#include "gtest/gtest.h"
#include "support/uvfile.h"

using namespace PCSX;

namespace {

// Ports picked high and odd to reduce the odds of colliding with anything real
// on a developer box or CI runner.
constexpr unsigned c_squattedPort = 47821;
constexpr unsigned c_freePort = 47823;
constexpr unsigned c_notifyPort = 47825;

// Pump the caller-side loop for a while, giving the uv worker thread time to
// service the queued request() and hand anything back through the async.
void pump(uv_loop_t* loop, int milliseconds = 250) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(milliseconds);
    while (std::chrono::steady_clock::now() < deadline) {
        uv_run(loop, UV_RUN_NOWAIT);
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}

// Takes a port and holds it, so UvFifoListener's bind is guaranteed to fail.
struct Squatter {
    explicit Squatter(uv_loop_t* loop, unsigned port) {
        uv_tcp_init(loop, &m_tcp);
        struct sockaddr_in addr;
        EXPECT_EQ(uv_ip4_addr("0.0.0.0", port, &addr), 0);
        EXPECT_EQ(uv_tcp_bind(&m_tcp, reinterpret_cast<const sockaddr*>(&addr), 0), 0);
        EXPECT_EQ(uv_listen(reinterpret_cast<uv_stream_t*>(&m_tcp), 16, [](uv_stream_t*, int) {}), 0);
    }
    ~Squatter() { uv_close(reinterpret_cast<uv_handle_t*>(&m_tcp), [](uv_handle_t*) {}); }
    uv_tcp_t m_tcp = {};
};

}  // namespace

// Control: a listener that binds cleanly must start and stop without incident.
// If this one ever fails, the busy-port test below proves nothing.
TEST(UvFifoListener, StartStopOnFreePort) {
    UvThreadOp::UvThread uvThread;
    uv_loop_t loop;
    uv_loop_init(&loop);

    int nullptrCallbacks = 0;
    UvFifoListener listener;
    uv_async_t async = {};
    listener.start(c_freePort, &loop, &async, [&nullptrCallbacks](UvFifo* fifo) {
        if (!fifo) nullptrCallbacks++;
    });
    pump(&loop);

    EXPECT_EQ(listener.status(), UvFifoListener::Status::Listening);
    EXPECT_TRUE(listener.isListening());
    EXPECT_EQ(listener.lastErrorCode(), 0);
    EXPECT_EQ(nullptrCallbacks, 0);

    listener.stop();
    pump(&loop);

    EXPECT_EQ(listener.status(), UvFifoListener::Status::Stopped);
    EXPECT_EQ(nullptrCallbacks, 1);

    uv_run(&loop, UV_RUN_NOWAIT);
    uv_loop_close(&loop);
}

// The bug: start() on an occupied port hits the uv_tcp_bind failure path, which
// uv_close()es m_server and tells nobody. Nothing in UvFifoListener records that
// it is already closing, so a subsequent stop() - which is exactly what the GUI
// checkbox and the Quitting event both do, since SIO1Server/ATConsServer set
// SERVER_STARTED unconditionally - closes the same handle a second time.
TEST(UvFifoListener, StopAfterFailedBindIsSafe) {
    UvThreadOp::UvThread uvThread;
    uv_loop_t loop;
    uv_loop_init(&loop);

    Squatter squatter(&loop, c_squattedPort);

    int nullptrCallbacks = 0;
    UvFifoListener listener;
    uv_async_t async = {};
    listener.start(c_squattedPort, &loop, &async, [&nullptrCallbacks](UvFifo* fifo) {
        if (!fifo) nullptrCallbacks++;
    });
    pump(&loop);

    // The failure has to be visible, and it has to be the *right* failure -
    // an unreported bind error and a bind error reported as the wrong code are
    // both things a status bullet would render identically.
    EXPECT_EQ(listener.status(), UvFifoListener::Status::Failed);
    EXPECT_FALSE(listener.isListening());
    EXPECT_EQ(listener.lastErrorCode(), UV_EADDRINUSE);
    EXPECT_STREQ(listener.lastError(), uv_strerror(UV_EADDRINUSE));
    // Consumers learn about it through the same nullptr they get on shutdown,
    // so nobody has to grow a second teardown path.
    EXPECT_EQ(nullptrCallbacks, 1);

    // This is the line that used to abort inside uv_close.
    listener.stop();
    pump(&loop);

    EXPECT_EQ(listener.status(), UvFifoListener::Status::Failed);

    uv_run(&loop, UV_RUN_NOWAIT);
    uv_loop_close(&loop);
}

// UvFifo has no readable callback of its own - data lands in a lock-free queue
// on the worker thread and the consumer is expected to poll size(). That is
// what SIO1 and ATCons do off the counters, and it is why porting the GDB and
// web servers onto this transport needs a wake-up first: frame-granularity
// polling would put visible latency on every GDB packet.
//
// This test only passes if uv_async_send actually reached the caller's loop.
// Nothing else runs the callback, so a notifier that never fires fails it.
TEST(UvFifo, ReadableNotifierFires) {
    UvThreadOp::UvThread uvThread;
    uv_loop_t loop;
    uv_loop_init(&loop);

    UvFifo* accepted = nullptr;
    UvFifoListener listener;
    uv_async_t listenerAsync = {};
    listener.start(c_notifyPort, &loop, &listenerAsync, [&accepted](UvFifo* fifo) {
        if (fifo) accepted = fifo;
    });
    pump(&loop);
    ASSERT_EQ(listener.status(), UvFifoListener::Status::Listening);

    IO<File> client(new UvFifo("127.0.0.1", c_notifyPort));
    pump(&loop);
    ASSERT_NE(accepted, nullptr);
    IO<File> serverSide(accepted);

    int notifications = 0;
    uv_async_t notifyAsync = {};
    accepted->setNotifier(&loop, &notifyAsync, [&notifications]() { notifications++; });
    pump(&loop);
    const int baseline = notifications;

    static const char c_payload[] = "hello";
    constexpr size_t c_payloadSize = sizeof(c_payload) - 1;
    client->write(c_payload, c_payloadSize);
    pump(&loop, 500);

    EXPECT_GT(notifications, baseline);
    EXPECT_EQ(serverSide->size(), c_payloadSize);

    char buffer[16] = {};
    EXPECT_EQ(serverSide->read(buffer, c_payloadSize), static_cast<ssize_t>(c_payloadSize));
    EXPECT_STREQ(buffer, c_payload);

    // A peer hanging up has to wake the consumer too, or anything waiting on
    // the notifier instead of polling never learns the connection is gone.
    const int beforeClose = notifications;
    client.reset();
    pump(&loop, 500);
    EXPECT_GT(notifications, beforeClose);
    EXPECT_TRUE(serverSide->isClosed());

    accepted->clearNotifier();
    serverSide.reset();
    listener.stop();
    pump(&loop);
    uv_close(reinterpret_cast<uv_handle_t*>(&notifyAsync), [](uv_handle_t*) {});
    uv_close(reinterpret_cast<uv_handle_t*>(&listenerAsync), [](uv_handle_t*) {});
    pump(&loop);
    uv_loop_close(&loop);
}
