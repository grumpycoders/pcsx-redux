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

#include "support/eventbus.h"

#include <memory>
#include <string>

#include "gtest/gtest.h"

namespace {

struct TestEvent {
    int value;
};

}  // namespace

TEST(EventBus, Basic) {
    auto bus = std::make_shared<PCSX::EventBus::EventBus>();
    PCSX::EventBus::Listener listener(bus);
    int sum = 0;
    listener.listen<TestEvent>([&sum](const TestEvent& e) { sum += e.value; });
    bus->signal(TestEvent{1});
    bus->signal(TestEvent{2});
    EXPECT_EQ(sum, 3);
}

TEST(EventBus, ListenerDestroysItselfDuringSignal) {
    auto bus = std::make_shared<PCSX::EventBus::EventBus>();
    PCSX::EventBus::Listener before(bus);
    auto self = new PCSX::EventBus::Listener(bus);
    PCSX::EventBus::Listener after(bus);
    std::string trace;
    before.listen<TestEvent>([&trace](const TestEvent&) { trace += 'b'; });
    self->listen<TestEvent>([&trace, &self, capture = std::string(64, 's')](const TestEvent&) {
        delete self;
        self = nullptr;
        // The closure must still be alive here.
        trace += capture[0];
    });
    after.listen<TestEvent>([&trace](const TestEvent&) { trace += 'a'; });
    bus->signal(TestEvent{0});
    bus->signal(TestEvent{0});
    EXPECT_EQ(trace, "bsaba");
}

TEST(EventBus, ListenerDestroysNextDuringSignal) {
    auto bus = std::make_shared<PCSX::EventBus::EventBus>();
    PCSX::EventBus::Listener first(bus);
    auto second = new PCSX::EventBus::Listener(bus);
    PCSX::EventBus::Listener third(bus);
    std::string trace;
    first.listen<TestEvent>([&trace, &second](const TestEvent&) {
        trace += '1';
        delete second;
        second = nullptr;
    });
    second->listen<TestEvent>([&trace](const TestEvent&) { trace += '2'; });
    third.listen<TestEvent>([&trace](const TestEvent&) { trace += '3'; });
    bus->signal(TestEvent{0});
    bus->signal(TestEvent{0});
    EXPECT_EQ(trace, "1313");
}

TEST(EventBus, NestedSignalWithDestruction) {
    struct OtherEvent {};
    auto bus = std::make_shared<PCSX::EventBus::EventBus>();
    auto victim = new PCSX::EventBus::Listener(bus);
    PCSX::EventBus::Listener outer(bus);
    std::string trace;
    victim->listen<TestEvent>([&trace](const TestEvent&) { trace += 'v'; });
    victim->listen<OtherEvent>([&trace, &victim](const OtherEvent&) {
        trace += 'o';
        delete victim;
        victim = nullptr;
    });
    outer.listen<TestEvent>([&trace, &bus](const TestEvent&) {
        trace += 'x';
        bus->signal(OtherEvent{});
    });
    bus->signal(TestEvent{0});
    bus->signal(TestEvent{0});
    EXPECT_EQ(trace, "vxox");
}

TEST(EventBus, ClosureDestructorSignalsDuringCleanup) {
    struct Signaller {
        std::shared_ptr<PCSX::EventBus::EventBus> bus;
        ~Signaller() { bus->signal(TestEvent{1}); }
    };
    auto bus = std::make_shared<PCSX::EventBus::EventBus>();
    int count = 0;
    PCSX::EventBus::Listener observer(bus);
    observer.listen<TestEvent>([&count](const TestEvent& e) { count += e.value; });
    auto victim = new PCSX::EventBus::Listener(bus);
    std::shared_ptr<Signaller> signaller(new Signaller{bus});
    victim->listen<TestEvent>([signaller, &victim](const TestEvent&) {
        delete victim;
        victim = nullptr;
    });
    signaller.reset();
    bus->signal(TestEvent{0});
    EXPECT_EQ(victim, nullptr);
    EXPECT_EQ(count, 1);
}
