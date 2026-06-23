/***************************************************************************
 *   Copyright (C) 2021 PCSX-Redux authors                                 *
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

#include <atomic>
#include <bitset>
#include <chrono>
#include <climits>
#include <cstdint>
#include <ios>
#include <optional>
#include <sstream>
#include <thread>
#include "gtest/gtest.h"
#include "main/main.h"
#include "core/psxmem.h"
#include "core/system.h"
#include "core/psxemulator.h"
#include "support/eventbus.h"


TEST(CPU, InterpreterValid) {
    MainInvoker invoker("-no-ui", "-run", "-bios", "src/mips/openbios/openbios.bin", "-testmode", "-interpreter",
                        "-luacov", "-loadexe", "src/mips/tests/msan-valid/msan-valid.ps-exe");
    const int ret = invoker.invoke();
    EXPECT_EQ(ret, 0);
}

TEST(CPU, DynarecValid) {
    MainInvoker invoker("-no-ui", "-run", "-bios", "src/mips/openbios/openbios.bin", "-testmode", "-dynarec",
                        "-luacov", "-loadexe", "src/mips/tests/msan-valid/msan-valid.ps-exe");
    const int ret = invoker.invoke();
    EXPECT_EQ(ret, 0);
}

static constexpr std::chrono::milliseconds _30s_MILLIS = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::seconds(30));

inline uint8_t inspectMsanInitializedBitmap(const uint32_t address) {
    const uint32_t bitmapIndex = (address - PCSX::g_emulator->m_mem->c_msanStart) / 8;
    return PCSX::g_emulator->m_mem->m_msanInitializedBitmap[bitmapIndex];
}

static unsigned int nextMsanCheckIndex = 0;
static uint8_t SWX_EXPECTED_BITMASKS[36] = {
    0b0001, // swl 0 (8-bit) => lwl 1 (16-bit)
    0b0001, // swl 0 (8-bit) => lwl 2 (24-bit)
    0b0001, // swl 0 (8-bit) => lwl 3 (32-bit)
                //
    0b0011, // swl 1 (16-bit) => lwl 2 (24-bit)
    0b0011, // swl 1 (16-bit) => lwl 3 (32-bit)

    0b0111, // swl 2 (24-bit) => lwl 3 (32-bit)

	0b0001, // swl (8-bit) => lwr (32-bit)
	0b0001, // swl (8-bit) => lwr (24-bit)
	0b0001, // swl (8-bit) => lwr (16-bit)
	0b0001, // swl (8-bit) => lwr (8-bit)

	0b0011, // swl (16-bit) => lwr (32-bit)
	0b0011, // swl (16-bit) => lwr (24-bit)
	0b0011, // swl (16-bit) => lwr (16-bit)
	0b0011, // swl (16-bit) => lwr (8-bit)

	0b0111, // swl (24-bit) => lwr (32-bit)
	0b0111, // swl (24-bit) => lwr (24-bit)
	0b0111, // swl (24-bit) => lwr (16-bit)
	0b0111, // swl (24-bit) => lwr (8-bit)

	0b1000, // swr (8-bit) => lwr (32-bit)
	0b1000, // swr (8-bit) => lwr (24-bit)
	0b1000, // swr (8-bit) => lwr (16-bit)

	0b1100, // swr (16-bit) => lwr (32-bit)
	0b1100, // swr (16-bit) => lwr (24-bit)

	0b1110, // swr (24-bit) => lwr (32-bit)

	0b1000, // swr (8-bit) => lwl (32-bit)
	0b1000, // swr (8-bit) => lwl (24-bit)
	0b1000, // swr (8-bit) => lwl (16-bit)
	0b1000, // swr (8-bit) => lwl (8-bit)

	0b1100, // swr (16-bit) => lwl (32-bit)
	0b1100, // swr (16-bit) => lwl (24-bit)
	0b1100, // swr (16-bit) => lwl (16-bit)
	0b1100, // swr (16-bit) => lwl (8-bit)

	0b1110, // swr (24-bit) => lwl (32-bit)
	0b1110, // swr (24-bit) => lwl (24-bit)
	0b1110, // swr (24-bit) => lwl (16-bit)
	0b1110, // swr (24-bit) => lwl (8-bit)
};

std::optional<std::string> nextMsanTest(const std::string& msg) {
    if (PCSX::g_system->running()) {
        return "Expected emulator to be paused";
    }
    auto allocCount = PCSX::g_emulator->m_mem->m_msanAllocs.size();
    if (allocCount != 1) {
        std::stringstream returnMsg;
        returnMsg << "Expected 1 MSAN allocation, got";
        returnMsg << allocCount;
        return returnMsg.str();
    } else if (nextMsanCheckIndex >= 36) {
        std::stringstream returnMsg;
        returnMsg << "Invalid MSAN check test index: ";
        returnMsg << nextMsanCheckIndex;
        return returnMsg.str();
    }
    auto alloc = PCSX::g_emulator->m_mem->m_msanAllocs.begin();
    std::stringstream ss;
    ss << "32-bit read from uninitialized bytes in usable, partially initialized msan memory: 0x" << std::hex << alloc->first;
    std::string expectedMsg = ss.str();
    if (msg != expectedMsg) {
        std::stringstream returnMsg;
        returnMsg << "Inavlid MSAN event logged, expected: ";
        returnMsg << expectedMsg;
        returnMsg << ", got :";
        returnMsg << msg;
        return returnMsg.str();
    }
    const uint8_t expectedInitBitmap = SWX_EXPECTED_BITMASKS[nextMsanCheckIndex];
    const uint8_t actualInitBitmap = inspectMsanInitializedBitmap(alloc->first);
    if (expectedInitBitmap != actualInitBitmap) {
        std::stringstream ss;
        ss << "Initialized bitmap for address 0x" << std::hex << alloc->first
            << " mismatch: 0b" << std::bitset<8>(expectedInitBitmap)
            <<  " != 0b" << std::bitset<8>(actualInitBitmap);
        return ss.str();
    }
    PCSX::g_system->resume();
    return std::nullopt;
}

TEST(CPU, InterpreterInvalid) {
    using namespace std::chrono_literals;
    nextMsanCheckIndex = 0;
    std::atomic_int ret(INT_MIN);
    MainInvoker invoker("-no-ui", "-bios", "src/mips/openbios/openbios.bin", "-testmode", "-interpreter",
                        "-luacov", "-loadexe", "src/mips/tests/msan-invalid/msan-invalid.ps-exe");
    std::thread thread([&](){
        ret.store(invoker.invoke());
    });
    std::chrono::milliseconds elapsed(0);
    std::optional<std::string> result = std::nullopt;
    PCSX::EventBus::Listener listener(PCSX::g_system->m_eventBus);
    listener.listen<PCSX::Events::LogMessage>([&](const PCSX::Events::LogMessage& event) {
        if (event.logClass != PCSX::LogClass::CPU
            || event.message.starts_with("32-bit read")) {
            return;
        }
        nextMsanTest(event.message);
    });
    PCSX::g_system->resume();
    while (elapsed < _30s_MILLIS
        && ret.load() == INT_MIN) {
        std::this_thread::sleep_for(200ms);
        elapsed += std::chrono::milliseconds(200ms);
    }
    if (elapsed >= _30s_MILLIS) {
        PCSX::g_system->quit();
    }
    if (thread.joinable()) {
        thread.join();
    }
    if (result.has_value()) {
        FAIL() << result.value();
    }
    const int exit_code = ret.load();
    if (exit_code == INT_MIN) {
        FAIL() << "Test timed out";
    }
    EXPECT_EQ(exit_code, 0) << "Mismatch in expected exit code";
}

TEST(CPU, DynarecInvalid) {
    using namespace std::chrono_literals;
    nextMsanCheckIndex = 0;
    std::atomic_int ret(INT_MIN);
    MainInvoker invoker("-no-ui", "-bios", "src/mips/openbios/openbios.bin", "-testmode", "-dynarec",
                        "-luacov", "-loadexe", "src/mips/tests/msan-invalid/msan-invalid.ps-exe");
    std::thread thread([&](){
        ret.store(invoker.invoke());
    });
    std::chrono::milliseconds elapsed(0);
    std::optional<std::string> result = std::nullopt;
    PCSX::EventBus::Listener listener(PCSX::g_system->m_eventBus);
    listener.listen<PCSX::Events::LogMessage>([](const PCSX::Events::LogMessage& event) {
        if (event.logClass != PCSX::LogClass::CPU
            || event.message.starts_with("32-bit read")) {
            return;
        }
        nextMsanTest(event.message);
    });
    PCSX::g_system->resume();
    while (elapsed < _30s_MILLIS
        && ret.load() == INT_MIN) {
        std::this_thread::sleep_for(200ms);
        elapsed += std::chrono::milliseconds(200ms);
    }
    if (elapsed >= _30s_MILLIS) {
        PCSX::g_system->quit();
    }
    if (thread.joinable()) {
        thread.join();
    }
    if (result.has_value()) {
        FAIL() << result.value();
    }
    const int exit_code = ret.load();
    if (exit_code == INT_MIN) {
        FAIL() << "Test timed out";
    }
    EXPECT_EQ(exit_code, 0) << "Mismatch in expected exit code";
}
