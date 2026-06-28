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

#include <sys/stat.h>
#include <atomic>
#include <bitset>
#include <chrono>
#include <cstdint>
#include <limits>
#include <mutex>
#include <optional>
#include <thread>
#include "fmt/printf.h"
#include "gtest/gtest.h"
#include "main/main.h"
#include "core/psxmem.h"
#include "core/system.h"
#include "core/psxemulator.h"
#include "support/eventbus.h"

using namespace std::chrono_literals;

inline static const bool isMsanLog(const PCSX::Events::LogMessage& event) {
    return event.logClass == PCSX::LogClass::CPU
        && (event.message.contains("-bit read") || event.message.contains("-bit write"));
}

// ==== VALID ====

void execValidTest(const char* type) {
    std::atomic_int exitCode(std::numeric_limits<int>::min());
    MainInvoker invoker("-no-ui", "-run", "-bios", "src/mips/openbios/openbios.bin", "-testmode", type,
                        "-luacov", "-loadexe", "src/mips/tests/msan-valid/msan-valid.ps-exe");
    std::thread thread([&](){
        exitCode.store(invoker.invoke());
    });
    while (invoker.isInStartup());
    PCSX::EventBus::Listener listener(PCSX::g_system->m_eventBus);
    std::atomic_bool shouldFail = false;
    std::atomic_bool msanTriggered = false;
    listener.listen<PCSX::Events::LogMessage>([&](const PCSX::Events::LogMessage& event) {
        if (isMsanLog(event)) {
            msanTriggered = true; 
            shouldFail = true;
        }
    });
    std::chrono::milliseconds elapsed(0);
    PCSX::g_system->resume();
    while (elapsed < 30s
            && exitCode.load() == std::numeric_limits<int>::min()) {
        if (msanTriggered) {
            // Allow the tests to continue, even after triggering an MSAN
            // log. This means the test results are printed and we still
            // show a failure.
            std::chrono::milliseconds awaitPauseElapsed(0);
            while (awaitPauseElapsed < 5s && PCSX::g_system->running()) {
                std::cout << "Awaiting pause" << std::endl;
                std::this_thread::sleep_for(10ms);
                awaitPauseElapsed += 10ms;
            }
            if (awaitPauseElapsed >= 5s) {
                PCSX::g_system->quit(3);
                break;
            }
            PCSX::g_system->resume();
            msanTriggered = false;
        }
        std::this_thread::sleep_for(10ms);
        elapsed += 10ms;
    }
    if (elapsed >= 30s || shouldFail) {
        PCSX::g_system->quit(1);
    }
    if (thread.joinable()) {
        thread.join();
    }
    ASSERT_FALSE(shouldFail.load()) << "Unexpected MSAN log encountered";
    ASSERT_EQ(exitCode.load(), 0);
}

TEST(MSAN, InterpreterValid) {
    ASSERT_NO_FATAL_FAILURE(execValidTest("-interpreter"));
}

TEST(MSAN, DynarecValid) {
    ASSERT_NO_FATAL_FAILURE(execValidTest("-dynarec"));
}

// ==== INVALID ====

inline static const uint8_t inspectMsanInitializedBitmap(const uint32_t address) {
    const uint32_t bitmapIndex = (address - PCSX::g_emulator->m_mem->c_msanStart) / 8;
    return PCSX::g_emulator->m_mem->m_msanInitializedBitmap[bitmapIndex];
}

static constexpr uint8_t SWX_EXPECTED_BITMASKS[36] = {
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

inline std::string rtrim(std::string s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), s.end());
    return s;
}

std::optional<std::string> nextMsanTest(const std::string& msg,
                                        std::atomic_uint* nextMsanCheckIndex) {
    if (!PCSX::g_system->running()) {
        return fmt::sprintf("[Test index: %d] Expected emulator to not have reached pause state yet", nextMsanCheckIndex->load());
    }
    const size_t allocCount = PCSX::g_emulator->m_mem->m_msanAllocs.size();
    if (allocCount != 1) {
        return fmt::sprintf("[Test index: %d] Expected 1 MSAN allocation, got %zu", nextMsanCheckIndex->load(), allocCount);
    }
    const uint32_t msanAllocAddr = PCSX::g_emulator->m_mem->m_msanAllocs.begin()->first + PCSX::Memory::c_msanStart;
    const std::string expectedMsg = fmt::sprintf("32-bit read from uninitialized bytes in usable, partially initialized msan memory: %8.8lx", msanAllocAddr);
    const std::string trimmedMsg = rtrim(msg);
    if (trimmedMsg != expectedMsg) {
        return fmt::sprintf("[Test index: %d] Invalid MSAN event logged, expected: \"%s\", got: \"%s\"", nextMsanCheckIndex->load(), expectedMsg, trimmedMsg);
    }
    const uint8_t expectedInitBitmap = SWX_EXPECTED_BITMASKS[nextMsanCheckIndex->load()];
    const uint8_t actualInitBitmap = inspectMsanInitializedBitmap(msanAllocAddr);
    if (expectedInitBitmap != actualInitBitmap) {
        return fmt::sprintf(
            "[Test index: %d] Initialized bitmap for address 0x%8.8lx mismatch: 0b%s != 0b%s",
            nextMsanCheckIndex->load(),
            msanAllocAddr,
            std::bitset<8>(expectedInitBitmap).to_string(),
            std::bitset<8>(actualInitBitmap).to_string()
        );
    }
    nextMsanCheckIndex->fetch_add(1);
    return std::nullopt;
}

void execInvalidTest(const char* type) {
    std::atomic_int exitCode(std::numeric_limits<int>::min());
    MainInvoker invoker("-no-ui", "-run", "-bios", "src/mips/openbios/openbios.bin", "-testmode", type,
                        "-luacov", "-loadexe", "src/mips/tests/msan-invalid/msan-invalid.ps-exe");
    std::thread thread([&](){
        exitCode.store(invoker.invoke());
    });
    while (invoker.isInStartup());
    std::atomic_bool resumeSystem = false;
    std::optional<std::string> result = std::nullopt;
    std::mutex resultMutex;
    std::atomic_uint nextMsanCheckIndex = 0;
    PCSX::EventBus::Listener listener(PCSX::g_system->m_eventBus);
    listener.listen<PCSX::Events::LogMessage>([&](const PCSX::Events::LogMessage& event) {
        if (PCSX::g_system->quitting() || !isMsanLog(event)) {
            return;
        }
        std::lock_guard<std::mutex> guard(resultMutex);
        result = nextMsanTest(event.message, &nextMsanCheckIndex);
        resumeSystem = !result.has_value();
    });
    std::chrono::milliseconds elapsed(0);
    PCSX::g_system->resume();
    while (elapsed < 30s
        && nextMsanCheckIndex <= std::size(SWX_EXPECTED_BITMASKS)
        && exitCode.load() == std::numeric_limits<int>::min()) {
        {
            std::lock_guard<std::mutex> guard(resultMutex);
            if (result.has_value()) {
                PCSX::g_system->quit(2);
                break;
            }
            // When an MSAN log is published, it will be handled
            // first before a pause is triggered. Thus we need to
            // wait until the pause is triggered and then ensure the
            // emulator continues. This must be differentiated from
            // the case where we haven't handled an MSAN log.
            if (resumeSystem) {
                std::chrono::milliseconds awaitPauseElapsed(0);
                while (awaitPauseElapsed < 5s && PCSX::g_system->running()) {
                    std::cout << "Awaiting pause" << std::endl;
                    std::this_thread::sleep_for(10ms);
                    awaitPauseElapsed += 10ms;
                }
                if (awaitPauseElapsed >= 5s) {
                    PCSX::g_system->quit(3);
                    break;
                }
                PCSX::g_system->resume();
                resumeSystem = false;
            }
        }
        std::this_thread::sleep_for(10ms);
        elapsed += 10ms;
    }
    if (elapsed >= 30s) {
        PCSX::g_system->quit(1);
    }
    if (thread.joinable()) {
        thread.join();
    }
    if (result.has_value()) {
        FAIL() << result.value();
    }
    ASSERT_EQ(exitCode.load(), 0);
}

TEST(MSAN, InterpreterInvalid) {
    ASSERT_NO_FATAL_FAILURE(execInvalidTest("-interpreter"));
}

TEST(MSAN, DynarecInvalid) {
    ASSERT_NO_FATAL_FAILURE(execInvalidTest("-dynarec"));
}
