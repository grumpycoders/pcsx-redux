/***************************************************************************
 *   Copyright (C) 2023 PCSX-Redux authors                                 *
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

/*
 * R3000A CPU functions.
 */

#include "core/r3000a.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <magic_enum/magic_enum_all.hpp>
#include <memory>
#include <thread>

#include "core/cdrom.h"
#include "core/debug.h"
#include "core/gpu.h"
#include "core/gte.h"
#include "core/mdec.h"
#include "core/pgxp_mem.h"
#include "core/sio.h"
#include "core/sio1.h"
#include "core/spu.h"
#include "fmt/format.h"
#include "support/uvfile.h"
#include "supportpsx/memory.h"

int PCSX::R3000Acpu::psxInit() {
    g_system->printf(_("PCSX-Redux booting\n"));
    g_system->printf(_("Copyright (C) 2019-%i PCSX-Redux authors\n"), 2025);
    const auto& args = g_system->getArgs();

    if (g_emulator->settings.get<Emulator::SettingDynarec>()) {
        g_emulator->m_cpu = Cpus::DynaRec();
    }

    if (!g_emulator->m_cpu) g_emulator->m_cpu = Cpus::Interpreted();

    PGXP_Init();
    g_system->printf(_("CPU type: %s\n"), g_emulator->m_cpu->getName().c_str());

    return g_emulator->m_cpu->Init();
}

void PCSX::R3000Acpu::psxReset() {
    Reset();

    memset(&m_regs, 0, sizeof(m_regs));
    m_shellStarted = false;
    m_inISR = false;
    m_delayedLoadInfo[0].active = false;
    m_delayedLoadInfo[1].active = false;
    m_currentDelayedLoad = false;
    closeAllPCdrvFiles();

    setPC(0xbfc00000);  // Start in bootstrap

    g_emulator->m_debug->updatedPC(0xbfc00000);

    m_regs.CP0.r[12] = 0x10900000;  // COP0 enabled | BEV = 1 | TS = 1
    m_regs.CP0.r[15] = 0x00000002;  // PRevID = Revision ID, same as R3000A

    PCSX::g_emulator->m_hw->reset();
}

namespace {

// How long PCopen("tcp://...") waits for the connection before giving up.
constexpr auto c_pcdrvConnectTimeout = std::chrono::seconds(5);

// Lets the PCdrv code queue work on the UV thread, so that a socket is only ever
// freed there, after its uv_close: a read callback can't then land on a dead object.
struct PCdrvUvAccess : public PCSX::UvFifo {
    using PCSX::UvThreadOp::request;
};

bool startsWith(std::string_view str, std::string_view prefix) { return str.substr(0, prefix.size()) == prefix; }

bool isSchemeChar(char c) {
    return isalnum(static_cast<unsigned char>(c)) || (std::string_view("+-.").find(c) != std::string_view::npos);
}

// "xxx://" at the start of the name, with xxx made of URI scheme characters.
bool hasScheme(std::string_view name) {
    auto pos = name.find("://");
    if ((pos == std::string_view::npos) || (pos == 0)) return false;
    auto scheme = name.substr(0, pos);
    return std::all_of(scheme.begin(), scheme.end(), isSchemeChar);
}

// Names that PCdrv never turns into file paths.
bool isPCdrvNetName(std::string_view name) { return startsWith(name, "probe:") || hasScheme(name); }

std::string_view trim(std::string_view str) {
    while (!str.empty() && isspace(static_cast<unsigned char>(str.front()))) str.remove_prefix(1);
    while (!str.empty() && isspace(static_cast<unsigned char>(str.back()))) str.remove_suffix(1);
    return str;
}

bool pcdrvNetAllowed(std::string_view allowList, std::string_view hostPort) {
    if (allowList.empty()) return true;
    while (!allowList.empty()) {
        auto comma = allowList.find(',');
        if (trim(allowList.substr(0, comma)) == hostPort) return true;
        if (comma == std::string_view::npos) break;
        allowList.remove_prefix(comma + 1);
    }
    return false;
}

bool isDigit(char c) { return (c >= '0') && (c <= '9'); }

// Splits "host:port", with port a decimal number in 1-65535.
bool parseHostPort(std::string_view hostPort, std::string& host, unsigned& port) {
    auto colon = hostPort.rfind(':');
    if ((colon == std::string_view::npos) || (colon == 0)) return false;
    auto portStr = hostPort.substr(colon + 1);
    if (portStr.empty() || (portStr.size() > 5)) return false;
    if (!std::all_of(portStr.begin(), portStr.end(), isDigit)) return false;
    port = 0;
    for (auto c : portStr) port = port * 10 + (c - '0');
    if ((port == 0) || (port > 65535)) return false;
    host = hostPort.substr(0, colon);
    return true;
}

// A name resolution running on the UV thread. Shared between the emulator thread and the
// uv_getaddrinfo callback, so a callback landing after the deadline touches nothing freed.
struct PCdrvResolve {
    enum { Pending, Done, Failed };
    std::atomic<int> state = Pending;
    char address[64] = {};
    // Only ever touched on the UV thread.
    uv_getaddrinfo_t req = {};
    bool active = false;
};

void pcdrvResolved(uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
    auto holder = reinterpret_cast<std::shared_ptr<PCdrvResolve>*>(req->data);
    auto resolve = *holder;
    delete holder;
    resolve->active = false;
    bool ok = false;
    if ((status == 0) && res) {
        ok = uv_ip4_name(reinterpret_cast<const struct sockaddr_in*>(res->ai_addr), resolve->address,
                         sizeof(resolve->address)) == 0;
    }
    if (res) uv_freeaddrinfo(res);
    resolve->state.store(ok ? PCdrvResolve::Done : PCdrvResolve::Failed, std::memory_order_release);
}

// Runs on the UV thread.
void pcdrvStartResolve(uv_loop_t* loop, const std::shared_ptr<PCdrvResolve>& resolve, const std::string& host) {
    struct addrinfo hints = {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    // The request holds its own reference until its callback runs, cancelled or not.
    resolve->req.data = new std::shared_ptr<PCdrvResolve>(resolve);
    int r = uv_getaddrinfo(loop, &resolve->req, pcdrvResolved, host.c_str(), nullptr, &hints);
    if (r != 0) {
        delete reinterpret_cast<std::shared_ptr<PCdrvResolve>*>(resolve->req.data);
        resolve->state.store(PCdrvResolve::Failed, std::memory_order_release);
        return;
    }
    resolve->active = true;
}

// Resolves host to an IPv4 literal, since UvFifo only takes those. Empty on failure or past the deadline.
std::string pcdrvResolve(const std::string& host, std::chrono::steady_clock::time_point deadline) {
    auto resolve = std::make_shared<PCdrvResolve>();
    PCdrvUvAccess::request([resolve, host](uv_loop_t* loop) { pcdrvStartResolve(loop, resolve, host); });
    while ((resolve->state.load(std::memory_order_acquire) == PCdrvResolve::Pending) &&
           (std::chrono::steady_clock::now() < deadline)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    auto state = resolve->state.load(std::memory_order_acquire);
    if (state == PCdrvResolve::Pending) {
        // Too slow. Cancelling may come too late; the shared state covers that.
        PCdrvUvAccess::request([resolve](uv_loop_t*) {
            if (resolve->active) uv_cancel(reinterpret_cast<uv_req_t*>(&resolve->req));
        });
        return {};
    }
    if (state != PCdrvResolve::Done) return {};
    return resolve->address;
}

PCSX::IO<PCSX::File> pcdrvConnectTo(const std::string& address, unsigned port,
                                    std::chrono::steady_clock::time_point deadline) {
    PCSX::IO<PCSX::UvFifo> fifo(new PCSX::UvFifo(address, port));
    auto connecting = [&fifo]() { return fifo->isConnecting() && !fifo->failed(); };
    while (connecting() && (std::chrono::steady_clock::now() < deadline)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (fifo->isConnecting() || fifo->failed()) {
        fifo->close();
        PCdrvUvAccess::request([fifo](uv_loop_t*) {});
        return {};
    }
    return fifo;
}

// Connects "host:port" and returns the stream, or an empty handle on any failure or after
// c_pcdrvConnectTimeout, which covers both the name resolution and the connection. Both
// happen on the UV thread; this thread only polls their state.
PCSX::IO<PCSX::File> pcdrvConnect(std::string_view hostPort) {
    auto deadline = std::chrono::steady_clock::now() + c_pcdrvConnectTimeout;
    std::string host;
    unsigned port;
    if (!parseHostPort(hostPort, host, port)) return {};
    auto address = pcdrvResolve(host, deadline);
    if (address.empty()) return {};
    return pcdrvConnectTo(address, port, deadline);
}

// The stream behind a network name: empty when networking is off, the name is unknown, or
// the host is not allowed. Sets probe for probe:net, which is an empty stream.
PCSX::IO<PCSX::File> pcdrvNetStream(std::string_view filename, bool& probe) {
    auto& debugSettings = PCSX::g_emulator->settings.get<PCSX::Emulator::SettingDebugSettings>();
    probe = false;
    if (!debugSettings.get<PCSX::Emulator::DebugSettings::PCdrvNet>()) return {};
    if (filename == "probe:net") {
        static uint8_t empty;
        probe = true;
        return PCSX::IO<PCSX::File>(new PCSX::BufferFile(&empty, 0));
    }
    if (!startsWith(filename, "tcp://")) return {};
    filename.remove_prefix(6);
    if (!pcdrvNetAllowed(debugSettings.get<PCSX::Emulator::DebugSettings::PCdrvNetAllow>().value, filename)) return {};
    return pcdrvConnect(filename);
}

}  // namespace

PCSX::R3000Acpu::PCdrvFile::~PCdrvFile() {
    if (m_kind != Kind::Socket) return;
    // Close now, but drop the last reference on the UV thread, once the uv_close is queued there.
    IO<File> keep(*static_cast<IO<File>*>(this));
    keep->close();
    PCdrvUvAccess::request([keep](uv_loop_t*) {});
}

void PCSX::R3000Acpu::pcdrvOpenNet(const std::string& filename) {
    auto& regs = m_regs.GPR.n;
    bool probe;
    IO<File> stream = pcdrvNetStream(filename, probe);
    if (!stream) {
        regs.v0 = -1;
        regs.v1 = -1;
        return;
    }
    uint16_t fd = m_availableFDs.front();
    m_availableFDs.pop_front();
    auto kind = probe ? PCdrvFile::Kind::Probe : PCdrvFile::Kind::Socket;
    auto file = m_pcdrvFiles.insert(fd, new PCdrvFile(std::move(stream), kind));
    file->m_relativeFilename = filename;
    regs.v0 = 0;
    regs.v1 = fd;
}

// Never blocks: whatever has arrived, up to a2 bytes; 0 if nothing yet. The probe reads nothing.
void PCSX::R3000Acpu::pcdrvReadNet(PCdrvFile& filei, IO<File>& memFile) {
    auto& regs = m_regs.GPR.n;
    regs.v0 = 0;
    regs.v1 = 0;
    if (filei.m_kind == PCdrvFile::Kind::Probe) return;
    IO<File> file = filei;
    if (file->failed() || file->eof()) {
        regs.v0 = -1;
        regs.v1 = -1;
        return;
    }
    size_t available = std::min(static_cast<size_t>(regs.a2), file->size());
    if (!available) return;
    auto slice = file->read(available);
    regs.v1 = slice.size();
    if (slice.size()) memFile->writeAt(std::move(slice), regs.a3);
}

void PCSX::R3000Acpu::psxShutdown() { Shutdown(); }

bool PCSX::R3000Acpu::exception(uint32_t code, bool bd, bool cop0) {
    auto& emuSettings = g_emulator->settings;
    auto& debugSettings = emuSettings.get<Emulator::SettingDebugSettings>();
    unsigned ec = (code >> 2) & 0x1f;
    auto e = magic_enum::enum_cast<Exception>(ec);
    if (e.has_value()) {
        if (!cop0 && debugSettings.get<Emulator::DebugSettings::PCdrv>() && (e.value() == Exception::Break)) {
            IO<File> memFile = g_emulator->m_mem->getMemoryAsFile();
            uint32_t code = (memFile->readAt<uint32_t>(m_regs.pc) >> 6) & 0xfffff;
            auto& regs = m_regs.GPR.n;
            uint16_t fd = 0;
            m_currentDelayedLoad ^= 1;
            flushCurrentDelayedLoad();
            m_currentDelayedLoad ^= 1;
            flushCurrentDelayedLoad();
            switch (code) {
                case 0x101: {  // PCinit
                    closeAllPCdrvFiles();
                    regs.v0 = 0;
                    regs.v1 = 0;
                    m_regs.pc.increment();
                    return false;
                }
                case 0x102: {  // PCcreat
                    if (m_availableFDs.empty()) {
                        regs.v0 = -1;
                        regs.v1 = -1;
                        m_regs.pc.increment();
                        return false;
                    }
                    memFile->rSeek(m_regs.GPR.n.a0);
                    auto filename = memFile->gets<false>();
                    if (isPCdrvNetName(filename)) {
                        regs.v0 = -1;
                        regs.v1 = -1;
                        m_regs.pc.increment();
                        return false;
                    }
                    std::filesystem::path basepath = debugSettings.get<Emulator::DebugSettings::PCdrvBase>();
                    fd = m_availableFDs.front();
                    auto file = m_pcdrvFiles.insert(fd, new PCdrvFile(basepath / filename, FileOps::TRUNCATE));
                    file->m_relativeFilename = filename;
                    if ((*file)->failed()) {
                        regs.v0 = -1;
                        regs.v1 = -1;
                        delete &*file;
                    } else {
                        m_availableFDs.pop_front();
                        regs.v0 = 0;
                        regs.v1 = fd;
                    }
                    m_regs.pc.increment();
                    return false;
                }
                case 0x103: {  // PCopen
                    if (m_availableFDs.empty()) {
                        regs.v0 = -1;
                        regs.v1 = -1;
                        m_regs.pc.increment();
                        return false;
                    }
                    memFile->rSeek(m_regs.GPR.n.a0);
                    auto filename = memFile->gets<false>();
                    if (isPCdrvNetName(filename)) {
                        // Network names never become file paths.
                        pcdrvOpenNet(filename);
                        m_regs.pc.increment();
                        return false;
                    }
                    std::filesystem::path basepath = debugSettings.get<Emulator::DebugSettings::PCdrvBase>();
                    PCdrvFiles::iterator file;
                    auto path = basepath / filename;
                    fd = m_availableFDs.front();
                    if (regs.a2 == 0) {
                        file = m_pcdrvFiles.insert(fd, new PCdrvFile(path));
                    } else {
                        file = m_pcdrvFiles.insert(fd, new PCdrvFile(path, FileOps::READWRITE));
                    }
                    file->m_relativeFilename = filename;
                    if ((*file)->failed()) {
                        regs.v0 = -1;
                        regs.v1 = -1;
                        delete &*file;
                    } else {
                        m_availableFDs.pop_front();
                        regs.v0 = 0;
                        regs.v1 = fd;
                    }
                    m_regs.pc.increment();
                    return false;
                }
                case 0x104: {  // PCclose
                    fd = m_regs.GPR.n.a0;
                    auto file = m_pcdrvFiles.find(fd);
                    if (file == m_pcdrvFiles.end()) {
                        regs.v0 = -1;
                        regs.v1 = -1;
                    } else {
                        (*file)->close();
                        regs.v0 = 0;
                        regs.v1 = 0;
                        delete &*file;
                        m_availableFDs.push_back(fd);
                    }
                    m_regs.pc.increment();
                    return false;
                }
                case 0x105: {  // PCread
                    auto filei = m_pcdrvFiles.find(m_regs.GPR.n.a1);
                    if (filei == m_pcdrvFiles.end()) {
                        regs.v0 = -1;
                        regs.v1 = -1;
                        m_regs.pc.increment();
                        return false;
                    }
                    if (filei->m_kind != PCdrvFile::Kind::File) {
                        pcdrvReadNet(*filei, memFile);
                        m_regs.pc.increment();
                        return false;
                    }
                    IO<File> file = *filei;
                    if (file->failed() || file->eof()) {
                        regs.v0 = -1;
                        regs.v1 = -1;
                        m_regs.pc.increment();
                        return false;
                    }
                    auto slice = file->read(regs.a2);
                    regs.v0 = 0;
                    regs.v1 = slice.size();
                    memFile->writeAt(std::move(slice), regs.a3);
                    m_regs.pc.increment();
                    return false;
                }
                case 0x106: {  // PCwrite
                    auto filei = m_pcdrvFiles.find(m_regs.GPR.n.a1);
                    if (filei == m_pcdrvFiles.end()) {
                        regs.v0 = -1;
                        regs.v1 = -1;
                        m_regs.pc.increment();
                        return false;
                    }
                    IO<File> file = *filei;
                    if (filei->refusesWrite()) {
                        regs.v0 = -1;
                        regs.v1 = -1;
                        m_regs.pc.increment();
                        return false;
                    }
                    auto slice = memFile->readAt(regs.a2, regs.a3);
                    if ((regs.v1 = file->write(slice.data(), slice.size())) < 0) {
                        regs.v0 = -1;
                    } else {
                        regs.v0 = 0;
                    }
                    m_regs.pc.increment();
                    return false;
                }
                case 0x107: {  // PClseek
                    auto filei = m_pcdrvFiles.find(m_regs.GPR.n.a0);
                    if (filei == m_pcdrvFiles.end()) {
                        regs.v0 = -1;
                        regs.v1 = -1;
                        m_regs.pc.increment();
                        return false;
                    }
                    if (filei->m_kind != PCdrvFile::Kind::File) {
                        regs.v0 = -1;
                        regs.v1 = -1;
                        m_regs.pc.increment();
                        return false;
                    }
                    IO<File> file = *filei;
                    int wheel;
                    switch (regs.a3) {
                        case 0:
                            wheel = SEEK_SET;
                            break;
                        case 1:
                            wheel = SEEK_CUR;
                            break;
                        case 2:
                            wheel = SEEK_END;
                            break;
                        default:
                            regs.v0 = -1;
                            regs.v1 = -1;
                            m_regs.pc.increment();
                            return false;
                    }
                    ssize_t ret = file->rSeek(regs.a2, wheel);
                    if (ret < 0) {
                        regs.v0 = -1;
                        regs.v1 = ret;
                        m_regs.pc.increment();
                        return false;
                    }
                    if (file->writable()) {
                        file->wSeek(regs.a2, wheel);
                    }

                    if (ret >= 0) {
                        regs.v0 = 0;
                        regs.v1 = file->rTell();
                    } else {
                        regs.v0 = -1;
                        regs.v1 = ret;
                    }
                    m_regs.pc.increment();
                    return false;
                }
                default:
                    break;
            }
        }
        ec = 1 << ec;
        if (!g_system->getArgs().isTestModeEnabled() &&
            ((debugSettings.get<Emulator::DebugSettings::FirstChanceException>() & ec) != 0)) {
            auto name = magic_enum::enum_name(e.value());
            g_system->printf(fmt::format("First chance exception: {} from 0x{:08x}\n", name, m_regs.pc).c_str());
            g_system->pause(true);
        }
    }

    m_inISR = true;

    // Set the EPC & PC
    if (bd) {
        code |= 0x80000000;
        m_regs.CP0.n.EPC = m_regs.pc - 4;
    } else {
        m_regs.CP0.n.EPC = m_regs.pc;
    }

    if (m_regs.CP0.n.Status & 0x400000) {
        m_regs.pc.raw() = 0xbfc00180;
    } else {
        m_regs.pc.raw() = 0x80000080;
    }

    if (cop0) m_regs.pc.raw() -= 0x40;

    // Set the Cause
    m_regs.CP0.n.Cause = code;
    // Set the Status
    m_regs.CP0.n.Status = (m_regs.CP0.n.Status & ~0x3f) | ((m_regs.CP0.n.Status & 0xf) << 2);
    return true;
}

void PCSX::R3000Acpu::restorePCdrvFile(const std::filesystem::path& filename, uint16_t fd, bool writable,
                                       ssize_t readPosition, ssize_t writePosition) {
    auto& emuSettings = g_emulator->settings;
    auto& debugSettings = emuSettings.get<Emulator::SettingDebugSettings>();
    std::filesystem::path basepath = debugSettings.get<Emulator::DebugSettings::PCdrvBase>();
    auto path = basepath / filename;
    PCdrvFile* file;
    if (writable) {
        // Neither truncate nor append: the guest's writes go where its write position says.
        file = new PCdrvFile(path, FileOps::READWRITE);
        if ((*file)->failed()) {
            delete file;
            // Only recreate a file that is gone: one that merely failed to open keeps its contents.
            std::error_code ec;
            if (std::filesystem::exists(path, ec) || ec) return;
            file = new PCdrvFile(path, FileOps::TRUNCATE);
        }
    } else {
        file = new PCdrvFile(path);
    }
    if ((*file)->failed()) {
        delete file;
        return;
    }
    file->m_relativeFilename = filename.string();
    if (readPosition < 0) {
        (*file)->rSeek(0, SEEK_END);
    } else {
        (*file)->rSeek(readPosition, SEEK_SET);
    }
    if (writable) {
        if (writePosition < 0) {
            (*file)->wSeek(0, SEEK_END);
        } else {
            (*file)->wSeek(writePosition, SEEK_SET);
        }
    }
    m_pcdrvFiles.insert(fd, file);
    for (auto f = m_availableFDs.begin(); f != m_availableFDs.end(); f++) {
        if (*f == fd) {
            m_availableFDs.erase(f);
            break;
        }
    }
}

void PCSX::R3000Acpu::branchTest() {
    branchTestEvents();
    // Last, so that a snapshot taken at a vsync doesn't leave the scheduled callbacks and the
    // interrupt check of this branchTest() for whoever restores it: Execute() starts by
    // running an instruction, and they'd wait until the next branch.
    g_emulator->flushRewindCapture();
}

void PCSX::R3000Acpu::branchTestEvents() {
    const uint64_t cycle = m_regs.cycle;

    if (cycle >= g_emulator->m_counters->m_psxNextCounter) g_emulator->m_counters->update();
    g_emulator->dispatchVSync();

    if (m_regs.spuInterrupt.exchange(false)) g_emulator->m_spu->interrupt();

    const uint32_t scheduleMask = m_regs.scheduleMask;

    int32_t lowestDistance = std::numeric_limits<int64_t>::max();
    uint64_t lowestTarget = cycle;
    uint64_t* targets = m_regs.scheduleTargets;

    if ((scheduleMask != 0) && (m_regs.lowestTarget < cycle)) {
#define checkAndUpdate(irq_, act)                                     \
    {                                                                 \
        constexpr unsigned irq = static_cast<unsigned>(irq_);         \
        constexpr uint32_t mask = 1 << irq;                           \
        if ((scheduleMask & mask) != 0) {                             \
            uint64_t target = targets[irq];                           \
            int64_t dist = target - cycle;                            \
            if (dist > 0) {                                           \
                if (lowestDistance > dist) {                          \
                    lowestDistance = dist;                            \
                    lowestTarget = target;                            \
                }                                                     \
            } else {                                                  \
                m_regs.scheduleMask &= ~mask;                         \
                PSXIRQ_LOG("Calling scheduled callback %08x\n", irq); \
                act();                                                \
            }                                                         \
        }                                                             \
    }
        checkAndUpdate(Schedule::SIO, g_emulator->m_sio->scheduledCallback);
        checkAndUpdate(Schedule::SIO1, g_emulator->m_sio1->scheduledCallback);
        checkAndUpdate(Schedule::CDRFIFO, g_emulator->m_cdrom->fifoScheduledCallback);
        checkAndUpdate(Schedule::CDRCOMMANDS, g_emulator->m_cdrom->commandsScheduledCallback);
        checkAndUpdate(Schedule::CDREAD, g_emulator->m_cdrom->readScheduledCallback);
        checkAndUpdate(Schedule::GPUDMA, GPU::gpuInterrupt);
        checkAndUpdate(Schedule::MDECOUTDMA, g_emulator->m_mdec->scheduledCallback1);
        checkAndUpdate(Schedule::SPUDMA, spuInterrupt);
        checkAndUpdate(Schedule::MDECINDMA, g_emulator->m_mdec->scheduledCallback0);
        checkAndUpdate(Schedule::GPUOTCDMA, gpuotcInterrupt);
        checkAndUpdate(Schedule::CDRDMA, g_emulator->m_cdrom->scheduledDmaCallback);
        m_regs.lowestTarget = lowestTarget;
    }
    auto& mem = g_emulator->m_mem;
    auto istat = mem->readHardwareRegister<Memory::ISTAT>();
    auto imask = mem->readHardwareRegister<Memory::IMASK>();
    if ((istat & imask) && ((m_regs.CP0.n.Status & 0x401) == 0x401)) {
        // If the next instruction is a GTE instruction sans LWC2/SWC2, there's a hardware bug where the instruction
        // gets executed
        // But EPC still ends up pointing to the GTE instruction. In this case, the BIOS will add 4 to EPC to skip
        // the GTE instruction. To deal with this, we do not fire IRQs if the next instruction is a GTE instruction
        // https://psx-spx.consoledev.net/cpuspecifications/#interrupts-vs-gte-commands
        uint32_t next = mem->read32(m_regs.pc, Memory::ReadType::Instr);
        if (((next >> 24) & 0xfe) == 0x4a) {  // Return if it's a GTE instruction
            return;
        }

        PSXIRQ_LOG("Interrupt: %x %x\n", istat, imask);
        // A branch in the delay slot of a taken branch leaves its own jump pending here, and the next
        // instruction is that branch's delay slot. The interrupt is taken on that delay slot: EPC is the
        // branch with BD set, and the pending jump is dropped, since returning runs the branch again.
        for (auto& pending : m_delayedLoadInfo) {
            if (!pending.pcActive) continue;
            pending.pcActive = false;
            pending.fromLink = false;
            m_nextIsDelaySlot = false;
            m_regs.pc.raw() = pending.branchPC + 4;
            exception(0x400, true);
            return;
        }
        exception(0x400, 0);
    }
}

void PCSX::R3000Acpu::psxSetPGXPMode(uint32_t pgxpMode) {
    SetPGXPMode(pgxpMode);
    // g_emulator->m_cpu->Reset();
}

std::unique_ptr<PCSX::R3000Acpu> PCSX::Cpus::Interpreted() {
    std::unique_ptr<PCSX::R3000Acpu> cpu = getInterpreted();
    if (cpu->Implemented()) return cpu;
    return nullptr;
}

std::unique_ptr<PCSX::R3000Acpu> PCSX::Cpus::DynaRec() {
    std::unique_ptr<PCSX::R3000Acpu> cpu = getDynaRec();
    // An architecture with no dynarec at all returns nullptr here, which is not
    // the same as one whose dynarec reports itself unimplemented.
    if (cpu && cpu->Implemented()) return cpu;
    return nullptr;
}

void PCSX::R3000Acpu::processA0KernelCall(uint32_t call) {
    auto& r = m_regs.GPR.n;

    switch (call) {
        case 0x03: {  // write
            if (r.a0 != 1) break;
            IO<File> memFile = g_emulator->m_mem->getMemoryAsFile();
            uint32_t size = r.a2;
            r.v0 = size;
            memFile->rSeek(r.a1);
            while (size--) {
                g_system->biosPutc(memFile->getc());
            }
            break;
        }
        case 0x09: {  // putc
            g_system->biosPutc(r.a0);
            break;
        }
        case 0x3c: {  // putchar
            g_system->biosPutc(r.a0);
            break;
        }
        case 0x3e: {  // puts
            IO<File> memFile = g_emulator->m_mem->getMemoryAsFile();
            memFile->rSeek(r.a0);
            auto str = memFile->gets<false>();
            for (auto c : str) {
                g_system->biosPutc(c);
            }
            break;
        }
    }
}

void PCSX::R3000Acpu::processB0KernelCall(uint32_t call) {
    auto& r = m_regs.GPR.n;

    switch (call) {
        case 0x35: {  // write
            if (r.a0 != 1) break;
            IO<File> memFile = g_emulator->m_mem->getMemoryAsFile();
            uint32_t size = r.a2;
            r.v0 = size;
            memFile->rSeek(r.a1);
            while (size--) {
                g_system->biosPutc(memFile->getc());
            }
            break;
        }
        case 0x3b: {  // putc
            g_system->biosPutc(r.a0);
            break;
        }
        case 0x3d: {  // putchar
            g_system->biosPutc(r.a0);
            break;
        }
        case 0x3f: {  // puts
            IO<File> memFile = g_emulator->m_mem->getMemoryAsFile();
            memFile->rSeek(r.a0);
            auto str = memFile->gets<false>();
            for (auto c : str) {
                g_system->biosPutc(c);
            }
            break;
        }
    }
}

std::pair<const uint32_t, std::string>* PCSX::R3000Acpu::findContainingSymbol(uint32_t addr) {
    auto symBefore = m_symbols.upper_bound(addr);
    if (symBefore != m_symbols.begin()) {  // verify there is actually a symbol before addr
        symBefore--;
        if (symBefore->first != addr) {
            PCSX::PSXAddress addrInfo(addr);
            PCSX::PSXAddress symbolInfo(symBefore->first);
            if (addrInfo.segment != symbolInfo.segment) {
                // if the symbol is different and not in the same memory region, it'd be wrong
                return nullptr;
            }
        }
        return &*symBefore;
    }
    return nullptr;
}

std::string* PCSX::R3000Acpu::getSymbolAt(uint32_t addr) {
    auto symBefore = m_symbols.find(addr);
    if (symBefore != m_symbols.end()) {
        return &symBefore->second;
    }
    return nullptr;
}
