#include "core/runtime/session.hpp"
#include "core/runtime/backend_registry.hpp"

namespace slop::core::runtime {

session_t::~session_t() {
    close();
}

session_t::session_t(session_t&& other) noexcept
    : m_handle(other.m_handle)
    , m_info(std::move(other.m_info))
    , m_epoch_ms(other.m_epoch_ms)
{
    other.m_handle = {};
    other.m_epoch_ms = 0;
}

session_t& session_t::operator=(session_t&& other) noexcept {
    if (this != &other) {
        close();
        m_handle   = other.m_handle;
        m_info     = std::move(other.m_info);
        m_epoch_ms = other.m_epoch_ms;
        other.m_handle   = {};
        other.m_epoch_ms = 0;
    }
    return *this;
}

bool session_t::open(uint32_t pid) {
    close();
    m_handle = active().attach(pid);
    if (!m_handle.valid()) return false;
    m_info.pid = pid;
    if (auto procs = active().enum_processes(); procs.ok) {
        for (const auto& p : procs.items) {
            if (p.pid == pid) { m_info = p; break; }
        }
        m_info.pid = pid;
    }
    m_epoch_ms = 0; // TODO: use steady_ms()
    return true;
}

void session_t::close() {
    if (m_handle.valid()) {
        active().detach(m_handle);
    }
    m_handle = {};
    m_info   = {};
    m_epoch_ms = 0;
}

bool session_t::valid() const noexcept {
    return m_handle.valid();
}

uint32_t session_t::pid() const noexcept {
    return m_info.pid;
}

const std::string& session_t::name() const noexcept {
    return m_info.name;
}

arch_t session_t::arch() const noexcept {
    return m_info.arch;
}

int64_t session_t::epoch_ms() const noexcept {
    return m_epoch_ms;
}

io_result_t session_t::read(uintptr_t addr, void* buf, size_t len) {
    return active().read_memory(m_handle, addr, buf, len);
}

io_result_t session_t::write(uintptr_t addr, const void* buf, size_t len) {
    return active().write_memory(m_handle, addr, buf, len);
}

const target_handle_t& session_t::handle() const noexcept {
    return m_handle;
}

} // namespace slop::core::runtime
