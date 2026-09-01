#include "core/process/handle_table.hpp"

namespace slop::core::process {

uint64_t refresh_handles() {
    // TODO: enumerate handles via backend (NtQuerySystemInformation)
    return 0;
}

std::shared_ptr<const handle_table_t> cached_handles() {
    return nullptr;
}

} // namespace slop::core::process
