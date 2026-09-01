#include "core/process/process_list.hpp"

namespace slop::core::process {

uint64_t refresh_processes(bool /*resolve_details*/) {
    // TODO: submit job via infra::jobs to enumerate processes
    return 0;
}

std::shared_ptr<const process_list_t> cached_processes() {
    // TODO: return atomically-published snapshot
    return nullptr;
}

} // namespace slop::core::process
