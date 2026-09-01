#include "core/process/thread_table.hpp"

namespace slop::core::process {

uint64_t refresh_threads() {
    // TODO: enumerate threads via backend
    return 0;
}

std::shared_ptr<const thread_table_t> cached_threads() {
    return nullptr;
}

} // namespace slop::core::process
