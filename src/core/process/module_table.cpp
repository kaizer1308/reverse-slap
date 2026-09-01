#include "core/process/module_table.hpp"

namespace slop::core::process {

uint64_t refresh_modules() {
    // TODO: enumerate modules via backend
    return 0;
}

std::shared_ptr<const module_table_t> cached_modules() {
    return nullptr;
}

const runtime::module_info_t* va_to_module(uintptr_t /*va*/) {
    // TODO: binary search cached module ranges
    return nullptr;
}

} // namespace slop::core::process
