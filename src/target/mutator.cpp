#include "mutator.hpp"
#include "known_values.hpp"

#include <cstring>

namespace slop_target {

// Stable block for diff testing. Each field exercises a different change_type_t
static struct {
    int32_t  counter_inc   = 100;    // counter_incremented
    int32_t  counter_dec   = 100;    // counter_decremented
    float    float_val     = 1.0f;   // float_changed
    void*    ptr_val       = nullptr; // pointer_changed
    char     string_val[16] = "hello"; // string_modified
    uint8_t  zero_block[8] = {1,2,3,4,5,6,7,8}; // zeroed_out
    uint8_t  flip_byte     = 0xAA;   // byte_flip
} g_mutator_data;

void mutator_init() {
    g_mutator_data.ptr_val = &g_values;
}

void mutator_mutate() {
    // counter_incremented
    ++g_mutator_data.counter_inc;

    // counter_decremented
    --g_mutator_data.counter_dec;

    // float_changed
    g_mutator_data.float_val += 0.5f;

    // pointer_changed, point somewhere else
    g_mutator_data.ptr_val = (g_mutator_data.ptr_val == &g_values)
        ? static_cast<void*>(&g_mutator_data)
        : static_cast<void*>(&g_values);

    // string_modified
    if (g_mutator_data.string_val[0] == 'h')
        std::strcpy(g_mutator_data.string_val, "world");
    else
        std::strcpy(g_mutator_data.string_val, "hello");

    // zeroed_out
    std::memset(g_mutator_data.zero_block, 0, sizeof(g_mutator_data.zero_block));

    // byte_flip
    g_mutator_data.flip_byte = static_cast<uint8_t>(~g_mutator_data.flip_byte);
}

} // namespace slop_target
