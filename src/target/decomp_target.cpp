#include <cstdint>

#if defined(_MSC_VER)
#define DECOMP_EXPORT extern "C" __declspec(dllexport) __declspec(noinline)
#else
#define DECOMP_EXPORT extern "C" __attribute__((visibility("default"), noinline))
#endif

struct Fixture {
    int x;
    int y;
};

DECOMP_EXPORT int branch_signed(int a, int b) {
    return a < b ? a - b : a + b;
}

DECOMP_EXPORT unsigned branch_unsigned(unsigned a, unsigned b) {
    return a <= b ? b - a : a - b;
}

DECOMP_EXPORT int loop_sum(const int* values, int count) {
    int total = 0;
    for (int i = 0; i < count; ++i)
        total += values[i];
    return total;
}

DECOMP_EXPORT int sparse_switch(int value) {
    switch (value) {
    case -7: return 11;
    case 3: return 22;
    case 41: return 33;
    case 900: return 44;
    default: return -1;
    }
}

DECOMP_EXPORT std::uint32_t rotate_mix(std::uint32_t value, unsigned count) {
    count &= 31;
    const std::uint32_t rotated = count ? (value << count) | (value >> (32 - count)) : value;
    return rotated ^ 0x9E3779B9u;
}

DECOMP_EXPORT int call_leaf(int value) {
    return value * 3 + 1;
}

DECOMP_EXPORT int call_chain(int value) {
    return call_leaf(value) + 5;
}

DECOMP_EXPORT int indirect_call(int (*fn)(int), int value) {
    return fn(value);
}

DECOMP_EXPORT int stack_alias(int* value) {
    const int before = *value;
    *value = before + 7;
    return before;
}

DECOMP_EXPORT int struct_fields(const Fixture* value) {
    return value->x * 2 + value->y;
}

int main() {
    Fixture fixture{2, 3};
    int value = 5;
    const int numbers[]{1, 2, 3};
    return branch_signed(1, 2) + static_cast<int>(branch_unsigned(2, 1)) +
           loop_sum(numbers, 3) + sparse_switch(41) + static_cast<int>(rotate_mix(1, 3)) +
           call_chain(2) + indirect_call(call_leaf, 2) + stack_alias(&value) + struct_fields(&fixture);
}
