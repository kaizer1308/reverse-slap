#pragma once

// src/target/mutator.hpp
// Produce one of every change_type_t in a single pass for snapshot diff testing

namespace slop_target {

void mutator_init();
void mutator_mutate();   // Execute one mutation pass

} // namespace slop_target
