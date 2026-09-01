#pragma once

// src/core/infra/app_control.hpp
// the way a front end asks the app to quit, the shell polls this and does its own teardown

#include <string>

namespace slop::core::infra::app_control {

// first reason in wins
void request_quit(std::string reason);

bool quit_requested() noexcept;

std::string quit_reason();

// Test support
void reset();

} // namespace slop::core::infra::app_control
