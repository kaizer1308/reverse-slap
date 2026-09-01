#pragma once

// src/target/report.hpp
// Write JSON address report to %TEMP%\sloptarget-<pid>.json for verification

namespace slop_target {

void report_print();   // Print addresses to stdout
void report_json();    // Write JSON file to %TEMP%

} // namespace slop_target
