#include "harness.hpp"
#include "core/infra/lifecycle.hpp"
#include "../../driver/slopdrvr/src/function/NetworkStartup.h"

TEST_CASE(autoload_defaults_to_loading_kernel_bridge) {
    REQUIRE(slop::core::infra::lifecycle::config_t{}.load_driver);
}

TEST_CASE(autoload_wfp_collision_does_not_abort_kernel_bridge) {
    REQUIRE(!net_capture::startup_is_fatal(0u));
    REQUIRE(!net_capture::startup_is_fatal(0x40000000u));
    REQUIRE(!net_capture::startup_is_fatal(0xC0220009u));
    REQUIRE(net_capture::startup_is_fatal(0xC000009Au)); // insufficient resources
    REQUIRE(net_capture::startup_is_fatal(0xC0000022u)); // access denied
    REQUIRE(net_capture::startup_is_fatal(0xC00000BBu)); // not supported
    REQUIRE(net_capture::startup_is_fatal(0xC022000Au)); // WFP object in use
}
