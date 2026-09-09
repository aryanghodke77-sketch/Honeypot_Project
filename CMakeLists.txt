# CMakeLists.txt - Security Jack Project
cmake_minimum_required(VERSION 3.14)
project(SecurityJack VERSION 1.0 LANGUAGES CXX)

# C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Full-chain simulator demo (top-level wiring - ARCHITECTURE.md section 13)
add_executable(security_jack_sim
    main_sim.cpp
    simulation/console_logger.cpp
    simulation/simulated_ethernet.cpp
    simulation/simulated_auth_provider.cpp
    simulation/simulated_device.cpp
    simulation/simulated_relay.cpp
    core/crypto/sha256.cpp
    core/identity/enrollment_registry.cpp
    core/policy/trust_policy.cpp
    core/state/device_state_machine.cpp
    core/threat/threat_engine.cpp
    phase1/verification_workflow.cpp
    phase2/detection_engine.cpp
    phase2/high_packet_rate_detector.cpp
    phase2/response_engine.cpp
)
target_include_directories(security_jack_sim PRIVATE ${CMAKE_SOURCE_DIR})

# End-to-end scenario test
add_executable(full_chain_test
    tests/end_to_end/full_chain_test.cpp
    simulation/console_logger.cpp
    simulation/simulated_ethernet.cpp
    simulation/simulated_auth_provider.cpp
    simulation/simulated_device.cpp
    simulation/simulated_relay.cpp
    core/crypto/sha256.cpp
    core/identity/enrollment_registry.cpp
    core/policy/trust_policy.cpp
    core/state/device_state_machine.cpp
    core/threat/threat_engine.cpp
    phase1/verification_workflow.cpp
    phase2/detection_engine.cpp
    phase2/high_packet_rate_detector.cpp
    phase2/response_engine.cpp
)
target_include_directories(full_chain_test PRIVATE ${CMAKE_SOURCE_DIR})

# Unit tests
add_subdirectory(tests/unit)