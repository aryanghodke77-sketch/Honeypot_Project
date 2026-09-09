# tests/unit/CMakeLists.txt
cmake_minimum_required(VERSION 3.14)
project(task1_validation)

# Task 1 structural validation test
add_executable(task1_validation task1_validation.cpp)
target_include_directories(task1_validation PRIVATE ${CMAKE_SOURCE_DIR})

# Crypto / challenge-response auth unit tests
add_executable(crypto_validation
    crypto_validation.cpp
    ${CMAKE_SOURCE_DIR}/simulation/simulated_auth_provider.cpp
    ${CMAKE_SOURCE_DIR}/simulation/simulated_device.cpp
    ${CMAKE_SOURCE_DIR}/core/crypto/sha256.cpp
)
target_include_directories(crypto_validation PRIVATE ${CMAKE_SOURCE_DIR})