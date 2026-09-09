# tests/unit/CMakeLists.txt
cmake_minimum_required(VERSION 3.14)
project(task1_validation)

# Add the validation test executable
add_executable(task1_validation task1_validation.cpp)

# Include the project root directory for header includes
target_include_directories(task1_validation PRIVATE ${CMAKE_SOURCE_DIR})