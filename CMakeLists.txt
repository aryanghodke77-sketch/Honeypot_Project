# CMakeLists.txt - Security Jack Project
cmake_minimum_required(VERSION 3.14)
project(SecurityJack VERSION 1.0 LANGUAGES CXX)

# C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add unit tests subdirectory
add_subdirectory(tests/unit)