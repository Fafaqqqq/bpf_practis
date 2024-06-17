cmake_minimum_required(VERSION 3.21)

set(target root)

set(CMAKE_C_COMPILER "/usr/bin/clang")

project(${target})

add_subdirectory(bpf)
add_subdirectory(app)
add_subdirectory(lib)
