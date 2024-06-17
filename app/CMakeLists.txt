cmake_minimum_required(VERSION 3.21)

set(target bpf_test)

project(${target})

file(GLOB_RECURSE sources
    src/*.h
    src/*.c
)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_executable(${target} ${sources})

target_link_libraries(${target} bpf)
# target_link_libraries(${target} ${CMAKE_SOURCE_DIR}/lib/libbpf/src/root/usr/lib64/)
# target_link_libraries(${target} ${CMAKE_SOURCE_DIR}/lib/libbpf/src/root/usr/lib64/libbpf.a)

target_include_directories(${target} PRIVATE -L${CMAKE_SOURCE_DIR}/lib/libbpf/root/usr/include)

set_target_properties(${target} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/run)

