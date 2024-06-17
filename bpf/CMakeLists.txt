cmake_minimum_required(VERSION 3.10)

project(MyBPFProject LANGUAGES C)

# Путь к исходному файлу
set(SOURCE_FILE xdp_redirect_icmp.c)

# Опции компилятора для clang
set(CLANG_FLAGS "-O2 -target bpf")

# Проверка наличия clang
find_program(CLANG clang)

if(NOT CLANG)
    message(FATAL_ERROR "Clang не найден!")
endif()

# Целевая компиляция
add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/xdp_redirect_icmp.bpf.o
    COMMAND ${CLANG} -O2 -target bpf -I ${CMAKE_CURRENT_SOURCE_DIR}/lib/libbpf/src/root/usr/include -c ${CMAKE_CURRENT_SOURCE_DIR}/${SOURCE_FILE} -o ${CMAKE_SOURCE_DIR}/run/xdp_redirect_icmp.bpf.o
    COMMAND bpftool gen skeleton ${CMAKE_SOURCE_DIR}/run/xdp_redirect_icmp.bpf.o > ${CMAKE_SOURCE_DIR}/app/src/xdp_redirect_icmp.user.h
    DEPENDS ${SOURCE_FILE}
)

add_custom_target(MyBPFProgram ALL DEPENDS ${CMAKE_BINARY_DIR}/xdp_redirect_icmp.bpf.o)
