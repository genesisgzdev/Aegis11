cmake_minimum_required(VERSION 3.21)

project(Aegis11 VERSION 1.0.0 LANGUAGES CXX RC)

if(NOT WIN32)
    message(FATAL_ERROR "Aegis11 is a Windows-only application and must be built on a Windows runner.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(aegis11
    src/main.cpp
    resources/aegis.rc
)

target_include_directories(aegis11 PRIVATE include)
target_compile_definitions(aegis11 PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)

if(MSVC)
    target_compile_options(aegis11 PRIVATE /W4 /permissive-)
    target_link_options(aegis11 PRIVATE /MANIFEST:NO)
else()
    target_compile_options(aegis11 PRIVATE -Wall -Wextra -Wpedantic)
endif()

target_link_libraries(aegis11 PRIVATE
    advapi32 shell32 user32 ole32 oleaut32 taskschd fwpuclnt rpcrt4
    crypt32 wintrust ws2_32
)

include(CTest)
find_package(Python3 COMPONENTS Interpreter REQUIRED)
add_test(
    NAME repository_compile_checks
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/compile_checks.py"
)
