cmake_minimum_required(VERSION 3.21)

# Define the project and target language
project(Aegis11 
    VERSION 1.0.0 
    DESCRIPTION "System Controller and Telemetry Mitigation Engine"
    LANGUAGES CXX
)

# Enforce C++17 Standard (Required for std::filesystem and modern features)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Automatically gather all source and header files (updates automatically on build)
file(GLOB_RECURSE AEGIS_SOURCES CONFIGURE_DEPENDS 
    "src/*.cpp" 
    "include/*.hpp"
)

# Create the executable target
add_executable(${PROJECT_NAME} ${AEGIS_SOURCES})

# Include directories (so #include "..." works smoothly)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

# MSVC-Specific compiler and linker optimizations for stealth and performance
if(MSVC)
    # Statically link the C Runtime (CRT) to avoid requiring VCRedist installation
    set_property(TARGET ${PROJECT_NAME} PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

    # Aggressive compiler optimizations for Release builds
    target_compile_options(${PROJECT_NAME} PRIVATE
        $<$<CONFIG:Release>:/O2>      # Maximize speed
        $<$<CONFIG:Release>:/Ob2>     # Aggressive inline expansion
        $<$<CONFIG:Release>:/Oi>      # Generate intrinsic functions
        $<$<CONFIG:Release>:/GL>      # Whole program optimization
        $<$<CONFIG:Release>:/GS->     # Disable buffer security checks (reduces binary footprint)
        $<$<CONFIG:Release>:/Gw>      # Optimize global data
        /W4                           # Warning level 4
        /MP                           # Multi-processor compilation (faster build times)
    )

    # Advanced Linker Flags
    target_link_options(${PROJECT_NAME} PRIVATE
        $<$<CONFIG:Release>:/OPT:REF> # Eliminate unreferenced functions/data
        $<$<CONFIG:Release>:/OPT:ICF> # Fold identical COMDATs (reduces binary size)
        $<$<CONFIG:Release>:/LTCG>    # Link-time code generation
        /SUBSYSTEM:CONSOLE            # Explicit console subsystem definition
        "/MANIFESTUAC:level='requireAdministrator' uiAccess='false'" # Force UAC Elevation Manifest
    )
endif()

# Link native Windows APIs used by the Aegis11 Engine (WMI, COM, DACL, WFP)
target_link_libraries(${PROJECT_NAME} PRIVATE
    advapi32    # Registry operations, DACLs, Security Descriptors
    ole32       # Core COM Initialization
    oleaut32    # COM BSTR and VARIANT data types
    wbemuuid    # WMI (Windows Management Instrumentation) for Ghost Vigilante
    iphlpapi    # Network Helper API (DNS Cache flushing)
    taskschd    # Task Scheduler COM API
    fwpuclnt    # Windows Filtering Platform (WFP)
    runtimeobject # WinRT COM API for native Appx Management
)