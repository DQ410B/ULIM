cmake_minimum_required(VERSION 3.16)
project(ULIM LANGUAGES CXX)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" OR NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
  message(FATAL_ERROR "ULIM currently supports Linux x86_64; use x86_64 Linux under WSL2 on Windows")
endif()
find_package(OpenSSL 3 REQUIRED COMPONENTS Crypto)
find_package(Threads REQUIRED)
include(cmake/profiles.cmake)
set(ULIM_PROFILE "n112_L64_k10" CACHE STRING "Public dimensions of the D protocol")
set_property(CACHE ULIM_PROFILE PROPERTY STRINGS ${ULIM_AVAILABLE_PROFILES})
if(NOT ULIM_PROFILE IN_LIST ULIM_AVAILABLE_PROFILES)
  message(FATAL_ERROR "Unsupported ULIM_PROFILE. Available: ${ULIM_AVAILABLE_PROFILES}")
endif()
option(ULIM_NATIVE_ARCH "Compile for the current CPU using -march=native" ON)

add_library(ulim_build_settings INTERFACE)
target_compile_features(ulim_build_settings INTERFACE cxx_std_17)
target_include_directories(ulim_build_settings INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}")
target_include_directories(ulim_build_settings SYSTEM INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/third_party/emp-tool"
  "${CMAKE_CURRENT_SOURCE_DIR}/third_party/emp-ot"
  "${CMAKE_CURRENT_SOURCE_DIR}/third_party/emp-sh2pc")
target_compile_options(ulim_build_settings INTERFACE -O2 -g -Wall -Wextra -Werror -UNDEBUG
  -Wno-deprecated-declarations -Wno-ignored-attributes -Wno-error=unused-variable
  -Wno-error=unused-function -Wno-error=misleading-indentation -Wno-error=array-bounds)
if(ULIM_NATIVE_ARCH)
  target_compile_options(ulim_build_settings INTERFACE -march=native)
else()
  target_compile_options(ulim_build_settings INTERFACE -maes -mpclmul -msse4.1)
endif()
target_link_libraries(ulim_build_settings INTERFACE OpenSSL::Crypto Threads::Threads ${CMAKE_DL_LIBS} m)

add_executable(ulim src/main.cpp third_party/emp-tool/emp-tool/emp-tool.cpp)
target_compile_definitions(ulim PRIVATE
  ULIM_PROFILE_SOURCE="src/profiles/${ULIM_PROFILE}/worker.cpp"
  ULIM_PROFILE_NAME="${ULIM_PROFILE}")
target_link_libraries(ulim PRIVATE ulim_build_settings)
message(STATUS "ULIM main method: D; public parameter profile: ${ULIM_PROFILE}")
