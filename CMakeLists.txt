cmake_minimum_required(VERSION 3.20)
project(rudy_bpf_atlas VERSION 0.1.0 LANGUAGES CXX)

option(RUDY_BPF_ATLAS_BUILD_TESTS "Build the test suite" ON)

add_library(rudy_bpf_atlas_core
    src/analyzer.cpp
    src/report.cpp)
target_include_directories(rudy_bpf_atlas_core PUBLIC include)
target_compile_features(rudy_bpf_atlas_core PUBLIC cxx_std_20)
if(MSVC)
  target_compile_options(rudy_bpf_atlas_core PRIVATE /W4 /permissive- /EHsc)
else()
  target_compile_options(rudy_bpf_atlas_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
endif()

add_executable(rudy-bpf-atlas src/main.cpp)
target_link_libraries(rudy-bpf-atlas PRIVATE rudy_bpf_atlas_core)

if(RUDY_BPF_ATLAS_BUILD_TESTS)
  enable_testing()
  add_test(NAME cli-help COMMAND rudy-bpf-atlas --help)
  add_executable(rudy-bpf-atlas-tests tests/test_analyzer.cpp)
  target_link_libraries(rudy-bpf-atlas-tests PRIVATE rudy_bpf_atlas_core)
  add_test(NAME analyzer-tests COMMAND rudy-bpf-atlas-tests)
endif()

install(TARGETS rudy-bpf-atlas RUNTIME DESTINATION bin)
