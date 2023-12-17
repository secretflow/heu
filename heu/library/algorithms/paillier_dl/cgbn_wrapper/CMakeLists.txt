project(paillier_dl)
cmake_minimum_required(VERSION 3.1)

set(CMAKE_CXX_COMPILER "dlcc")
if ("$ENV{DLI_V2}" STREQUAL "ON")
    set(gpu_arch --cuda-gpu-arch=dlgput64)
    set(src_path src_gen2)
    set(file_suffix ".cu.cc")
    message(STATUS "***v2 sdk***")
else()
    set(gpu_arch --cuda-gpu-arch=dlgpuc64)
    set(src_path src_gen1)
    set(file_suffix "*")
    message(STATUS "***v1 sdk***")
endif()

include_directories(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_SOURCE_DIR}/third_party)
include_directories(${CMAKE_SOURCE_DIR}/third_party/cgbn/include)
include_directories(${CMAKE_SOURCE_DIR}/third_party/msgpack/include)
include_directories(${CMAKE_SOURCE_DIR}/third_party/yacl)
include_directories(${CMAKE_SOURCE_DIR}/third_party/absl)
include_directories(${CMAKE_SOURCE_DIR}/third_party/fmt/include)
include_directories(${CMAKE_SOURCE_DIR}/third_party/googletest/googletest/include)
include_directories(${CMAKE_SOURCE_DIR}/third_party/gmp-6.2.1)

file(GLOB_RECURSE src_files *.cc)
add_library(cgbn_wrapper SHARED ${src_files})
target_compile_options(cgbn_wrapper PRIVATE
                       -Wno-c++11-narrowing -DNDEBUG -std=c++17
                       -Wdouble-promotion -fPIC ${gpu_arch}
                       -x cuda -D__CUDA_ARCH__=300)
target_link_libraries(cgbn_wrapper PRIVATE curt)