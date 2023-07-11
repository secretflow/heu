project(paillier_dl)
cmake_minimum_required(VERSION 3.1)

set(CUDA_TOOLKIT_ROOT_DIR /usr/local/cuda)
find_package(CUDA REQUIRED)

set(CUDA_NVCC_FLAGS -arch=sm_75 -g)

include_directories(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_SOURCE_DIR}/third_party)
include_directories(${CMAKE_SOURCE_DIR}/third_party/cgbn/include)
include_directories(${CMAKE_SOURCE_DIR}/third_party/msgpack/include)
include_directories(${CMAKE_SOURCE_DIR}/third_party/yacl)
include_directories(${CMAKE_SOURCE_DIR}/third_party/absl)
include_directories(${CMAKE_SOURCE_DIR}/third_party/fmt/include)
include_directories(${CMAKE_SOURCE_DIR}/third_party/googletest/googletest/include)

file(GLOB_RECURSE src_files *.cu)
cuda_add_library(cgbn_wrapper SHARED ${src_files})
