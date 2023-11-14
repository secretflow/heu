// Copyright 2023 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <cuda.h>
#include <cuda_runtime_api.h>
#include <stdio.h>

#define CUDA_CHECK(status)                                                  \
  do {                                                                      \
    if (status != cudaSuccess) {                                            \
      fprintf(stderr,                                                       \
              "CUDA error occurred, status:%d, name:%s, string:%s, "        \
              "function:%s, file:%s, line:%d\n",                            \
              status, cudaGetErrorName(status), cudaGetErrorString(status), \
              __FUNCTION__, __FILE__, __LINE__);                            \
      return (status);                                                      \
    }                                                                       \
  } while (0)

#define CUDA_LAST_CHECK()                                                   \
  do {                                                                      \
    cudaError_t status = cudaGetLastError();                                \
    if (status != cudaSuccess) {                                            \
      fprintf(stderr,                                                       \
              "CUDA error occurred, status:%d, name:%s, string:%s, "        \
              "function:%s, file:%s, line:%d\n",                            \
              status, cudaGetErrorName(status), cudaGetErrorString(status), \
              __FUNCTION__, __FILE__, __LINE__);                            \
      return (status);                                                      \
    }                                                                       \
  } while (0)

#define CGBN_CHECK(report)                                                 \
  do {                                                                     \
    if (cgbn_error_report_check(report)) {                                 \
      fprintf(stderr,                                                      \
              "CGBN error occurred, status:%d, string:%s, function:%s, "   \
              "file:%s, line:%d\n",                                        \
              report->_error, cgbn_error_string(report), __FUNCTION__,     \
              __FILE__, __LINE__);                                         \
      if (report->_instance != 0xFFFFFFFF) {                               \
        fprintf(stderr, "CGBN error reported by instance %d",              \
                report->_instance);                                        \
        if (report->_blockIdx.x != 0xFFFFFFFF)                             \
          fprintf(stderr, " blockIdx=(%d, %d, %d) ", report->_blockIdx.x,  \
                  report->_blockIdx.y, report->_blockIdx.z);               \
        if (report->_threadIdx.x != 0xFFFFFFFF)                            \
          fprintf(stderr, " threadIdx=(%d, %d, %d)", report->_threadIdx.x, \
                  report->_threadIdx.y, report->_threadIdx.z);             \
        fprintf(stderr, "\n");                                             \
      } else {                                                             \
        fprintf(stderr, "CGBN error reported by blockIdx=(%d %d %d) ",     \
                report->_blockIdx.x, report->_blockIdx.y,                  \
                report->_blockIdx.z);                                      \
        fprintf(stderr, "threadIdx=(%d %d %d)\n", report->_threadIdx.x,    \
                report->_threadIdx.y, report->_threadIdx.z);               \
      }                                                                    \
      return (report->_error);                                             \
    }                                                                      \
  } while (0)

#define CUDA_CONTEXT_CHECK(status)                                             \
  do {                                                                         \
    if (status != CUDA_SUCCESS) {                                              \
      fprintf(stderr,                                                          \
              "CUDA CONTEXT error occurred, status:%d, function:%s, file:%s, " \
              "line:%d\n",                                                     \
              status, __FUNCTION__, __FILE__, __LINE__);                       \
      return (status);                                                         \
    }                                                                          \
  } while (0)
