// Copyright 2023 Clustar Technology Co., Ltd.
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

#include <cstdint>

namespace heu::lib::algorithms::paillier_clustar_fpga::fpga_engine {

#define TASK_NUM 16
#define MAP_SIZE (16 * 1024 * 1024UL)
#define MAP_MASK (MAP_SIZE - 1)

struct fpga_modexp_task {
  uint32_t task_id;
  uint32_t batch_id;
  void *task_state_addr;
  void *srcdata_state_addr;
  void *backdata_state_addr;
  void *result_buffer_state_addr;
  void *backdata_addr_L;
  void *backdata_addr_H;
  void *backdata_len_addr;
};

// extern struct fpga_modexp_task *task;

/*
 * Function     : init_task
 * Description  : used to initialize FPGA's ModexpMultifunc task struct
 * Para         : no para
 */
void init_task(void *map_base, struct fpga_modexp_task *task, uint32_t task_id);

/*
 * Function     : free_task
 * Description  : used to free FPGA's ModexpMultifunc task struct
 * Para         : no para
 */
void free_task(struct fpga_modexp_task *task);

}  // namespace heu::lib::algorithms::paillier_clustar_fpga::fpga_engine
