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

#include "task.h"
#include <stdio.h>
#include <stdint.h> 
#include <stdlib.h>
#include <sys/mman.h>
#include "reg.h"
#include "driver.h"

namespace heu::lib::algorithms::paillier_clustar_fpga::fpga_engine {

//struct fpga_modexp_task *task;
/*
 * Function     : init_task
 * Description  : used to initialize FPGA's ModexpMultifunc task struct
 * Para         : no para
 */ 
void init_task(void * map_base, struct fpga_modexp_task *task, uint32_t task_id) {
	char *task_base = static_cast<char*>(map_base) + TASK_MANAGER_BASE_ADDR + task_id * TASK_MANAGER_ADDR_SIZE;
	task->task_id = task_id;
	task->batch_id = -1;
	task->task_state_addr = task_base + TASK_STATE_ADDR;
	task->srcdata_state_addr = task_base + SRCDATA_STATE_ADDR;
	task->backdata_state_addr = task_base + BACKDATA_STATE_ADDR;
	task->backdata_addr_L = task_base + BACKDATA_ADDR_L;
	task->backdata_addr_H = task_base + BACKDATA_ADDR_H;
	task->backdata_len_addr = task_base + BACKDATA_LEN_ADDR;
	task->result_buffer_state_addr = task_base + RESULT_BUFFER_STATE_ADDR;
}

/*
 * Function     : free_task
 * Description  : used to free FPGA's ModexpMultifunc task struct
 * Para         : no para 
 */
void free_task(struct fpga_modexp_task *task) {
	free(task);
	task = NULL;
}

}
