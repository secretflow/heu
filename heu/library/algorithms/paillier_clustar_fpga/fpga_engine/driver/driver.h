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

#include <stdint.h>
#include <string.h>

#include "dma.h"
#include "reg.h"
#include "task.h"

#include "heu/library/algorithms/paillier_clustar_fpga/fpga_engine/config/config.h"

namespace heu::lib::algorithms::paillier_clustar_fpga::fpga_engine {

// #define MAX_MEMSPACE 8589672448  // 8589672448 = (1024 * 1024 * 1024 - 32 *
// 1024) * 8 bit 1000MB
#define DDR1_BASE_ADDR 0x1000000000
#define BACKDATA_INFO_SIZE 64  // 64Bytes
#define MAX_NUM_OF_DEV 8

typedef struct {
  uint8_t operate_mode;
  size_t batch_size;
  size_t para_data_size;  // data size of para
  size_t data1_size;      // data size of data1
  size_t data2_size;  // data size of data2. Set the parameter to 0 if there is
                      // no data2
  size_t data3_size;  // data size of data3. Set the parameter to 0 if there is
                      // no data3
  uint8_t para_bitlen;   // bitlength of parameter N
  uint8_t data1_bitlen;  // bitlength of data1
  uint8_t data2_bitlen;  // bitlength of data2
  uint8_t data3_bitlen;  // bitlength of data3
  uint32_t task_space_size_req;
  uint32_t pisum_block_num;
  uint32_t pisum_cfg;
  // The parameters below are related to buffer function.
  uint8_t data1_memtype;  // The location where data1 is stored.
  // 0 represents CPU. 128-(128+15) represent task id on FPGA. 255 repesents no
  // data available. Same for data2, data3 and result.
  uint8_t data2_memtype;
  uint8_t data3_memtype;
  uint8_t result_memtype;    // Specify the location to store result data.
  uint8_t srcdata_buf_hold;  // Specify whether to hold data in back_data_status
                             // and result_buffer registers of the source data.
  // 1 represents holding and 0 represents cleaning automatically.
  uint8_t bypass_computing;  // bypass id
  uint8_t fpga_dev_id;       // Specify the FPGA device to operate
} fpga_config;

uint8_t get_data_width(size_t n_length);

uint32_t getdatalength(uint32_t n_len);

/*
 * Function     : fpga_dev_number_get
 * Description  : used to open get the numbers of dev
 * Para         : no para
 * Return:
 *              : the numbers of xdma_dev
 */
int fpga_dev_number_get();

/*
 * Function     : open_dev
 * Description  : used to open FPGA driver
 * Para         :
 * 	 dev_num    : the number of xdma_dev,  0 t0 7
 * Return:
 *   0          : SUCCESS
 *   other      : FAILURE, refer to Error Id.
 */
int open_dev(int *userfd, int *h2cfd, int *c2hfd, uint8_t dev_num);

/*
 * Function     : close_dev
 * Description  : used to close FPGA driver
 * Para         :
 * 	 dev_num    : the number of xdma_dev,  0 to 7
 * Return:
 *   0          : SUCCESS
 *   other      : FAILURE, refer to Error Id.
 */
int close_dev(int userfd, int h2cfd, int c2hfd, uint8_t dev_num);

/*
 * Function    : fpga_fedai_operator_accl
 * Description : used to achieve fedai_operator accleration in FPGA, including
 * handshake between FPGA and HOST, register configuration, data transfer,
 * Modexp_Multifunc accleration, etc. Para: task      : FPGA's task struct data
 * : ModexpMultifunc's data (MEN) to FPGA cipher    : ModexpMultifunc's result
 * from FPGA data_size : byte size of ModexpMultifunc's data n_length  : bit
 * length of ModexpMultifunc Key N^2 bypass    : ModexpMultifunc's bypass mode
 * (on: 1, off: 0) Return: 0         : SUCCESS other     : FAILURE, refer to
 * Error Id.
 */
int fpga_fedai_operator_accl(fpga_config *cfg, char *para, char *data1,
                             char *data2, char *data3, char *result);

int fpga_fedai_operator_accl_split_task(fpga_config *cfg, char *para,
                                        char *data1, char *data2, char *data3,
                                        char *result);

int open_user_fd(int *userfd, uint8_t dev_num);

int close_user_fd(int user_fd, uint8_t dev_num);

}  // namespace heu::lib::algorithms::paillier_clustar_fpga::fpga_engine
