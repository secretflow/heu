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
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

namespace heu::lib::algorithms::paillier_clustar_fpga::fpga_engine {

#define MULTI_CARD
// #define MULTI_CARD_DEBUG
#define MULTI_DEBUG
// #define TASK_DEBUG
// #define TEST_DEBUG

// #define MULTI_CARD_TEST
//  FPGA DEFINE
#define PISUM_MULTI
#define MAX_BUFFER_TASK_ID 8

#ifndef FPGA_TASK_NUM
#define FPGA_TASK_NUM 16
#endif

#define FPGA_BUSY_FLAG \
  1  // FPGA is in Busy state, and encryption operation is in progress

#define FPGAC_LICENSE_CHECK0 0x32709FD6
#define FPGAC_LICENSE_CHECK1 0x795446CF
#define FPGAC_LICENSE_CHECK2 0x253FC76B
#define FPGAC_LICENSE_CHECK3 0xFA35D968

// FPGA Errors
#define ERROR_FPGA_INTERNAL 2  // FPGA internal error detected
#define ERROR_FPGA_TIMEOUT 3   // Time out error detected by FPGA
#define ERROR_FPGA_LICENSE 4   // LicenseCheck error detected by FPGA
#define ERROR_FPGA_SPACESIZE_CFG 5

// Software Buffer Errors
#define ERROR_BUFFER_LIST 257  // Input buffer_id_list is illegal
#define ERROR_CLEAN_BUF \
  258  // Buffer clean error, the corresponding task_id is under operation or
       // there's no buffer data on the task_id
#define ERROR_BUF_EXCEEDED \
  259  // There is no enough task id left to calculate buffer tasks
#define ERROR_DATA_MEMTYPE \
  260  // Memtypes of input data do not match the operate_mode
#define ERROR_RES_MEMTYPE \
  261  // Memtype of result data equals to those of input datas or not supported
       // or corresponding task id is being used
#define ERROR_SRCDAT_BUFINFO \
  262  // Information buffered in FPGA contradicts cfg of input data
#define ERROR_SRCDAT_BUFSTATE \
  263  // Task_id for buffered source data has no data stored on it
#define ERROR_BUFF_FLAG 264  // The configuration of buffer flag is wrong

// Software Errors
#define ERROR_OPEN_DRIVER 513   // Error detected when opening driver
#define ERROR_CLOSE_DRIVER 514  // Error detected when closing driver
#define ERROR_EVEN 515          // Error that N is even
#define ERROR_SEND_CMD 516      // Error detected when sending cmd to FPGA
#define ERROR_SEND_PARA 517     // Error detected when sending para to FPGA
#define ERROR_SEND_DATA 518     // Error detected when sending data to FPGA
#define ERROR_CMD_NUMBER 519    // Error when configure the number of CMD
#define ERROR_PARA_SIZE 520     // Error when configure the size of PARA
#define ERROR_RECV_DATA 521     // Error detected when receiving data from FPGA
#define ERROR_DATASIZE \
  522  // Total input data size is larger than MAX_MEMSPACE or the data size is
       // 0
#define ERROR_REG_OPERATION \
  523  // Unknown problems on setting FPGA registers, unexpected interaction
       // process
#define ERROR_OPERATEMODE 524  // Unsupported operate mode
#define ERROR_LENGTH 525       // Unsupported bitlength
#define ERROR_BATCHSIZE 526    // Batch_size <= 0
#define ERROR_TASK_ID 527      // Unsupported task id (0 <= task_id <= 15)
#define ERROR_TIMEOUT_CAL 528  // Time out detected during calculation
#define ERROR_TIMEOUT_MAX \
  529  // Time out detected, the longest waiting time exceeded
#define ERROR_GETBACKDATA \
  530  // Abnormal, Back data is not fetched, causing its status to be 1 always
#define ERROR_FPGA_SRC_FLAG \
  531  // Interaction error, when lauch_en is configured to 1, src_data_flag is
       // 1;         1
#define ERROR_FPGA_BACK_FLAG \
  532  // Interaction error, when lauch_en is configured to 1, backdata_vld_flag
       // is 1;     2
#define ERROR_PISUM_MODE \
  533  // In Pisum mode, the Pisum_block_num or the Pisum_cfg is wrong configure
#define ERROR_PISUM_CFG \
  534  // In Pisum mode, when Pisum_block_num > 1 and the Pisum_cfg = 1, the
       // batch_size is not the Integer multiple of pisum_block_num
#define ERROR_NODEVICE_SPACESIZE_MATCHED 535
#define ERROR_TASK_ASSIGN_AND_DEVICE_BUSY 536
#define ERROR_PISUM_SET_CFG 537
#define ERROR_PISUM_CONFIG_FILE 538

#define ERROR_BUF_TYPE 769     // The configuration of buf_type is wrong
#define ERROR_SCANF_MODE 770   // The configuration of scanf_mode is wrong
#define ERROR_DATA_RUNNUM 771  // The configuration of run_num is wrong
#define ERROR_BYPASS 772       // Unsupported bypass mode
#define ERROR_CHECK 773        // Error when Comparing results

// CPU DEFINE
// #ifndef CPU_CORE_NUM
// #define CPU_CORE_NUM 1
// #endif

#ifndef FPGA_CHANNEL_NUM
#define FPGA_CHANNEL_NUM 1
#endif

#ifndef FPGA_TASK_SIZE
#define FPGA_TASK_SIZE 1024
#endif

extern struct timeval time_point[40];
extern struct timeval fpgaid_time_point[8][30];
extern long double single_task_maximum_time;
extern long double maximum_time;

}  // namespace heu::lib::algorithms::paillier_clustar_fpga::fpga_engine
