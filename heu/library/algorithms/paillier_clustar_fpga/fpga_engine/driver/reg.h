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

#define TASK_MANAGER_BASE_ADDR 0x00010000
#define TASK_MANAGER_ADDR_SIZE 0x0100


#define TASK_STATE_ADDR 0x00
#define SRCDATA_STATE_ADDR 0x04
#define BACKDATA_STATE_ADDR 0x08
#define BACKDATA_ADDR_L 0x0C
#define BACKDATA_ADDR_H 0x10
#define BACKDATA_LEN_ADDR 0x14
#define RESULT_BUFFER_STATE_ADDR 0x18

#define LOOPBACK_EN_ADDR 0x12000
#define RESULT_BUFFER_CNT_ADDR 0x1801C

#define SYS_PROCESS_ERR_ADDR 0x1C104  //bit0: FPGA internal error, bit1: FPGA timeout
#define TASK_BUF_HOLF_TIMEOUT_ADDR 0x1C108
#define BUFFER_CLEAR_REG_ADDR 0x12008
#define BUFFER_CLEAR_FB_REG_ADDR 0x1200C
#define BUFF_HOLD1_THRESHOLD_VALUE 0x12010
#define BUFF_HOLD2_THRESHOLD_VALUE 0x12014
#define TASK_BUSY_COUNT_ADDR 0x12018
#define BUFF_HOLD_TIMEOUT 0x1c108
#define TASK_SPACE_SIZE_CONFIG 0x1201c
#define TASK_SPACE_SIZE_CONFIG_RESP  0x12020

#define CMD_ADDR_LEN 0x4000
#define PARA_ADDR_LEN 0x4000

/*
 * Function       : reg32_write
 * Description    : used to write 32bits FPGA's register
 * Para:
 *   addr         : reg address
 *   write_val    : write_val
 */
void reg32_write(int user_fd, void *addr, uint32_t write_val);

/*
 * Function       : reg32_read
 * Description    : used to read 32bits FPGA's register
 * Para:
 *   addr         : reg address
 * Return         : reg value
 */
uint32_t reg32_read(void *addr);

/*
 * Function       : get_status
 * Description    : used to get bit status of FPGA's register
 * Para:
 *   addr         : reg address
 *   pos          : bit position of 32bits' register
 * Return         : bit status
 */
uint32_t get_status(void *addr, uint8_t pos);

/*
 * Function       : set_status
 * Description    : used to set bit status of FPGA's register
 * Para:
 *   addr         : reg address
 *   pos          : bit position of 32bits' register
 */
void set_status(int user_fd, void *addr, uint8_t pos);

/*
 * Function       : clear_status
 * Description    : used to clear bit status of FPGA's register
 * Para:
 *   addr         : reg address
 *   pos          : bit position of 32bits' register
 */
void clear_status(int user_fd, void *addr, uint8_t pos);

/*
 * Function       : check_and_clear_status
 * Description    : used to clear bit status of FPGA's register if the original status is 1, otherwise return error
 * Para:
 *   addr         : reg address
 *   pos          : bit position of 32bits' register
 */
int check_and_clear_status(int user_fd, void *addr, uint8_t pos);

} // heu::lib::algorithms::paillier_clustar_fpga::fpga_engine
