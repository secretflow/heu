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

/*
 * Function    : transfer_to_fpga
 * Description : used to transfer data from HOST to FPGA through PCIE
 * Para:
 *   fname     : filename of driver
 *   fd        : fd of driver
 *   buffer    : send_data buffer
 *   size      : size of data to send
 *   base      : base address of send_buffer
 */ 
uint32_t transfer_to_fpga(const char *fname, int fd, char *buffer, uint32_t size, uint64_t base);

/*
 * Function    : transfer_from_fpga
 * Description : used to transfer data from FPGA to HOST through PCIE
 * Para:
 *   fname     : filename of driver
 *   fd        : fd of driver
 *   buffer    : recv_data buffer
 *   size      : size of data to receive
 *   base      : base address of recv_data buffer
 */
uint32_t transfer_from_fpga(const char *fname, int fd, char *buffer, uint32_t size, uint64_t base);

} // heu::lib::algorithms::paillier_clustar_fpga::fpga_engine
