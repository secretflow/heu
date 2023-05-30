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

#include "reg.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/file.h>

namespace heu::lib::algorithms::paillier_clustar_fpga::fpga_engine {

/*
 * Function       : reg_write
 * Description    : used to write FPGA's register
 * Para:
 *   addr         : reg address
 *   write_val    : reg value
 *   access_width : reg type
 *     'b'        : read 1 byte
 *     'h'        : read 2 bytes
 *     'w'        : read 4 bytes
 */ 
void reg_write(void *addr, uint32_t write_val, char access_width) {
	switch (access_width) {
		case 'b':
			*((uint8_t *) addr) = write_val;
			break;
		case 'h':
			*((uint16_t *) addr) = write_val;
			break;
		case 'w':
			*((uint32_t *) addr) = write_val;
			break;
		default:
			fprintf(stderr, "Illegal write reg data type '%c'.\n", access_width);
			exit(2);
	}
}

/*
 * Function       : reg_read
 * Description    : used to read FPGA's register
 * Para:
 *   addr         : reg address
 *   access_width : reg type
 *     'b'        : read 1 byte
 *     'h'        : read 2 bytes
 *     'w'        : read 4 bytes
 * Return: reg value
 */ 
uint32_t reg_read(void *addr, char access_width) {
	uint32_t read_val;
	switch (access_width) {
		case 'b':
			read_val = *((uint8_t *) addr);
			break;
		case 'h':
			read_val = *((uint16_t *) addr);
			break;
		case 'w':
			read_val = *((uint32_t *) addr);
			break;
		default:
			fprintf(stderr, "Illegal read reg data type '%c'.\n", access_width);
			exit(2);
	}
	
	return read_val;
}

/*
 * Function       : reg32_write
 * Description    : used to write 32bits FPGA's register
 * Para:
 *   addr         : reg address
 *   write_val    : write_val
 */
void reg32_write(int user_fd, void *addr, uint32_t write_val) {
	flock(user_fd, LOCK_EX);
	reg_write(addr, write_val, 'w');
	flock(user_fd, LOCK_UN);
}

/*
 * Function       : reg32_read
 * Description    : used to read 32bits FPGA's register
 * Para:
 *   addr         : reg address
 * Return         : reg value
 */
uint32_t reg32_read(void *addr) {
	return reg_read(addr, 'w');
}

/*
 * Function       : get_status
 * Description    : used to get bit status of FPGA's register
 * Para:
 *   addr         : reg address
 *   pos          : bit position of 32bits' register
 * Return         : bit status
 */
uint32_t get_status(void *addr, uint8_t pos) {
	uint32_t status;
	status = (reg_read(addr, 'w') >> pos);
	return (status & 0x1);
}

/*
 * Function       : set_status
 * Description    : used to set bit status of FPGA's register
 * Para:
 *   addr         : reg address
 *   pos          : bit position of 32bits' register
 */
void set_status(int user_fd, void *addr, uint8_t pos) {
	flock(user_fd, LOCK_EX);
	uint32_t status = reg_read(addr, 'w');
	uint32_t mask = (1 << pos);
	status = status | mask;
	reg_write(addr, status, 'w');
	flock(user_fd, LOCK_UN);
}

/*
 * Function       : clear_status
 * Description    : used to clear bit status of FPGA's register
 * Para:
 *   addr         : reg address
 *   pos          : bit position of 32bits' register
 */
void clear_status(int user_fd, void *addr, uint8_t pos) {
	flock(user_fd, LOCK_EX);
	uint32_t status = reg_read(addr, 'w');
	uint32_t mask = ~(1 << pos);
	status = status & mask;
	reg_write(addr, status, 'w');
	flock(user_fd, LOCK_UN);
}

/*
 * Function       : check_and_clear_status
 * Description    : used to clear bit status of FPGA's register if the original status is 1, otherwise return error
 * Para:
 *   addr         : reg address
 *   pos          : bit position of 32bits' register
 */
int check_and_clear_status(int user_fd, void *addr, uint8_t pos) {
	flock(user_fd, LOCK_EX);
	uint32_t status = reg_read(addr, 'w');
	if((status & (1 << pos)) == 0){
		flock(user_fd, LOCK_UN);
		return 1;
	}
	uint32_t mask = ~(1 << pos);
	status = status & mask;
	reg_write(addr, status, 'w');
	flock(user_fd, LOCK_UN);
	return 0;
}

} // heu::lib::algorithms::paillier_clustar_fpga::fpga_engine
