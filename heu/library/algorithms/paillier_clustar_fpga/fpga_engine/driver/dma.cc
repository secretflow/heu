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

#include "dma.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/file.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

namespace heu::lib::algorithms::paillier_clustar_fpga::fpga_engine {

/*
 * man 2 write:
 * On Linux, write() (and similar system calls) will transfer at most
 * 	0x7ffff000 (2,147,479,552) bytes, returning the number of bytes
 *	actually transferred.  (This is true on both 32-bit and 64-bit
 *	systems.)
 */
#define RW_MAX_SIZE 0x7ffff000

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
uint32_t transfer_to_fpga(const char *fname, int fd, char *buffer,
                          uint32_t size, uint64_t base) {
  ssize_t rc;
  char *buf = buffer;
  uint32_t count = 0;
  uint64_t offset = base;

  while (count < size) {
    uint32_t bytes = size - count;
    if (bytes > RW_MAX_SIZE) {
      bytes = RW_MAX_SIZE;
    }

    if (offset) {
      rc = lseek(fd, offset, SEEK_SET);
      if (static_cast<uint64_t>(rc) != offset) {
        fprintf(stdout, "%s, seek off 0x%lx != 0x%" PRIx64 ".\n", fname, rc,
                offset);
        perror("seek file");
        return -EIO;
      }
    }
    /* write data to file from memory buffer */
    rc = write(fd, buf, bytes);
    if (rc != bytes) {
      fprintf(stdout, "%s, W off 0x%" PRIx64 ", 0x%lx != 0x%x.\n", fname,
              offset, rc, bytes);
      perror("write file");
      return -EIO;
    }

    count += bytes;
    buf += bytes;
    offset += bytes;
  }

  if (count != size) {
    fprintf(stdout, "%s, R failed 0x%x != 0x%x.\n", fname, count, size);
    return -EIO;
  }
  return count;
}

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
uint32_t transfer_from_fpga(const char *fname, int fd, char *buffer,
                            uint32_t size, uint64_t base) {
  ssize_t rc;
  char *buf = buffer;
  uint32_t count = 0;
  uint64_t offset = base;

  while (count < size) {
    uint32_t bytes = size - count;

    if (bytes > RW_MAX_SIZE) {
      bytes = RW_MAX_SIZE;
    }

    if (offset) {
      rc = lseek(fd, offset, SEEK_SET);
      if (static_cast<uint64_t>(rc) != offset) {
        fprintf(stderr, "%s, seek off 0x%lx != 0x%" PRIx64 ".\n", fname, rc,
                offset);
        perror("seek file");
        return -EIO;
      }
    }

    /* read data from file into memory buffer */
    rc = read(fd, buf, bytes);
    if (rc != bytes) {
      fprintf(stderr, "%s, R off 0x%x, 0x%lx != 0x%x.\n", fname, count, rc,
              bytes);
      perror("read file");
      return -EIO;
    }

    count += bytes;
    buf += bytes;
    offset += bytes;
  }

  if (count != size) {
    fprintf(stderr, "%s, R failed 0x%x != 0x%x.\n", fname, count, size);
    return -EIO;
  }
  return count;
}

}  // namespace heu::lib::algorithms::paillier_clustar_fpga::fpga_engine
