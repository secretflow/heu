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

#include "driver.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <termios.h>
#include <unistd.h>

namespace heu::lib::algorithms::paillier_clustar_fpga::fpga_engine {

const char DEV_USER[MAX_NUM_OF_DEV][20] = {
    "/dev/xdma0_user", "/dev/xdma1_user", "/dev/xdma2_user", "/dev/xdma3_user",
    "/dev/xdma4_user", "/dev/xdma5_user", "/dev/xdma6_user", "/dev/xdma7_user"};
const char DEV_C2H[MAX_NUM_OF_DEV][4][20] = {
    {"/dev/xdma0_c2h_0", "/dev/xdma0_c2h_1", "/dev/xdma0_c2h_2",
     "/dev/xdma0_c2h_3"},
    {"/dev/xdma1_c2h_0", "/dev/xdma1_c2h_1", "/dev/xdma1_c2h_2",
     "/dev/xdma1_c2h_3"},
    {"/dev/xdma2_c2h_0", "/dev/xdma2_c2h_1", "/dev/xdma2_c2h_2",
     "/dev/xdma2_c2h_3"},
    {"/dev/xdma3_c2h_0", "/dev/xdma3_c2h_1", "/dev/xdma3_c2h_2",
     "/dev/xdma3_c2h_3"},
    {"/dev/xdma4_c2h_0", "/dev/xdma4_c2h_1", "/dev/xdma4_c2h_2",
     "/dev/xdma4_c2h_3"},
    {"/dev/xdma5_c2h_0", "/dev/xdma5_c2h_1", "/dev/xdma5_c2h_2",
     "/dev/xdma5_c2h_3"},
    {"/dev/xdma6_c2h_0", "/dev/xdma6_c2h_1", "/dev/xdma6_c2h_2",
     "/dev/xdma6_c2h_3"},
    {"/dev/xdma7_c2h_0", "/dev/xdma7_c2h_1", "/dev/xdma7_c2h_2",
     "/dev/xdma7_c2h_3"}};
const char DEV_H2C[MAX_NUM_OF_DEV][4][20] = {
    {"/dev/xdma0_h2c_0", "/dev/xdma0_h2c_1", "/dev/xdma0_h2c_2",
     "/dev/xdma0_h2c_3"},
    {"/dev/xdma1_h2c_0", "/dev/xdma1_h2c_1", "/dev/xdma1_h2c_2",
     "/dev/xdma1_h2c_3"},
    {"/dev/xdma2_h2c_0", "/dev/xdma2_h2c_1", "/dev/xdma2_h2c_2",
     "/dev/xdma2_h2c_3"},
    {"/dev/xdma3_h2c_0", "/dev/xdma3_h2c_1", "/dev/xdma3_h2c_2",
     "/dev/xdma3_h2c_3"},
    {"/dev/xdma4_h2c_0", "/dev/xdma4_h2c_1", "/dev/xdma4_h2c_2",
     "/dev/xdma4_h2c_3"},
    {"/dev/xdma5_h2c_0", "/dev/xdma5_h2c_1", "/dev/xdma5_h2c_2",
     "/dev/xdma5_h2c_3"},
    {"/dev/xdma6_h2c_0", "/dev/xdma6_h2c_1", "/dev/xdma6_h2c_2",
     "/dev/xdma6_h2c_3"},
    {"/dev/xdma7_h2c_0", "/dev/xdma7_h2c_1", "/dev/xdma7_h2c_2",
     "/dev/xdma7_h2c_3"}};

uint8_t get_data_width(size_t n_length) {
  switch (n_length) {
    case 128:
      return 0x0;
      break;
    case 256:
      return 0x1;
      break;
    case 512:
      return 0x2;
      break;
    case 768:
      return 0x3;
      break;
    case 1024:
      return 0x4;
      break;
    case 2048:
      return 0x5;
      break;
    case 3072:
      return 0x6;
      break;
    case 4096:
      return 0x7;
      break;
    case 0:
      return 0x0;
      break;
  }
  return 0x8;
}

uint32_t getdatalength(uint32_t n_len) {
  switch (n_len) {
    case 0x0:
      return 128;
    case 0x1:
      return 256;
    case 0x2:
      return 512;
    case 0x3:
      return 768;
    case 0x4:
      return 1024;
    case 0x5:
      return 2048;
    case 0x6:
      return 3072;
    case 0x7:
      return 4096;
  }
  return 0x8;
}

uint32_t get_error_num(uint32_t error_id) {
  uint32_t rc = 0;
  switch (error_id) {
    case 1:
      rc = FPGA_BUSY_FLAG;
      break;
    case 65:
      rc = ERROR_LENGTH;
      break;
    case 66:
      rc = ERROR_DATASIZE;
      break;
    case 67:
      rc = ERROR_PARA_SIZE;
      break;
    case 68:
      rc = ERROR_OPERATEMODE;
      break;
    case 69:
      rc = ERROR_TASK_ID;
      break;
    case 70:
      rc = ERROR_CMD_NUMBER;
      break;
    case 71:
      rc = ERROR_DATASIZE;
      break;
    case 72:
      rc = ERROR_BUFF_FLAG;
      break;
    case 129:
      rc = ERROR_FPGA_INTERNAL;
      break;
    case 130:
      rc = ERROR_FPGA_TIMEOUT;
      break;
    default:
      break;
  }
  return rc;
}

/*
 * Function     : open_dev
 * Description  : used to open FPGA driver
 * Para         :
 * 	 dev_num    : the number of xdma_dev,  0 t0 7
 * Return:
 *   0          : SUCCESS
 *   other      : FAILURE, refer to Error Id.
 */
int open_dev(int *userfd, int *h2cfd, int *c2hfd, uint8_t dev_num) {
  char *xdma_num = NULL;
  int num = 255;
  const char *xdma_dev = "XDMA_DEV";

  xdma_num = getenv(xdma_dev);
  if (xdma_num != NULL) num = atoi(xdma_num);

  int user_fd;
  int h2c_fd;
  int c2h_fd;

  int fpga_id = (num <= dev_num ? num : dev_num);
  fpga_id = fpga_id < MAX_NUM_OF_DEV ? fpga_id : 0;
  user_fd = open(DEV_USER[fpga_id], O_RDWR | O_SYNC);
  if (user_fd == -1) {
    fprintf(stderr, "unable to open dev %s, user_fd: %d, errno: %d.\n",
            DEV_USER[fpga_id], user_fd, errno);
    return ERROR_OPEN_DRIVER;
  }
  h2c_fd = open(DEV_H2C[fpga_id][0], O_RDWR);
  if (h2c_fd == -1) {
    fprintf(stderr, "unable to open dev %s, h2c_fd: %d, errno: %d.\n",
            DEV_H2C[fpga_id][0], h2c_fd, errno);
    return ERROR_OPEN_DRIVER;
  }
  c2h_fd = open(DEV_C2H[fpga_id][0], O_RDWR | O_NONBLOCK);
  if (c2h_fd == -1) {
    fprintf(stderr, "unable to open dev %s, c2h_fd: %d, errno: %d.\n",
            DEV_C2H[fpga_id][0], c2h_fd, errno);
    return ERROR_OPEN_DRIVER;
  }

  *userfd = user_fd;
  *h2cfd = h2c_fd;
  *c2hfd = c2h_fd;
  return 0;
}

/*
 * Function     : close_dev
 * Description  : used to close FPGA driver
 * Para         :
 * 	 dev_num    : the number of xdma_dev,  0 to 7
 * Return:
 *   0          : SUCCESS
 *   other      : FAILURE, refer to Error Id.
 */
int close_dev(int userfd, int h2cfd, int c2hfd, uint8_t dev_num) {
  int rc;
  char *xdma_num = NULL;
  int num = 255;
  const char *xdma_dev = "XDMA_DEV";

  xdma_num = getenv(xdma_dev);
  if (xdma_num != NULL) num = atoi(xdma_num);

  int user_fd = userfd;
  int h2c_fd = h2cfd;
  int c2h_fd = c2hfd;

  int fpga_id = (num <= dev_num ? num : dev_num);
  fpga_id = fpga_id < MAX_NUM_OF_DEV ? fpga_id : 0;
  rc = close(user_fd);
  if (rc != 0) {
    fprintf(stderr, "unable to close dev %s, %d.\n", DEV_USER[fpga_id],
            user_fd);
    return ERROR_CLOSE_DRIVER;
  }
  rc = close(h2c_fd);
  if (rc != 0) {
    fprintf(stderr, "unable to close dev %s, %d.\n", DEV_C2H[fpga_id][0],
            h2c_fd);
    return ERROR_CLOSE_DRIVER;
  }
  rc = close(c2h_fd);
  if (rc != 0) {
    fprintf(stderr, "unable to close dev %s, %d.\n", DEV_H2C[fpga_id][0],
            c2h_fd);
    return ERROR_CLOSE_DRIVER;
  }

  return 0;
}

/*
 * Function     : fpga_dev_number_get
 * Description  : used to get the numbers of dev
 * Para         : no para
 * Return:
 *   0          : the numbers of xdma_dev
 */
int fpga_dev_number_get() {
  int xdma_num = 0;
  int user_fd = 0;
  int rc = 0;
  uint32_t name = 3402287818;
  for (uint32_t i = 0; i < MAX_NUM_OF_DEV; i++) {
    rc = open_user_fd(&user_fd, i);
    if (rc != 0) {
      return xdma_num;
    }

    char *map_base = static_cast<char *>(
        mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, user_fd, 0));
    if (map_base == (void *)-1) {
      close_user_fd(user_fd, i);
      exit(1);
    }
    uint32_t vendor_id = reg32_read(map_base);
    if (vendor_id == name) {
      xdma_num++;
    }

    if (munmap(map_base, MAP_SIZE) == -1) {
      exit(1);
    }
    rc = close_user_fd(user_fd, i);
    if (rc != 0) {
      exit(1);
    }
  }

  return xdma_num;
}

// Try to open xdmaX_user
int open_user_fd(int *userfd, uint8_t dev_num) {
  int fpga_id = dev_num;
  int user_fd = open(DEV_USER[fpga_id], O_RDWR | O_SYNC);
  if (user_fd == -1) {
    return ERROR_OPEN_DRIVER;
  }

  *userfd = user_fd;
  return 0;
}

// Close xdmaX_user
int close_user_fd(int user_fd, uint8_t dev_num) {
  int fpga_id = dev_num;
  int rc = close(user_fd);
  if (rc != 0) {
    fprintf(stderr, "unable to close dev %s, %d.\n", DEV_USER[fpga_id],
            user_fd);
    return ERROR_CLOSE_DRIVER;
  }

  return 0;
}

/*
 * Function    : fpga_fedai_operator_accl
 * Description : used to achieve Modexp_Multifunc accleration in FPGA, including
 * handshake between FPGA and HOST, register configuration, data transfer,
 * Modexp_Multifunc accleration, etc. Para: cfg       : Configuration
 * Information para      : ModexpMultifunc's para to FPGA data1     :
 * ModexpMultifunc's data1 to FPGA data2     : ModexpMultifunc's data1 to FPGA
 *   data3     : ModexpMultifunc's data1 to FPGA
 *   result    : ModexpMultifunc's result from FPGA
 * Return:
 *   0         : SUCCESS
 *   other     : FAILURE, refer to Error Id.
 */
int fpga_fedai_operator_accl(fpga_config *cfg, char *para, char *data1,
                             char *data2, char *data3, char *result) {
#ifdef TASK_DEBUG
  printf("task id inside are %d, %d, %d\n", cfg->data1_memtype,
         cfg->data2_memtype, cfg->data3_memtype);
#endif
  long long rc;
  // uint32_t para_length, data1_length, data2_length, data3_length;
  // uint32_t dev_num = cfg->fpga_dev_id >= 0 ? cfg->fpga_dev_id : 255; //
  // Ooops: fpga_dev_id(uint8_t) always >= 0
  uint32_t dev_num = cfg->fpga_dev_id;
  uint8_t n_parity;
  uint32_t task_id = 0;
  int fpga_id = 0;
  uint32_t i = 0;
  uint32_t j = 0;
  uint32_t k = 0;
  /*************************************************************************\
  |*************Check whether parameters follow the regulations*************|
  \*************************************************************************/
  // Check whether bitlengths are supported
  if (cfg->para_bitlen == 0x8) {
    fprintf(stderr,
            "***** invalid data0_length, only supports 0, 128, 256, 512, 768, "
            "1024, 2048, 3072, 4096\n");
    return ERROR_LENGTH;
  } else if (cfg->data1_bitlen == 0x8) {
    fprintf(stderr,
            "***** invalid data1_length, only supports 0, 128, 256, 512, 768, "
            "1024, 2048, 3072, 4096\n");
    return ERROR_LENGTH;
  } else if (cfg->data2_bitlen == 0x8) {
    fprintf(stderr,
            "***** invalid data2_length, only supports 0, 128, 256, 512, 768, "
            "1024, 2048, 3072, 4096\n");
    return ERROR_LENGTH;
  } else if (cfg->data3_bitlen == 0x8) {
    fprintf(stderr,
            "***** invalid data3_length, only supports 0, 128, 256, 512, 768, "
            "1024, 2048, 3072, 4096\n");
    return ERROR_LENGTH;
  }

  // Check whether para N is even
  if (cfg->operate_mode != 9) {
    memcpy(&n_parity, para, 1);
    n_parity &= 0x1;
    if (n_parity == 0) {
      fprintf(stderr, "***** Even modulus is not supported.\n");
      return ERROR_EVEN;
    }
  } else {
    memcpy(&n_parity, para + 256 / 8, 1);
    n_parity &= 0x1;
    if (n_parity == 0) {
      fprintf(stderr, "***** Even modulus is not supported.\n");
      return ERROR_EVEN;
    }
  }

  // Check whether operate_mode is supported
  if (cfg->operate_mode > 16 || cfg->operate_mode < 1) {
    fprintf(stderr, "***** Unsupported operate mode.\n");
    return ERROR_OPERATEMODE;
  }

  // Check whether batch_size is supported
  if ((cfg->batch_size == static_cast<size_t>(-1)) || (cfg->batch_size == 0)) {
    fprintf(stderr, "***** Data's batch size must be assigned.\n");
    return ERROR_BATCHSIZE;
  }

  // Check whether memtype of result is supported
  if ((cfg->result_memtype == 0 && result == NULL) ||
      (cfg->result_memtype != 0 &&
       (cfg->result_memtype < 128 || cfg->result_memtype > (128 + 15))) ||
      (cfg->result_memtype != 0 &&
       (cfg->result_memtype == cfg->data1_memtype ||
        cfg->result_memtype == cfg->data1_memtype ||
        cfg->result_memtype == cfg->data3_memtype))) {
    fprintf(stderr, "***** Unsupported memtype of result data.\n");
    return ERROR_RES_MEMTYPE;
  }

  // Check whether memtypes of inputdata are supported
  rc = 0;
  switch (cfg->operate_mode) {
    case 1:
    case 3:
    case 10:
    case 13:
    case 14:
    case 15:
    case 16:
      if (cfg->data1_memtype == 255 ||
          (cfg->data1_memtype == 0 && data1 == NULL) ||
          cfg->data2_memtype != 255 || cfg->data3_memtype != 255)
        rc = ERROR_DATA_MEMTYPE;
      break;
    case 2:
    case 7:
    case 8:
    case 9:
    case 12:
      if (cfg->data1_memtype == 255 ||
          (cfg->data1_memtype == 0 && data1 == NULL) ||
          cfg->data2_memtype == 255 ||
          (cfg->data2_memtype == 0 && data2 == NULL) ||
          cfg->data3_memtype != 255)
        rc = ERROR_DATA_MEMTYPE;
      break;
    case 4:
    case 5:
      if (cfg->data1_memtype == 255 ||
          (cfg->data1_memtype == 0 && data1 == NULL) ||
          cfg->data3_memtype == 255 ||
          (cfg->data3_memtype == 0 && data3 == NULL) ||
          cfg->data2_memtype != 255)
        rc = ERROR_DATA_MEMTYPE;
      break;
    case 6:
      if (cfg->data1_memtype == 255 ||
          (cfg->data1_memtype == 0 && data1 == NULL) ||
          cfg->data2_memtype == 255 ||
          (cfg->data2_memtype == 0 && data2 == NULL) ||
          cfg->data3_memtype == 255 ||
          (cfg->data3_memtype == 0 && data3 == NULL))
        rc = ERROR_DATA_MEMTYPE;
      break;
    case 11:
      if (cfg->data2_memtype == 255 ||
          (cfg->data2_memtype == 0 && data2 == NULL) ||
          cfg->data1_memtype != 255 || cfg->data3_memtype != 255)
        rc = ERROR_DATA_MEMTYPE;
      break;
    default:
      break;
  }
  if (rc != 0) {
    fprintf(stderr,
            "***** Memtypes of Input data do not match operate mode.\n");
    return rc;
  }

  // Mapping driver files
  int userfd[100], h2cfd[100], c2hfd[100];
  int user_fd, h2c_fd, c2h_fd;
  char *map_base = 0;
  uint32_t memory_total_size[MAX_NUM_OF_DEV] = {0};
  uint32_t task_busy_counts[MAX_NUM_OF_DEV] = {0};
  uint32_t min_busy_counts = 0;
  uint32_t task_space_size[MAX_NUM_OF_DEV] = {0};
  uint32_t taskid_counts[MAX_NUM_OF_DEV] = {0};
  uint32_t matched_deviceid[MAX_NUM_OF_DEV + 1] = {0};
  uint32_t device_verify_state[MAX_NUM_OF_DEV] = {0};
  uint32_t matched_deviceid_count = 0;
  uint32_t task_launch_flag, srcdata_vld_flag, backdata_vld_flag,
      result_buffer_flag;
  struct fpga_modexp_task *task;
  void *task_busy_count;
  void *device_memory_size;
  void *device_task_space_size;
#ifdef MULTI_CARD_DEBUG
  fprintf(stdout, "driver.c dev_num = %d\n", dev_num);
#endif
  if (dev_num >= 128 && dev_num <= 135) {
    rc = open_dev(&userfd[0], &h2cfd[0], &c2hfd[0], 0);
    fpga_id = dev_num - 128;
    user_fd = userfd[0];
    h2c_fd = h2cfd[0];
    c2h_fd = c2hfd[0];
    task = (struct fpga_modexp_task *)malloc(sizeof(struct fpga_modexp_task));

    if (fpga_id != 0) {
      rc =
          open_dev(&userfd[fpga_id], &h2cfd[fpga_id], &c2hfd[fpga_id], fpga_id);
      map_base = static_cast<char *>(mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE,
                                          MAP_SHARED, userfd[fpga_id], 0));
      user_fd = userfd[fpga_id];
      h2c_fd = h2cfd[fpga_id];
      c2h_fd = c2hfd[fpga_id];
    } else
      map_base = static_cast<char *>(
          mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, userfd[0], 0));
#ifdef MULTI_CARD_DEBUG
    fprintf(stdout, "open device fpga_id %d ret %d\n", fpga_id, rc);
#endif
    if (rc != 0) {
      return rc;
    }
    flock(h2cfd[0], LOCK_EX);
  } else {
    rc = open_dev(&userfd[0], &h2cfd[0], &c2hfd[0], 0);
    // fprintf(stdout,"open device 0 ret %d\n",rc);
    dev_num = fpga_id;
    user_fd = userfd[fpga_id];
    h2c_fd = h2cfd[fpga_id];
    c2h_fd = c2hfd[fpga_id];
    if (rc != 0) {
      return rc;
    }

    task = (struct fpga_modexp_task *)malloc(sizeof(struct fpga_modexp_task));
    if ((cfg->data1_memtype <= (128 + 15) && cfg->data1_memtype >= 128) ||
        (cfg->data2_memtype <= (128 + 15) && cfg->data2_memtype >= 128) ||
        (cfg->data3_memtype <= (128 + 15) && cfg->data3_memtype >= 128) ||
        (cfg->result_memtype <= (128 + 15) && cfg->result_memtype >= 128)) {
      char *buffer_data_info;
      uint64_t addr_base, bit_width_check = 0, batch_size_check = 0;
      buffer_data_info = (char *)malloc(BACKDATA_INFO_SIZE * sizeof(char));

      // Check whether the input numbers are buffered in FPGA and whether their
      // information matches cfg
      uint8_t memtype_check[3], bitlen_check[3];
      memtype_check[0] = cfg->data1_memtype;
      memtype_check[1] = cfg->data2_memtype;
      memtype_check[2] = cfg->data3_memtype;
      bitlen_check[0] = cfg->data1_bitlen;
      bitlen_check[1] = cfg->data2_bitlen;
      bitlen_check[2] = cfg->data3_bitlen;
      map_base = static_cast<char *>(
          mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, userfd[0], 0));
      if (map_base == (void *)-1) {
        exit(1);
      }
      for (i = 0; i < 3; i++) {
        if (memtype_check[i] <= (128 + 15) && memtype_check[i] >= 128) {
          init_task(map_base, task, memtype_check[i] - 128);

          task_launch_flag = get_status(task->task_state_addr, 0);
          srcdata_vld_flag = get_status(task->srcdata_state_addr, 0);
          backdata_vld_flag = get_status(task->backdata_state_addr, 0);
          result_buffer_flag = get_status(task->result_buffer_state_addr, 0);

          if (backdata_vld_flag != 1 || result_buffer_flag != 1 ||
              task_launch_flag == 1 || srcdata_vld_flag == 1) {
            rc = ERROR_SRCDAT_BUFSTATE;
            fprintf(stderr,
                    "***** No input data buffered in the given task id.\n");
            free(buffer_data_info);
            free_task(task);
            close_dev(userfd[0], h2cfd[0], c2hfd[0], dev_num);
            if (munmap(map_base, MAP_SIZE) == -1) {
              exit(1);
            }
            return rc;
          }
          addr_base =
              DDR1_BASE_ADDR + (memtype_check[i] - 128) * 1024 * 1024 * 1024llu;
          bit_width_check = 0;
          batch_size_check = 0;

          flock(c2hfd[0], LOCK_EX);
          transfer_from_fpga(DEV_C2H[fpga_id][0], c2hfd[0], buffer_data_info,
                             BACKDATA_INFO_SIZE, addr_base);
          flock(c2hfd[0], LOCK_UN);
          memcpy(&bit_width_check, buffer_data_info, 2);
          bit_width_check = (bit_width_check & 0xF00) >> 8;
          memcpy(&batch_size_check, buffer_data_info + 2, 8);
          batch_size_check = (batch_size_check & 0xFFFFFFFF0000000) >> 28;

          if (bit_width_check != bitlen_check[i] ||
              batch_size_check != cfg->batch_size) {
            rc = ERROR_SRCDAT_BUFINFO;
            fprintf(stderr,
                    "***** Information buffered in FPGA contradicts cfg of "
                    "input data%d.\n",
                    i + 1);

            free(buffer_data_info);
            free_task(task);
            close_dev(userfd[0], h2cfd[0], c2hfd[0], dev_num);
            if (munmap(map_base, MAP_SIZE) == -1) {
              exit(1);
            }
            return rc;
          }
        }
      }
      free(buffer_data_info);
    } else {
      /*************************************************************************\
      |***************************Distribute fpga
      id****************************|
      \*************************************************************************/
      int fpga_count = 0;
#define DEVICE_MEMORY_ADDR 0x10
      fpga_count = fpga_dev_number_get();
#ifdef TASK_DEBUG
      printf("fpga_count = %d\n", fpga_count);
      fprintf(stdout, "cfg->task_space_size_req = %d\n",
              cfg->task_space_size_req);
#endif
      // Mapping driver files
      for (i = 1; static_cast<int>(i) < fpga_count; ++i) {
        rc = open_dev(&userfd[i], &h2cfd[i], &c2hfd[i], i);
        if (rc != 0) {
          return rc;
        }
      }
      flock(h2cfd[0], LOCK_EX);

      for (i = 0; static_cast<int>(i) < fpga_count; ++i) {
        map_base = static_cast<char *>(mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE,
                                            MAP_SHARED, userfd[i], 0));
        if (map_base == (void *)-1) {
          flock(h2cfd[0], LOCK_UN);
          exit(1);
        }
        task_busy_count = map_base + TASK_BUSY_COUNT_ADDR;
        device_memory_size = map_base + DEVICE_MEMORY_ADDR;
        device_task_space_size = map_base + TASK_SPACE_SIZE_CONFIG;
        task_busy_counts[i] = reg32_read(task_busy_count);
        // fprintf(stdout,"task_busy_counts %d, i %d\n",task_busy_counts[i],i);
        memory_total_size[i] = reg32_read(device_memory_size);
        task_space_size[i] = reg32_read(device_task_space_size);
        device_verify_state[i] = reg32_read(map_base + 0x60);

        if (task_space_size[i] <= 1024)
          taskid_counts[i] = 16;
        else if (task_space_size[i] == 2048)
          taskid_counts[i] = 8;
        else if (task_space_size[i] == 4096)
          taskid_counts[i] = 4;

        if (task_space_size[i] == cfg->task_space_size_req) {
          matched_deviceid[matched_deviceid_count] = i;
          matched_deviceid_count++;
        }
        if (munmap(map_base, MAP_SIZE) == -1) {
          flock(h2cfd[0], LOCK_UN);
          exit(1);
        }
      }
      if (matched_deviceid_count == 0) {
        rc = ERROR_NODEVICE_SPACESIZE_MATCHED;
        flock(h2cfd[0], LOCK_UN);
        for (j = 0; static_cast<int>(j) < fpga_count; j++) {
          close_dev(userfd[j], h2cfd[j], c2hfd[j], j);
        }
        return rc;
      } else if (matched_deviceid_count == 1) {
        uint32_t dev_task_busy_count = 0;
        uint32_t dev_taskid_count = 0;
        fpga_id = matched_deviceid[0];
        dev_taskid_count = taskid_counts[fpga_id];
        dev_task_busy_count = task_busy_counts[fpga_id];
        if (dev_task_busy_count < dev_taskid_count) {
          for (k = 0; static_cast<int>(k) < fpga_count; k++) {
            if (k != 0) close_dev(userfd[k], h2cfd[k], c2hfd[k], k);
          }
          map_base =
              static_cast<char *>(mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE,
                                       MAP_SHARED, userfd[fpga_id], 0));
          dev_num = fpga_id;
          user_fd = userfd[fpga_id];
          h2c_fd = h2cfd[fpga_id];
          c2h_fd = c2hfd[fpga_id];
#ifdef TASK_DEBUG
          fprintf(stdout, "the chosen fpga_id is %d dev_num is %d\n", fpga_id,
                  dev_num);
#endif
        } else {
          uint8_t poll_flag = 0;
          map_base =
              static_cast<char *>(mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE,
                                       MAP_SHARED, userfd[fpga_id], 0));
          do {
            uint32_t dev_task_busy_count = 0;
            task_busy_count = map_base + TASK_BUSY_COUNT_ADDR;
            dev_task_busy_count = reg32_read(task_busy_count);

            if (dev_task_busy_count < dev_taskid_count) {
              poll_flag = 0;
              for (k = 0; static_cast<int>(k) < fpga_count; k++) {
                if (k != 0) close_dev(userfd[k], h2cfd[k], c2hfd[k], k);
              }
              dev_num = fpga_id;
              user_fd = userfd[fpga_id];
              h2c_fd = h2cfd[fpga_id];
              c2h_fd = c2hfd[fpga_id];
            } else {
              fprintf(stdout, "test10: task_busy_count %d\n",
                      dev_task_busy_count);
              usleep(1000);
              poll_flag = 1;
            }
          } while (poll_flag);
        }
      } else {
        min_busy_counts = taskid_counts[matched_deviceid[0]];
        for (i = 0; i < matched_deviceid_count; ++i) {
#ifdef TASK_DEBUG
          fprintf(stdout, "dev_id %d busy_counts %d\n", i, task_busy_counts);
#endif
          if (task_busy_counts[matched_deviceid[i]] == 0) {
            fpga_id = matched_deviceid[i];
            break;
          } else if (task_busy_counts[matched_deviceid[i]] < min_busy_counts) {
            min_busy_counts = task_busy_counts[matched_deviceid[i]];
          }

          if (min_busy_counts == taskid_counts[matched_deviceid[0]]) {
            uint8_t poll_flag = 0;
            uint32_t dev_taskid_count = taskid_counts[matched_deviceid[0]];

            do {
              for (i = 0; i < matched_deviceid_count; i++) {
                map_base = static_cast<char *>(
                    mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
                         userfd[matched_deviceid[i]], 0));
                uint32_t dev_task_busy_count = 0;
                task_busy_count = map_base + TASK_BUSY_COUNT_ADDR;
                dev_task_busy_count = reg32_read(task_busy_count);

                if (dev_task_busy_count < dev_taskid_count) {
                  poll_flag = 0;
                  fpga_id = matched_deviceid[i];
                  dev_num = fpga_id;
                  user_fd = userfd[fpga_id];
                  h2c_fd = h2cfd[fpga_id];
                  c2h_fd = c2hfd[fpga_id];
                  break;
                } else {
                  usleep(1000);
                  poll_flag = 1;
                }
                if (munmap(map_base, MAP_SIZE) == -1) {
                  flock(h2cfd[0], LOCK_UN);
                  exit(1);
                }
              }
            } while (poll_flag);

            map_base =
                static_cast<char *>(mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE,
                                         MAP_SHARED, userfd[fpga_id], 0));
          }
        }

        for (i = 0; static_cast<int>(i) < fpga_count; i++) {
          if (i != 0 && static_cast<int>(i) != fpga_id)
            close_dev(userfd[i], h2cfd[i], c2hfd[i], i);
        }
        map_base = static_cast<char *>(mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE,
                                            MAP_SHARED, userfd[fpga_id], 0));
        dev_num = fpga_id;
        user_fd = userfd[fpga_id];
        h2c_fd = h2cfd[fpga_id];
        c2h_fd = c2hfd[fpga_id];
#ifdef TASK_DEBUG
        fprintf(stdout, "the chosen fpga_id is %d dev_num is %d\n", fpga_id,
                dev_num);
#endif
      }

      if (device_verify_state[fpga_id] == 0) {
        fprintf(stderr, "***** The matched_Device is not verified\n");
        return ERROR_FPGA_LICENSE;
      }
      // Check whether data_size is supported
      unsigned long long max_task_memspace = 0;
      max_task_memspace = memory_total_size[fpga_id] / taskid_counts[fpga_id] *
                              1024 * 1024 * 1024 -
                          16 * 1024;
      // fprintf(stdout,"cmd_size %ld, para_size %ld, data_size %ld, total_size
      // %ld, max_task_space %ld\n",16*1024,cfg->para_data_size,
      // cfg->data1_size,16*1024+cfg->para_data_size+cfg->data1_size,max_task_memspace+16*1024);
      if ((cfg->para_data_size + cfg->data1_size + cfg->data2_size +
           cfg->data3_size) >
          (max_task_memspace)) {  /////////!!!!!!!!MAX_MEMSPACE
        fprintf(stderr,
                "***** Input data size is larger than maximum storage size.\n");
        return ERROR_DATASIZE;
      }
    }
  }
  // debugcxd
  //  printf("3\n");
  //  printf("choosen fpga %d\n", fpga_id);
  /*************************************************************************\
  |************Set Registers according to bypass_computing mode*************|
  \*************************************************************************/
  // Set registers for bypass modes
  switch (cfg->operate_mode) {
    case 1:
    case 2:
    case 3:
    case 6:
    case 7:
    case 11:
    case 12:
    case 13:
    case 14:
    case 15:
      switch (cfg->bypass_computing) {
        case 0:
          reg32_write(user_fd, map_base + 0x40c00, 0x0);
          reg32_write(user_fd, map_base + 0x60c00, 0x0);
          reg32_write(user_fd, map_base + 0x80c00, 0x0);
          reg32_write(user_fd, map_base + 0xa0c00, 0x0);
          reg32_write(user_fd, map_base + 0x110000, 0x0);
          reg32_write(user_fd, map_base + 0xe0000, 0x0);
          reg32_write(user_fd, map_base + 0x20000, 0x0);
          reg32_write(user_fd, map_base + 0xf0000, 0x0);
          reg32_write(user_fd, map_base + 0x100000, 0x0);
          reg32_write(user_fd, map_base + 0x140000, 0x0);
          reg32_write(user_fd, map_base + 0x130000, 0x0);
          break;
        case 1:
          reg32_write(user_fd, map_base + 0x40c00, 0x1);
          reg32_write(user_fd, map_base + 0x60c00, 0x1);
          reg32_write(user_fd, map_base + 0x80c00, 0x1);
          reg32_write(user_fd, map_base + 0xa0c00, 0x1);
          break;
        default:
          printf("***** Invalid arguments bypass %d\n", cfg->bypass_computing);
          return ERROR_BYPASS;
      }
      break;
    case 4:
    case 5:
      switch (cfg->bypass_computing) {
        case 0:
          reg32_write(user_fd, map_base + 0x40c00, 0x0);
          reg32_write(user_fd, map_base + 0x60c00, 0x0);
          reg32_write(user_fd, map_base + 0x80c00, 0x0);
          reg32_write(user_fd, map_base + 0xa0c00, 0x0);
          reg32_write(user_fd, map_base + 0x110000, 0x0);
          reg32_write(user_fd, map_base + 0xe0000, 0x0);
          reg32_write(user_fd, map_base + 0x2e0000, 0x0);
          reg32_write(user_fd, map_base + 0xf0000, 0x0);
          reg32_write(user_fd, map_base + 0x100000, 0x0);
          reg32_write(user_fd, map_base + 0x140000, 0x0);
          reg32_write(user_fd, map_base + 0x130000, 0x0);
          break;
        case 1:
          reg32_write(user_fd, map_base + 0x40c00, 0x1);
          reg32_write(user_fd, map_base + 0x60c00, 0x1);
          reg32_write(user_fd, map_base + 0x80c00, 0x1);
          reg32_write(user_fd, map_base + 0xa0c00, 0x1);
          reg32_write(user_fd, map_base + 0x110000, 0x1);
          reg32_write(user_fd, map_base + 0xe0000, 0x1);
          reg32_write(user_fd, map_base + 0xf0000, 0x1);
          reg32_write(user_fd, map_base + 0x100000, 0x2);
          reg32_write(user_fd, map_base + 0x140000, 0x1);
          break;
        case 2:
          reg32_write(user_fd, map_base + 0x40c00, 0x1);
          reg32_write(user_fd, map_base + 0x60c00, 0x1);
          reg32_write(user_fd, map_base + 0x80c00, 0x1);
          reg32_write(user_fd, map_base + 0xa0c00, 0x1);
          reg32_write(user_fd, map_base + 0x110000, 0x0);
          reg32_write(user_fd, map_base + 0xe0000, 0x1);
          reg32_write(user_fd, map_base + 0xf0000, 0x1);
          reg32_write(user_fd, map_base + 0x100000, 0x1);
          reg32_write(user_fd, map_base + 0x140000, 0x1);
          break;
        case 3:
          reg32_write(user_fd, map_base + 0x40c00, 0x0);
          reg32_write(user_fd, map_base + 0x60c00, 0x0);
          reg32_write(user_fd, map_base + 0x80c00, 0x0);
          reg32_write(user_fd, map_base + 0xa0c00, 0x0);
          reg32_write(user_fd, map_base + 0x110000, 0x1);
          reg32_write(user_fd, map_base + 0xe0000, 0x1);
          reg32_write(user_fd, map_base + 0xf0000, 0x1);
          reg32_write(user_fd, map_base + 0x100000, 0x2);
          reg32_write(user_fd, map_base + 0x140000, 0x1);
          break;
        case 6:
          reg32_write(user_fd, map_base + 0x40c00, 0x0);
          reg32_write(user_fd, map_base + 0x60c00, 0x0);
          reg32_write(user_fd, map_base + 0x80c00, 0x0);
          reg32_write(user_fd, map_base + 0xa0c00, 0x0);
          reg32_write(user_fd, map_base + 0x110000, 0x0);
          reg32_write(user_fd, map_base + 0xe0000, 0x0);
          reg32_write(user_fd, map_base + 0xf0000, 0x0);
          reg32_write(user_fd, map_base + 0x100000, 0x3);
          reg32_write(user_fd, map_base + 0x140000, 0x1);
          break;
        default:
          printf("***** Invalid arguments bypass %d\n", cfg->bypass_computing);
          return ERROR_BYPASS;
      }
      break;
    case 8:
    case 9:
      switch (cfg->bypass_computing) {
        case 0:
          reg32_write(user_fd, map_base + 0x40c00, 0x0);
          reg32_write(user_fd, map_base + 0x60c00, 0x0);
          reg32_write(user_fd, map_base + 0x80c00, 0x0);
          reg32_write(user_fd, map_base + 0xa0c00, 0x0);
          reg32_write(user_fd, map_base + 0x110000, 0x0);
          reg32_write(user_fd, map_base + 0xe0000, 0x0);
          reg32_write(user_fd, map_base + 0x20000, 0x0);
          reg32_write(user_fd, map_base + 0xf0000, 0x0);
          reg32_write(user_fd, map_base + 0x100000, 0x0);
          reg32_write(user_fd, map_base + 0x140000, 0x0);
          reg32_write(user_fd, map_base + 0x130000, 0x0);
          break;
        case 1:
          reg32_write(user_fd, map_base + 0x40c00, 0x1);
          reg32_write(user_fd, map_base + 0x60c00, 0x1);
          reg32_write(user_fd, map_base + 0x80c00, 0x1);
          reg32_write(user_fd, map_base + 0xa0c00, 0x1);
          reg32_write(user_fd, map_base + 0x110000, 0x1);
          reg32_write(user_fd, map_base + 0xe0000, 0x1);
          reg32_write(user_fd, map_base + 0xf0000, 0x1);
          reg32_write(user_fd, map_base + 0x100000, 0x2);
          reg32_write(user_fd, map_base + 0x140000, 0x1);
          break;
        case 3:
          reg32_write(user_fd, map_base + 0x40c00, 0x0);
          reg32_write(user_fd, map_base + 0x60c00, 0x0);
          reg32_write(user_fd, map_base + 0x80c00, 0x0);
          reg32_write(user_fd, map_base + 0xa0c00, 0x0);
          reg32_write(user_fd, map_base + 0x110000, 0x1);
          reg32_write(user_fd, map_base + 0xe0000, 0x1);
          reg32_write(user_fd, map_base + 0xf0000, 0x1);
          reg32_write(user_fd, map_base + 0x100000, 0x2);
          reg32_write(user_fd, map_base + 0x140000, 0x1);
          break;
        default:
          printf("***** Invalid arguments bypass %d\n", cfg->bypass_computing);
          return ERROR_BYPASS;
      }
      break;
    case 16:
      switch (cfg->bypass_computing) {
        case 0:
          reg32_write(user_fd, map_base + 0x40c00, 0x0);
          reg32_write(user_fd, map_base + 0x60c00, 0x0);
          reg32_write(user_fd, map_base + 0x80c00, 0x0);
          reg32_write(user_fd, map_base + 0xa0c00, 0x0);
          reg32_write(user_fd, map_base + 0x110000, 0x0);
          reg32_write(user_fd, map_base + 0xe0000, 0x0);
          reg32_write(user_fd, map_base + 0x20000, 0x0);
          reg32_write(user_fd, map_base + 0xf0000, 0x0);
          reg32_write(user_fd, map_base + 0x100000, 0x0);
          reg32_write(user_fd, map_base + 0x140000, 0x0);
          reg32_write(user_fd, map_base + 0x130000, 0x0);
          break;
        case 1:
          reg32_write(user_fd, map_base + 0x40c00, 0x1);
          reg32_write(user_fd, map_base + 0x60c00, 0x1);
          reg32_write(user_fd, map_base + 0x80c00, 0x1);
          reg32_write(user_fd, map_base + 0xa0c00, 0x1);
          reg32_write(user_fd, map_base + 0x110000, 0x1);
          reg32_write(user_fd, map_base + 0xe0000, 0x1);
          reg32_write(user_fd, map_base + 0xf0000, 0x1);
          reg32_write(user_fd, map_base + 0x100000, 0x2);
          reg32_write(user_fd, map_base + 0x20000, 0x1);
          reg32_write(user_fd, map_base + 0x140000, 0x1);
          break;
        default:
          printf("***** Invalid arguments bypass %d\n", cfg->bypass_computing);
          return ERROR_BYPASS;
      }
      break;
    case 10:
      switch (cfg->bypass_computing) {
        case 0:
          reg32_write(user_fd, map_base + 0x40c00, 0x0);
          reg32_write(user_fd, map_base + 0x60c00, 0x0);
          reg32_write(user_fd, map_base + 0x80c00, 0x0);
          reg32_write(user_fd, map_base + 0xa0c00, 0x0);
          reg32_write(user_fd, map_base + 0x110000, 0x0);
          reg32_write(user_fd, map_base + 0xe0000, 0x0);
          reg32_write(user_fd, map_base + 0x20000, 0x0);
          reg32_write(user_fd, map_base + 0xf0000, 0x0);
          reg32_write(user_fd, map_base + 0x100000, 0x0);
          reg32_write(user_fd, map_base + 0x140000, 0x0);
          reg32_write(user_fd, map_base + 0x130000, 0x0);
          break;
        case 1:
          reg32_write(user_fd, map_base + 0x40c00, 0x1);
          reg32_write(user_fd, map_base + 0x60c00, 0x1);
          reg32_write(user_fd, map_base + 0x80c00, 0x1);
          reg32_write(user_fd, map_base + 0xa0c00, 0x1);
          reg32_write(user_fd, map_base + 0x110000, 0x2);
          reg32_write(user_fd, map_base + 0xe0000, 0x1);
          reg32_write(user_fd, map_base + 0x130000, 0x8);
          break;
        case 8:
          reg32_write(user_fd, map_base + 0x40c00, 0x0);
          reg32_write(user_fd, map_base + 0x60c00, 0x0);
          reg32_write(user_fd, map_base + 0x80c00, 0x0);
          reg32_write(user_fd, map_base + 0xa0c00, 0x0);
          reg32_write(user_fd, map_base + 0x110000, 0x0);
          reg32_write(user_fd, map_base + 0xe0000, 0x0);
          reg32_write(user_fd, map_base + 0x130000, 0x2);
          break;
        case 9:
          reg32_write(user_fd, map_base + 0x40c00, 0x0);
          reg32_write(user_fd, map_base + 0x60c00, 0x0);
          reg32_write(user_fd, map_base + 0x80c00, 0x0);
          reg32_write(user_fd, map_base + 0xa0c00, 0x0);
          reg32_write(user_fd, map_base + 0x110000, 0x0);
          reg32_write(user_fd, map_base + 0xe0000, 0x0);
          reg32_write(user_fd, map_base + 0x130000, 0x1);
          break;
        default:
          printf("***** Invalid arguments bypass %d\n", cfg->bypass_computing);
          return ERROR_BYPASS;
      }
      break;
    default:
      printf("***** Invalid arguments operate_mode %d\n", cfg->operate_mode);
      return ERROR_OPERATEMODE;
  }
#ifdef MULTI_CARD_DEBUG
  fprintf(stdout, "Distribute task id!!!  fpga_id = %d\n", fpga_id);
#endif
  /*************************************************************************\
  |***************************Distribute task id****************************|
  \*************************************************************************/
  uint8_t flag = 1;
  size_t poll_num = 0;
  uint32_t error_flag = 0;
  void *sys_process_err_addr;
  sys_process_err_addr = map_base + SYS_PROCESS_ERR_ADDR;

  task_id = 0;
  if (cfg->result_memtype ==
      0) {  // Poll to distribute a task id for current work
    poll_num = 0;
    do {
      if (poll_num * 50 > maximum_time) {
        rc = ERROR_TIMEOUT_MAX;
        flock(h2cfd[0], LOCK_UN);
        free_task(task);
        if (fpga_id != 0) {
          close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
          close_dev(userfd[0], h2cfd[0], c2hfd[0], 0);
        } else
          close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
        if (munmap(map_base, MAP_SIZE) == -1) {
          exit(1);
        }
        return rc;
      }

#ifdef MULTI_DEBUG
      error_flag = reg32_read(sys_process_err_addr);
      error_flag &= 0x3;
      if (error_flag != 0) {
        flock(h2cfd[0], LOCK_UN);
        free_task(task);
        if (fpga_id != 0) {
          close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
          close_dev(userfd[0], h2cfd[0], c2hfd[0], 0);
        } else
          close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
        if (munmap(map_base, MAP_SIZE) == -1) {
          exit(1);
        }
        if (error_flag == 1) {
          fprintf(stdout, "Time out 1 error detected by FPGA\n");
          rc = ERROR_FPGA_TIMEOUT;
        } else {
          fprintf(stdout, "FPGA internal 1 error detected.\n");
          rc = ERROR_FPGA_INTERNAL;
        }
        return rc;
      }
#endif
      init_task(map_base, task, task_id);
      task_launch_flag = get_status(task->task_state_addr, 0);
      srcdata_vld_flag = get_status(task->srcdata_state_addr, 0);
      backdata_vld_flag = get_status(task->backdata_state_addr, 0);
      result_buffer_flag = get_status(task->result_buffer_state_addr, 0);
      if (task_launch_flag || srcdata_vld_flag || backdata_vld_flag ||
          result_buffer_flag) {
        usleep(50);
        task_id = (task_id + 1) % TASK_NUM;
        poll_num++;
      } else {
        flag = 0;
      }
    } while (flag);
  } else {  // Task id is already distributed, just check the status of
            // registers of this task id
    task_id = cfg->result_memtype - 128;
    init_task(map_base, task, task_id);
    task_launch_flag = get_status(task->task_state_addr, 0);
    srcdata_vld_flag = get_status(task->srcdata_state_addr, 0);
    backdata_vld_flag = get_status(task->backdata_state_addr, 0);
    result_buffer_flag = get_status(task->result_buffer_state_addr, 0);
    if (task_launch_flag == 1 || srcdata_vld_flag == 1 ||
        backdata_vld_flag == 1 || result_buffer_flag == 0) {
      rc = ERROR_RES_MEMTYPE;
      flock(h2cfd[0], LOCK_UN);
      free_task(task);
      if (fpga_id != 0) {
        if (dev_num >= 128 && dev_num <= 135) {
          close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
        } else {
          close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
          close_dev(userfd[0], h2cfd[0], c2hfd[0], 0);
        }
      } else
        close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
      if (munmap(map_base, MAP_SIZE) == -1) {
        exit(1);
      }
      return rc;
    }
  }
  // fprintf(stdout,"TASK ID %d\n",task_id);

  /*************************************************************************\
  |***********************Construct the parameter cmd***********************|
  \*************************************************************************/
  uint64_t cmd_data_base = task_id * 1024 * 1024 * 1024llu;
  uint64_t para_data_base = cmd_data_base + CMD_ADDR_LEN;
  uint64_t data_base_offset =
      para_data_base + cfg->para_data_size;  ////////!!!!!!!!!
  if (data_base_offset % 64 != 0) {
    data_base_offset = (data_base_offset / 64 + 1) * 64;
  }
  // uint64_t data_base_offset = para_data_base + cfg->para_data_size;
  uint64_t data1_base = data_base_offset, data2_base = data_base_offset,
           data3_base = data_base_offset;
  if (cfg->data1_memtype == 0) {
    data1_base = data_base_offset;
    data_base_offset += cfg->data1_size;
  } else if (cfg->data1_memtype >= 128 && cfg->data1_memtype <= (128 + 15)) {
    data1_base = DDR1_BASE_ADDR + BACKDATA_INFO_SIZE +
                 (cfg->data1_memtype - 128) * 1024 * 1024 * 1024llu;
  }
  if (data_base_offset % 64 != 0) {
    data_base_offset = (data_base_offset / 64 + 1) * 64;
  }

  if (cfg->data2_memtype == 0) {
    data2_base = data_base_offset;
    data_base_offset += cfg->data2_size;
  } else if (cfg->data2_memtype >= 128 && cfg->data2_memtype <= (128 + 15)) {
    data2_base = DDR1_BASE_ADDR + BACKDATA_INFO_SIZE +
                 (cfg->data2_memtype - 128) * 1024 * 1024 * 1024llu;
  }
  if (data_base_offset % 64 != 0) {
    data_base_offset = (data_base_offset / 64 + 1) * 64;
  }

  if (cfg->data3_memtype == 0) {
    data3_base = data_base_offset;
  } else if (cfg->data3_memtype >= 128 && cfg->data3_memtype <= (128 + 15)) {
    data3_base = DDR1_BASE_ADDR + BACKDATA_INFO_SIZE +
                 (cfg->data3_memtype - 128) * 1024 * 1024 * 1024llu;
  }

  uint32_t para_data_base_L = para_data_base & 0xFFFFFFFF;
  uint32_t para_data_base_H = para_data_base >> 32;
  uint32_t data1_base_L = data1_base & 0xFFFFFFFF;
  uint32_t data1_base_H = data1_base >> 32;
  uint32_t data2_base_L = data2_base & 0xFFFFFFFF;
  uint32_t data2_base_H = data2_base >> 32;
  uint32_t data3_base_L = data3_base & 0xFFFFFFFF;
  uint32_t data3_base_H = data3_base >> 32;
  uint32_t src_buffer_flag = 0;
  if (cfg->data1_memtype <= (128 + 15) && cfg->data1_memtype >= 128)
    src_buffer_flag = src_buffer_flag | 1;
  if (cfg->data2_memtype <= (128 + 15) && cfg->data2_memtype >= 128)
    src_buffer_flag = src_buffer_flag | 2;
  if (cfg->data3_memtype <= (128 + 15) && cfg->data3_memtype >= 128)
    src_buffer_flag = src_buffer_flag | 4;
  if (cfg->srcdata_buf_hold) src_buffer_flag = src_buffer_flag | 8;
#ifdef MULTI_CARD_DEBUG
  fprintf(stdout, "data1bitlen %d, data2bitlen %d, data3bitlen %d\n",
          cfg->data1_bitlen, cfg->data2_bitlen, cfg->data3_bitlen);
#endif
  uint32_t task_config = (0x0 << 28) | ((cfg->data3_bitlen & 0xF) << 24) |
                         ((cfg->data2_bitlen & 0xF) << 20) |
                         ((cfg->data1_bitlen & 0xF) << 16) |
                         ((cfg->para_bitlen & 0xF) << 12) |
                         ((task_id & 0xF) << 8) | (cfg->operate_mode & 0xFF);
  uint32_t cmd_data_size = 0;
  // uint32_t cmd_data_size = CMD_ADDR_LEN;
  uint32_t cmd_num = 0;
  uint32_t cmd_id = 0;
  char *cmd;
  if (cfg->operate_mode == 16) {
    cmd_num = 19;
    cmd_data_size = (32 * 39) / 8;
  } else {
    cmd_num = 17;
    cmd_data_size = (32 * 35) / 8;
  }

  rc = posix_memalign((void **)&cmd, 4096,
                      (sizeof(char) * cmd_data_size) + 4096);
  if (rc != 0) {
    flock(h2cfd[0], LOCK_UN);
    free_task(task);
    if (fpga_id != 0) {
      close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
      close_dev(userfd[0], h2cfd[0], c2hfd[0], 0);
    } else
      close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
    if (munmap(map_base, MAP_SIZE) == -1) {
      exit(1);
    }
    return rc;
  }
#ifdef MULTI_CARD_DEBUG
  fprintf(stdout, "fpgaid = %d,  cfg->batch_size = %d\n", fpga_id,
          cfg->batch_size);
#endif
  memset(cmd, 0, cmd_data_size);
  memcpy(cmd, &cmd_num, 4);
#ifdef MULTI_CARD_DEBUG
  fprintf(stdout, "cmd_num = 0x%x\n", cmd_num);
#endif
  cmd_id = 0;
  memcpy(cmd + 4, &cmd_id, 4);
  memcpy(cmd + 8, &task_config, 4);
#ifdef MULTI_CARD_DEBUG
  fprintf(stdout, "cmd_id = 0x%x, task_config = 0x%x\n", cmd_id, task_config);
#endif
  cmd_id = 1;
  memcpy(cmd + 12, &cmd_id, 4);
  memcpy(cmd + 16, &src_buffer_flag, 4);
#ifdef MULTI_CARD_DEBUG
  fprintf(stdout, "cmd_id = 0x%x, src_buffer_flag = 0x%x\n", cmd_id,
          src_buffer_flag);
#endif
  cmd_id = 2;
  memcpy(cmd + 20, &cmd_id, 4);
  memcpy(cmd + 24, &(cfg->batch_size), 4);
#ifdef MULTI_CARD_DEBUG
  fprintf(stdout, "cmd_id = 0x%x, cfg->batch_size = 0x%x\n", cmd_id,
          cfg->batch_size);
#endif
  cmd_id = 3;
  memcpy(cmd + 28, &cmd_id, 4);
  memset(cmd + 32, 0, 4);
#ifdef MULTI_CARD_DEBUG
  fprintf(stdout, "cmd_id = 0x%x, batch_id = 0x%x\n", cmd_id, 0);
#endif
  cmd_id = 4;
  memcpy(cmd + 36, &cmd_id, 4);
  memcpy(cmd + 40, &para_data_base_L, 4);
#ifdef MULTI_CARD_DEBUG
  fprintf(stdout, "cmd_id = 0x%x, para_data_base_L = 0x%x\n", cmd_id,
          para_data_base_L);
#endif
  cmd_id = 5;
  memcpy(cmd + 44, &cmd_id, 4);
  memcpy(cmd + 48, &para_data_base_H, 4);
#ifdef MULTI_CARD_DEBUG
  fprintf(stdout, "cmd_id = 0x%x, para_data_base_H = 0x%x\n", cmd_id,
          para_data_base_H);
#endif
  cmd_id = 6;
  memcpy(cmd + 52, &cmd_id, 4);
  memcpy(cmd + 56, &(cfg->para_data_size), 4);
#ifdef MULTI_CARD_DEBUG
  fprintf(stdout, "cmd_id = 0x%x, cfg->para_data_size = 0x%x\n", cmd_id,
          cfg->para_data_size);
#endif
  cmd_id = 7;
  memcpy(cmd + 60, &cmd_id, 4);
  memcpy(cmd + 64, &data1_base_L, 4);
#ifdef MULTI_CARD_DEBUG
  fprintf(stdout, "cmd_id = 0x%x, data1_base_L = 0x%x\n", cmd_id, data1_base_L);
#endif
  cmd_id = 8;
  memcpy(cmd + 68, &cmd_id, 4);
  memcpy(cmd + 72, &data1_base_H, 4);
#ifdef MULTI_CARD_DEBUG
  fprintf(stdout, "cmd_id = 0x%x, data1_base_H = 0x%x\n", cmd_id, data1_base_H);
#endif
  cmd_id = 9;
  memcpy(cmd + 76, &cmd_id, 4);
  memcpy(cmd + 80, &(cfg->data1_size), 4);
#ifdef MULTI_CARD_DEBUG
  fprintf(stdout, "cmd_id = 0x%x, cfg->data1_size = 0x%x\n", cmd_id,
          cfg->data1_size);
#endif
  cmd_id = 10;
  memcpy(cmd + 84, &cmd_id, 4);
  memcpy(cmd + 88, &data2_base_L, 4);
#ifdef MULTI_CARD_DEBUG
  fprintf(stdout, "cmd_id = 0x%x, data2_base_L = 0x%x\n", cmd_id, data2_base_L);
#endif
  cmd_id = 11;
  memcpy(cmd + 92, &cmd_id, 4);
  memcpy(cmd + 96, &data2_base_H, 4);
#ifdef MULTI_CARD_DEBUG
  fprintf(stdout, "cmd_id = 0x%x, data2_base_H = 0x%x\n", cmd_id, data2_base_H);
#endif
  cmd_id = 12;
  memcpy(cmd + 100, &cmd_id, 4);
  memcpy(cmd + 104, &(cfg->data2_size), 4);
#ifdef MULTI_CARD_DEBUG
  fprintf(stdout, "cmd_id = 0x%x, cfg->data2_size = 0x%x\n", cmd_id,
          cfg->data2_size);
#endif
  cmd_id = 13;
  memcpy(cmd + 108, &cmd_id, 4);
  memcpy(cmd + 112, &data3_base_L, 4);
#ifdef MULTI_CARD_DEBUG
  fprintf(stdout, "cmd_id = 0x%x, data3_base_L = 0x%x\n", cmd_id, data3_base_L);
#endif
  cmd_id = 14;
  memcpy(cmd + 116, &cmd_id, 4);
  memcpy(cmd + 120, &data3_base_H, 4);
#ifdef MULTI_CARD_DEBUG
  fprintf(stdout, "cmd_id = 0x%x, data3_base_H = 0x%x\n", cmd_id, data3_base_H);
#endif
  cmd_id = 15;
  memcpy(cmd + 124, &cmd_id, 4);
  memcpy(cmd + 128, &(cfg->data3_size), 4);
#ifdef MULTI_CARD_DEBUG
  fprintf(stdout, "cmd_id = 0x%x, cfg->data3_size = 0x%x\n", cmd_id,
          cfg->data3_size);
#endif
  cmd_id = 16;
  memcpy(cmd + 132, &cmd_id, 4);
  memcpy(cmd + 136, &(cfg->task_space_size_req), 4);
#ifdef MULTI_CARD_DEBUG
  fprintf(stdout, "cmd_id = 0x%x, cfg->task_space_size_req = 0x%x\n", cmd_id,
          cfg->task_space_size_req);
#endif
  if (cfg->operate_mode == 16) {
    cmd_id = 17;
    memcpy(cmd + 140, &cmd_id, 4);
    memcpy(cmd + 144, &(cfg->pisum_cfg), 4);
    cmd_id = 18;
    memcpy(cmd + 148, &cmd_id, 4);
    memcpy(cmd + 152, &(cfg->pisum_block_num), 4);
  }

  /*************************************************************************\
  |**********************Sending cmd, para, data to FPGA********************|
  \*************************************************************************/
  gettimeofday(&fpgaid_time_point[fpga_id][4], NULL);
  gettimeofday(&time_point[4], NULL);
  // write cmd data to FPGA
#ifdef MULTI_CARD_DEBUG
  fprintf(stdout, "33333   dev_num = %d  fpga_id = %d\n", dev_num, fpga_id);
#endif
#ifdef DEBUG
  fprintf(stdout,
          "*****fpga_id %d CPU Transfer task cmd  to FPGA (Addr: 0x%08" PRIx64
          ", Data "
          "size: %d bytes).\n",
          fpga_id, cmd_data_base, cmd_data_size);
#endif
#ifdef MULTI_CARD_DEBUG
  showMemoryHex(cmd, cmd_data_size);
  printf("\n");
#endif
  rc = 0;
  rc = transfer_to_fpga(DEV_H2C[fpga_id][0], h2c_fd, cmd, cmd_data_size,
                        cmd_data_base);
  if (rc < 0) {
    fprintf(stderr, "***** ERROR happend during transfering cmd to FPGA.\n");
    free_task(task);
    free(cmd);
    flock(h2cfd[0], LOCK_UN);
    if (fpga_id != 0) {
      close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
      close_dev(userfd[0], h2cfd[0], c2hfd[0], 0);
    } else
      close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
    if (munmap(map_base, MAP_SIZE) == -1) {
      exit(1);
    }
    return ERROR_SEND_CMD;
  }
  free(cmd);

  // write para data to FPGA
#ifdef DEBUG
  fprintf(stdout,
          "***** CPU Transfer task para to FPGA (Addr: 0x%08" PRIx64
          ", Data size: %zu "
          "bytes).\n",
          para_data_base, cfg->para_data_size);
#endif
  rc = 0;
  rc = transfer_to_fpga(DEV_H2C[fpga_id][0], h2c_fd, para, cfg->para_data_size,
                        para_data_base);
  if (rc < 0) {
    fprintf(stderr, "***** ERROR happend during transfering para to FPGA.\n");
    free_task(task);
    flock(h2cfd[0], LOCK_UN);
    if (fpga_id != 0) {
      close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
      close_dev(userfd[0], h2cfd[0], c2hfd[0], 0);
    } else
      close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
    if (munmap(map_base, MAP_SIZE) == -1) {
      exit(1);
    }
    return ERROR_SEND_PARA;
  }

  // transfer data1 to FPGA
  if (cfg->data1_memtype == 0) {
#ifdef DEBUG
    fprintf(stdout,
            "***** CPU Transfer task data to FPGA (Addr: 0x%08" PRIx64
            ", Data size: "
            "%zu bytes).\n",
            data1_base, cfg->data1_size);
#endif
    rc = 0;
    rc = transfer_to_fpga(DEV_H2C[fpga_id][0], h2c_fd, data1, cfg->data1_size,
                          data1_base);
    if (rc < 0) {
      fprintf(stderr,
              "***** ERROR happend during transfering data1 to FPGA.\n");
      free_task(task);
      flock(h2cfd[0], LOCK_UN);
      if (fpga_id != 0) {
        close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
        close_dev(userfd[0], h2cfd[0], c2hfd[0], 0);
      } else
        close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
      if (munmap(map_base, MAP_SIZE) == -1) {
        exit(1);
      }
      return ERROR_SEND_DATA;
    }
  }
#ifdef MULTI_CARD_DEBUG
  showMemoryHex(data1, cfg->data1_size);
  printf("\n");
#endif

  if (cfg->data2_memtype == 0) {
#ifdef DEBUG
    fprintf(stdout,
            "***** CPU Transfer task data to FPGA (Addr: 0x%08" PRIx64
            ", Data size: "
            "%zu bytes).\n",
            data2_base, cfg->data2_size);
#endif
    rc = 0;
    rc = transfer_to_fpga(DEV_H2C[fpga_id][0], h2c_fd, data2, cfg->data2_size,
                          data2_base);
    if (rc < 0) {
      fprintf(stderr,
              "***** ERROR happend during transfering data2 to FPGA.\n");
      free_task(task);
      flock(h2cfd[0], LOCK_UN);
      if (fpga_id != 0) {
        close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
        close_dev(userfd[0], h2cfd[0], c2hfd[0], 0);
      } else
        close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
      if (munmap(map_base, MAP_SIZE) == -1) {
        exit(1);
      }
      return ERROR_SEND_DATA;
    }
  }
#ifdef MULTI_CARD_DEBUG
  showMemoryHex(data2, cfg->data2_size);
  printf("\n");
#endif

  if (cfg->data3_memtype == 0) {
#ifdef DEBUG
    fprintf(stdout,
            "***** CPU Transfer task data to FPGA (Addr: 0x%08" PRIx64
            ", Data size: "
            "%zu bytes).\n",
            data3_base, cfg->data3_size);
#endif
    rc = 0;
    rc = transfer_to_fpga(DEV_H2C[fpga_id][0], h2c_fd, data3, cfg->data3_size,
                          data3_base);
    if (rc < 0) {
      fprintf(stderr,
              "***** ERROR happend during transfering data3 to FPGA.\n");
      free_task(task);
      flock(h2cfd[0], LOCK_UN);
      if (fpga_id != 0) {
        close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
        close_dev(userfd[0], h2cfd[0], c2hfd[0], 0);
      } else
        close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
      if (munmap(map_base, MAP_SIZE) == -1) {
        exit(1);
      }
      return ERROR_SEND_DATA;
    }
  }
  gettimeofday(&fpgaid_time_point[fpga_id][5], NULL);
  gettimeofday(&time_point[5], NULL);

  // inform FPGA that source data available
  set_status(user_fd, task->srcdata_state_addr, 0);
  // launch this task
#ifdef DEBUG
  fprintf(stdout, "***** CPU Launch Task.\n");
#endif
  set_status(user_fd, task->task_state_addr, 0);

  gettimeofday(&fpgaid_time_point[fpga_id][6], NULL);
  // long double time_after = (fpgaid_time_point[fpga_id][6].tv_sec) * 1000.0 +
  // (fpgaid_time_point[fpga_id][6].tv_usec) / 1000.0;
  // fprintf(stdout,"fpga_id %d, After Send Time %16.4Lf
  // (ms)\n",fpga_id,time_after);
  gettimeofday(&time_point[6], NULL);
  // long double time_after_send = (time_point[6].tv_sec) * 1000.0 +
  // (time_point[6].tv_usec) / 1000.0;
  // fprintf(stdout,"fpga_id %d, After Send Time %16.4Lf
  // (ms)\n",fpga_id,time_after_send);
  flock(h2cfd[0], LOCK_UN);

#ifdef DEBUG
  fprintf(stdout, "\n***** FPGA start the Algorithm Accl\n");
#endif

  /*************************************************************************\
  |*****************Polling until FPGA finishes calculation*****************|
  \*************************************************************************/
  // poll task's status to know whether this task is finished
  if (cfg->bypass_computing == 1 || cfg->bypass_computing == 2) {
    usleep(500);
  }
  // debugcxd
  //  printf("7\n");
#ifdef DEBUG
  fprintf(stdout, "***** CPU Polling FPGA task's status.(Polling Gap: 50us)\n");
#endif
  uint32_t task_status;
  uint32_t task_error_id;
  // fprintf(stdout,"task_launch_flag\n");
  poll_num = 0;
  flag = 1;
  rc = 0;

#ifdef MULTI_DEBUG
  do {
    if (poll_num * 50 > maximum_time) {
      rc = ERROR_TIMEOUT_MAX;
      free_task(task);
      if (fpga_id != 0) {
        close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
        close_dev(userfd[0], h2cfd[0], c2hfd[0], 0);
      } else
        close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
      if (munmap(map_base, MAP_SIZE) == -1) {
        exit(1);
      }
      return rc;
    }

    error_flag = reg32_read(sys_process_err_addr);
    error_flag &= 0x3;
    if (error_flag != 0) {
      free_task(task);
      if (fpga_id != 0) {
        close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
        close_dev(userfd[0], h2cfd[0], c2hfd[0], 0);
      } else
        close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
      if (munmap(map_base, MAP_SIZE) == -1) {
        exit(1);
      }
      if (error_flag == 1) {
        fprintf(stdout, "Time out 2 error detected by FPGA\n");
        rc = ERROR_FPGA_TIMEOUT;
      } else {
        fprintf(stdout, "FPGA internal 2 error detected.\n");
        rc = ERROR_FPGA_INTERNAL;
      }
      return rc;
    }
    task_status = reg32_read(task->task_state_addr);
    task_error_id = (task_status >> 8) & 0xFF;
    if (task_error_id != 0) {
      fprintf(stdout, "Detected task_error_id %d\n", task_error_id);
      free_task(task);
      if (fpga_id != 0) {
        close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
        close_dev(userfd[0], h2cfd[0], c2hfd[0], 0);
      } else
        close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
      if (munmap(map_base, MAP_SIZE) == -1) {
        exit(1);
      }
      return get_error_num(task_error_id);
    }
    srcdata_vld_flag = get_status(task->srcdata_state_addr, 0);
    if (srcdata_vld_flag == 1) {
      usleep(50);
      poll_num++;
    } else {  // in case that FPGA poll down srcdata_vld_flag because of wrong
              // cfg info.
      task_status = reg32_read(task->task_state_addr);
      task_error_id = (task_status >> 8) & 0xFF;
      if (task_error_id != 0) {
        fprintf(stdout, "Detected task_error_id %d\n", task_error_id);
        free_task(task);
        if (fpga_id != 0) {
          close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
          close_dev(userfd[0], h2cfd[0], c2hfd[0], 0);
        } else
          close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
        if (munmap(map_base, MAP_SIZE) == -1) {
          exit(1);
        }
        return get_error_num(task_error_id);
      }
      flag = 0;
    }
  } while (flag);
#endif

  poll_num = 0;  // All srcdatas have been read
                 // poll back data's status
                 // debugcxd
  // printf("8\n");
#ifdef DEBUG
  fprintf(stdout, "***** CPU Polling FPGA back data's status.\n");
#endif
  flag = 1;
  rc = 0;
  do {
    if (poll_num * 50 > single_task_maximum_time) {  // todo : confirm this
                                                     // value
      rc = ERROR_TIMEOUT_CAL;
      free_task(task);
      if (fpga_id != 0) {
        close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
        close_dev(userfd[0], h2cfd[0], c2hfd[0], 0);
      } else
        close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
      if (munmap(map_base, MAP_SIZE) == -1) {
        exit(1);
      }
      return rc;
    }

#ifdef MULTI_DEBUG
    error_flag = reg32_read(sys_process_err_addr);
    error_flag &= 0x3;
    if (error_flag != 0) {
      free_task(task);
      if (fpga_id != 0) {
        close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
        close_dev(userfd[0], h2cfd[0], c2hfd[0], 0);
      } else
        close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
      if (munmap(map_base, MAP_SIZE) == -1) {
        exit(1);
      }
      if (error_flag == 1) {
        fprintf(stdout, "Time out error 3 detected by FPGA\n");
        rc = ERROR_FPGA_TIMEOUT;
      } else {
        fprintf(stdout, "FPGA internal 3 error detected.\n");
        rc = ERROR_FPGA_INTERNAL;
      }
      return rc;
    }
#endif
    backdata_vld_flag = get_status(task->backdata_state_addr, 0);
    if (backdata_vld_flag == 0) {
      usleep(50);
      poll_num++;
    } else {
      flag = 0;
    }
  } while (flag);
#ifdef DEBUG
  fprintf(stdout,
          "***** FPGA's task done! FPGA has finished the Algorithm accl.\n");
#endif

  // debugcxd
  //  printf("9\n");
  gettimeofday(&fpgaid_time_point[fpga_id][7], NULL);
  // long double time_before = (fpgaid_time_point[fpga_id][7].tv_sec) * 1000.0 +
  // (fpgaid_time_point[fpga_id][7].tv_usec) / 1000.0;
  // fprintf(stdout,"fpga_id %d,Before Recv Time %16.4Lf
  // (ms)\n",fpga_id,time_before);
  gettimeofday(&time_point[7], NULL);
  // long double time_before_recv = (time_point[7].tv_sec) * 1000.0 +
  // (time_point[7].tv_usec) / 1000.0;
  // fprintf(stdout,"fpga_id %d,Before Recv Time %16.4Lf
  // (ms)\n",fpga_id,time_before_recv);

  /*************************************************************************\
  |**************************Read results from FPGA*************************|
  \*************************************************************************/
  // read back data's size, base
  uint32_t recv_data_size;
  uint64_t recv_data_base;
  uint32_t recv_data_base_L;
  uint32_t recv_data_base_H;
  rc = 0;
  gettimeofday(&fpgaid_time_point[fpga_id][8], NULL);
  gettimeofday(&time_point[8], NULL);
  if (cfg->result_memtype == 0) {
    recv_data_base_L = reg32_read(task->backdata_addr_L) + BACKDATA_INFO_SIZE;
    recv_data_base_H = reg32_read(task->backdata_addr_H);
    recv_data_size = reg32_read(task->backdata_len_addr) - BACKDATA_INFO_SIZE;
    recv_data_base = ((uint64_t)recv_data_base_H << 32) | recv_data_base_L;
#ifdef DEBUG
    fprintf(
        stdout,
        "\n*****fpga_id = %d CPU Get task data from FPGA (Addr: 0x%08" PRIx64
        ", "
        "Data size: %d bytes).\n",
        fpga_id, recv_data_base, recv_data_size);
#endif
    flock(c2hfd[0], LOCK_EX);
    rc = transfer_from_fpga(DEV_C2H[fpga_id][0], c2h_fd, result, recv_data_size,
                            recv_data_base);
#ifdef MULTI_CARD_DEBUG
    showMemoryHex(result, recv_data_size);
    printf("\n");
#endif
    flock(c2hfd[0], LOCK_UN);

    if (rc < 0) {
      fprintf(stderr, "***** ERROR happend during transfering data to HOST.\n");
      free_task(task);
      if (fpga_id != 0) {
        close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
        close_dev(userfd[0], h2cfd[0], c2hfd[0], 0);
      } else
        close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
      if (munmap(map_base, MAP_SIZE) == -1) {
        exit(1);
      }
      return ERROR_RECV_DATA;
    }
    // clear back data's status
#ifdef DEBUG
    fprintf(stdout, "***** CPU Clear FPGA Back data's status.\n");
#endif
    rc = check_and_clear_status(user_fd, task->backdata_state_addr, 0);
    if (rc != 0) {
      rc = ERROR_REG_OPERATION;
    }

#ifdef DEBUG
    fprintf(stdout, "***** CPU Clear FPGA Back data done!\n");
#endif
  }
  gettimeofday(&fpgaid_time_point[fpga_id][9], NULL);
  gettimeofday(&time_point[9], NULL);

  free_task(task);

  if (fpga_id != 0) {
    close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
    close_dev(userfd[0], h2cfd[0], c2hfd[0], 0);
  } else
    close_dev(user_fd, h2c_fd, c2h_fd, fpga_id);
  if (munmap(map_base, MAP_SIZE) == -1) {
    exit(1);
  }
  return 0;
}

}  // namespace heu::lib::algorithms::paillier_clustar_fpga::fpga_engine
