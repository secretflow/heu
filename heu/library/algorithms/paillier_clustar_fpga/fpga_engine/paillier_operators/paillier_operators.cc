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

#include "paillier_operators.h"

#include <float.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include <exception>
#include <future>
#include <iostream>
#include <memory>

#include "fmt/ostream.h"
#include "yacl/base/exception.h"

#include "heu/library/algorithms/paillier_clustar_fpga/fpga_engine/driver/driver.h"
#include "heu/library/algorithms/paillier_clustar_fpga/fpga_engine/driver/mpint_wrapper.h"
#include "heu/library/algorithms/util/mp_int.h"
#include "heu/library/algorithms/util/spi_traits.h"

namespace heu::lib::algorithms::paillier_clustar_fpga::fpga_engine {

#define MAX_SUM_GROUPS 8192
long MAX_MEMSPACE = 8589672448;  // unit in bits
unsigned CPU_CORE_NUM = 3;

void init_params() {
  char *maxmem = getenv("MAX_MEMSPACE");
  if (maxmem) {
    MAX_MEMSPACE = atol(maxmem) * 1024 * 1024 * 8;
  }
  printf("MAX_MEMSPACE: %ld\n", MAX_MEMSPACE);

  char *env_cpu_core_num = getenv("CPU_CORE_NUM");
  if (env_cpu_core_num) {
    CPU_CORE_NUM = atoi(env_cpu_core_num);
  }
  printf("CPU_CORE_NUM: %u\n", CPU_CORE_NUM);
}

// 1 alloc byte_length memory and init to 0
// 2 return char*
char *c_malloc_init_zero(size_t byte_length) {
  void *ptr;
  int rc = posix_memalign((void **)&ptr, 4096, byte_length);
  if (rc != 0) {
    YACL_THROW("FPGA c_malloc failed");
  }

  memset(ptr, 0, byte_length);
  return static_cast<char *>(ptr);
}

struct mpint_numbers {
  MPInt n_cal;
  MPInt nsquare_cal;
  MPInt maxint_cal;
  MPInt tmp;
};

struct mpint_para_powmod {
  char *fpn_encode;
  char *pen_cipher;
  char *data1;
  char *data2;
  struct mpint_numbers *keys;
  uint32_t *res_exp;
  uint32_t *res_base;
  uint32_t *fpn_exp;
  uint32_t *pen_exp;
  uint32_t *fpn_base;
  size_t batch_index;
  size_t s_index;
  size_t e_index;
  size_t fpn_dim0;
  size_t fpn_dim1;
  size_t pen_dim0;
  size_t pen_dim1;
  size_t res_dim1;
  size_t e_length;
  size_t r_length;
};

void cpu_invert_pen_mul_fpn(void *th_para) {
  struct mpint_para_powmod *para = (struct mpint_para_powmod *)th_para;
  struct mpint_numbers *keys = para->keys;
  size_t i, op1_line, op1_col, op2_line, op2_col, src_1, src_2, src_data;

  MPInt neg_c_cal;
  neg_c_cal.SetZero();

  MPInt neg_scalar_cal;
  neg_scalar_cal.SetZero();

  MPInt fpn_cal;
  fpn_cal.SetZero();

  MPInt pen_cal;
  pen_cal.SetZero();
  for (i = para->s_index; i < para->e_index; i++) {
    op1_line = i / para->res_dim1;
    op1_col = i - para->res_dim1 * (i / para->res_dim1);
    op2_line = op1_line;
    op2_col = op1_col;

    op1_line = para->fpn_dim0 == 1 ? 0 : op1_line;
    op1_col = para->fpn_dim1 == 1 ? 0 : op1_col;
    op2_line = para->pen_dim0 == 1 ? 0 : op2_line;
    op2_col = para->pen_dim1 == 1 ? 0 : op2_col;

    src_1 = op1_line * para->fpn_dim1 + op1_col;
    src_2 = op2_line * para->pen_dim1 + op2_col;
    src_data = i - para->batch_index;

    fpn_cal.FromMagBytes({para->fpn_encode + src_1 * para->e_length * 2 / 8,
                          para->e_length * 2 / 8},
                         Endian::little);
    pen_cal.FromMagBytes(
        {para->pen_cipher + src_2 * para->r_length / 8, para->r_length / 8},
        Endian::little);

    if (fpn_cal >= keys->tmp) {
      MPInt::InvertMod(pen_cal, keys->nsquare_cal, &neg_c_cal);
      neg_scalar_cal = keys->n_cal - fpn_cal;
      CMPIntWrapper::MPIntToBytes(neg_c_cal,
                                  para->data1 + src_data * para->r_length / 8,
                                  para->r_length / 8);
      CMPIntWrapper::MPIntToBytes(neg_scalar_cal,
                                  para->data2 + src_data * para->e_length / 8,
                                  para->e_length / 8);
    } else {
      memcpy(para->data1 + src_data * para->r_length / 8,
             para->pen_cipher + src_2 * para->r_length / 8, para->r_length / 8);
      memcpy(para->data2 + src_data * para->e_length / 8,
             para->fpn_encode + src_1 * para->e_length * 2 / 8,
             para->e_length / 8);
    }
    para->res_exp[i] = para->fpn_exp[src_1] + para->pen_exp[src_2];
    para->res_base[i] = para->fpn_base[0];
  }
}

void fpn_matrix_elementwise_multiply_pen_matrix(
    char *fpn_encode, void *fpn_base_void, void *fpn_exp_void, char *pen_cipher,
    void * /*pen_base_void*/, void *pen_exp_void, char *res_cipher,
    void *res_base_void, void *res_exp_void, size_t fpn_dim0, size_t fpn_dim1,
    size_t pen_dim0, size_t pen_dim1, char *n, char * /*g*/, char *nsquare,
    char *max_int, size_t /*encode_bitlength*/, size_t cipher_bitlength,
    size_t device_num) {
  // change the pointer types
  uint32_t *fpn_base = (uint32_t *)fpn_base_void;
  uint32_t *fpn_exp = (uint32_t *)fpn_exp_void;
  // uint32_t* pen_base = (uint32_t*) pen_base_void;
  uint32_t *pen_exp = (uint32_t *)pen_exp_void;
  uint32_t *res_base = (uint32_t *)res_base_void;
  uint32_t *res_exp = (uint32_t *)res_exp_void;

  size_t para_length = cipher_bitlength;
  size_t data1_length = cipher_bitlength;
  size_t data2_length = cipher_bitlength / 2;
  size_t data3_length = 0;

  size_t res_dim0 = fpn_dim0 > pen_dim0 ? fpn_dim0 : pen_dim0;
  size_t res_dim1 = fpn_dim1 > pen_dim1 ? fpn_dim1 : pen_dim1;
  size_t batch_size_res = res_dim0 * res_dim1;
  size_t batch_size_cur;
  size_t batch_size_max =
      floor(MAX_MEMSPACE / (double)(data1_length + data2_length));

  char *para, *data1, *data2, *result;
  result = res_cipher;

  fpga_config *cfg;
  cfg = (fpga_config *)malloc(sizeof(fpga_config));
  memset(cfg, 0, sizeof(fpga_config));
  cfg->operate_mode = 7;  // call encrypted mul2 function of FPGA to calulate
  cfg->para_data_size = para_length / 8;
  cfg->data3_size = 0;
  cfg->para_bitlen = get_data_width(para_length);
  cfg->data1_bitlen = get_data_width(data1_length);
  cfg->data2_bitlen = get_data_width(data2_length);
  cfg->data3_bitlen = get_data_width(data3_length);
  cfg->data1_memtype = 0;
  cfg->data2_memtype = 0;
  cfg->data3_memtype = 255;
  cfg->result_memtype = 0;
  cfg->srcdata_buf_hold = 0;
  cfg->bypass_computing = 0;
  cfg->fpga_dev_id = device_num;
  cfg->task_space_size_req = FPGA_TASK_SIZE;

  int rc = posix_memalign((void **)&para, 4096,
                          (sizeof(char) * cfg->para_data_size) + 4096);
  if (rc != 0) {
    check_error_status(rc);
    free(cfg);
    return;
  }
  memcpy(para, nsquare, para_length / 8);

  size_t malloc_size =
      batch_size_res > batch_size_max ? batch_size_max : batch_size_res;
  size_t data1_alloc_size =
      (sizeof(char) * malloc_size * data1_length / 8) + 4096;
  rc = posix_memalign((void **)&data1, 4096, data1_alloc_size);
  if (rc != 0) {
    check_error_status(rc);
    free(cfg);
    free(para);
    return;
  }
  memset(data1, 0, data1_alloc_size);

  size_t data2_alloc_size =
      (sizeof(char) * malloc_size * data2_length / 8) + 4096;
  rc = posix_memalign((void **)&data2, 4096, data2_alloc_size);
  if (rc != 0) {
    check_error_status(rc);
    free(cfg);
    free(para);
    free(data1);
    return;
  }
  memset(data2, 0, data2_alloc_size);

  std::shared_ptr<mpint_numbers> keys_sptr = std::make_shared<mpint_numbers>();
  mpint_numbers *keys = keys_sptr.get();
  keys->n_cal.SetZero();
  keys->nsquare_cal.SetZero();
  keys->maxint_cal.SetZero();
  keys->tmp.SetZero();

  keys->n_cal.FromMagBytes({n, para_length / 8}, Endian::little);
  keys->maxint_cal.FromMagBytes({max_int, para_length / 8}, Endian::little);
  keys->nsquare_cal.FromMagBytes({nsquare, para_length / 8}, Endian::little);
  keys->tmp = keys->n_cal - keys->maxint_cal;

  for (size_t i = 0; i < batch_size_res; i += batch_size_max) {
    // printf("Loop time %lu\n", i / batch_size_max + 1);
    if ((i + batch_size_max) > batch_size_res)
      batch_size_cur = batch_size_res - i;
    else
      batch_size_cur = batch_size_max;

    cfg->batch_size = batch_size_cur;
    cfg->data1_size = (data1_length * batch_size_cur) / 8;
    cfg->data2_size = (data2_length * batch_size_cur) / 8;

    mpint_para_powmod th_para[CPU_CORE_NUM];
    for (size_t j = 0; j < CPU_CORE_NUM; j++) {
      th_para[j].fpn_encode = fpn_encode;
      th_para[j].pen_cipher = pen_cipher;
      th_para[j].data1 = data1;
      th_para[j].data2 = data2;
      th_para[j].keys = keys;
      th_para[j].res_exp = res_exp;
      th_para[j].res_base = res_base;
      th_para[j].fpn_exp = fpn_exp;
      th_para[j].pen_exp = pen_exp;
      th_para[j].fpn_base = fpn_base;
      th_para[j].fpn_dim0 = fpn_dim0;
      th_para[j].fpn_dim1 = fpn_dim1;
      th_para[j].pen_dim0 = pen_dim0;
      th_para[j].pen_dim1 = pen_dim1;
      th_para[j].res_dim1 = res_dim1;
      th_para[j].e_length = data2_length;
      th_para[j].r_length = data1_length;
      th_para[j].s_index = i + j * (batch_size_cur / CPU_CORE_NUM);
      th_para[j].e_index = i + (j + 1) * (batch_size_cur / CPU_CORE_NUM);
      th_para[j].batch_index = i;
    }
    th_para[CPU_CORE_NUM - 1].e_index = i + batch_size_cur;

    std::vector<std::future<void>> fut_vec;
    fut_vec.reserve(CPU_CORE_NUM);
    for (size_t j = 0; j < CPU_CORE_NUM; j++) {
      auto fut =
          std::async(std::launch::async, cpu_invert_pen_mul_fpn, &th_para[j]);
      fut_vec.emplace_back(std::move(fut));
    }

    for (size_t j = 0; j < CPU_CORE_NUM; j++) {
      fut_vec[j].get();
    }

    rc = fpga_fedai_operator_accl_split_task(cfg, para, data1, data2, NULL,
                                             result);
    if (rc != 0) {
      check_error_status(rc);
      free(cfg);
      free(para);
      free(data1);
      free(data2);
      return;
    }

    result = result + batch_size_cur * para_length / 8;
  }

  free(cfg);
  free(para);
  free(data1);
  free(data2);
}

void pen_sum_with_same_exp(char *pen_cipher, void *pen_base_void,
                           void *pen_exp_void, char *res_cipher,
                           void *res_base_void, void *res_exp_void,
                           size_t pen_dim0, size_t pen_dim1, char * /*n*/,
                           char * /*g*/, char *nsquare, char * /*max_int*/,
                           size_t cipher_bitlength, size_t device_num) {
  // change the pointer types
  uint32_t *pen_base = (uint32_t *)pen_base_void;
  uint32_t *pen_exp = (uint32_t *)pen_exp_void;
  uint32_t *res_base = (uint32_t *)res_base_void;
  uint32_t *res_exp = (uint32_t *)res_exp_void;

  size_t para_length = cipher_bitlength;
  size_t data1_length = cipher_bitlength;
  size_t data2_length = 0;
  size_t data3_length = 0;

  size_t batch_size_res = pen_dim0 * pen_dim1;
  if (pen_dim1 == 1) {
    memcpy(res_cipher, pen_cipher, cipher_bitlength * batch_size_res / 8);
    memcpy(res_base, pen_base, batch_size_res * sizeof(uint32_t));
    memcpy(res_exp, pen_exp, batch_size_res * sizeof(uint32_t));
    return;
  }

  fpga_config *cfg = (fpga_config *)malloc(sizeof(fpga_config));
  cfg->operate_mode = 16;  // call pi_sum function of FPGA to calulate
  cfg->para_data_size = para_length / 8 + 4;
  cfg->data2_size = 0;
  cfg->data3_size = 0;
  cfg->para_bitlen = get_data_width(para_length);
  cfg->data1_bitlen = get_data_width(data1_length);
  cfg->data2_bitlen = get_data_width(data2_length);
  cfg->data3_bitlen = get_data_width(data3_length);
  cfg->data1_memtype = 0;
  cfg->data2_memtype = 255;
  cfg->data3_memtype = 255;
  cfg->result_memtype = 0;
  cfg->srcdata_buf_hold = 0;
  cfg->bypass_computing = 0;
  cfg->fpga_dev_id = device_num;
  cfg->task_space_size_req = FPGA_TASK_SIZE;
  cfg->pisum_cfg = 1;
  char *para;
  int rc = posix_memalign((void **)&para, 4096,
                          (sizeof(char) * cfg->para_data_size) + 4096);
  if (rc != 0) {
    check_error_status(rc);
    free(cfg);
    return;
  }
  memcpy(para, nsquare, para_length / 8);

  char *data1 = pen_cipher;
  char *result = res_cipher;
  size_t batch_size_max = floor(MAX_MEMSPACE / (double)para_length);
  size_t max_row_per_batch, cur_row, batch_num_per_row, batch_size_extra;
  uint32_t sum_length;  // length of each summation, maximum length 2^32
  size_t cur_pen_dim1 = pen_dim1;
  char *tmp_result = NULL;
  size_t i = 0;
  size_t j = 0;
  if (batch_size_max < pen_dim1) {
    cfg->pisum_block_num = 1;
    fpga_config *cfg_extra;
    cfg_extra = (fpga_config *)malloc(sizeof(fpga_config));
    char *para_extra;
    rc = posix_memalign((void **)&para_extra, 4096,
                        (sizeof(char) * (cfg->para_data_size + 4)) +
                            4096);  // 4 bytes are reserved for sum
    if (rc != 0) {
      check_error_status(rc);
      free(cfg);
      free(cfg_extra);
      free(para);
      return;
    }

    memcpy(para_extra, nsquare, para_length / 8);
    memcpy(cfg_extra, cfg, sizeof(fpga_config));

    char *result_sum, *pointer_swap;
    rc = posix_memalign(
        (void **)&tmp_result, 4096,
        (sizeof(char) *
         (pen_dim0 * (size_t)ceil((double)pen_dim1 / batch_size_max) *
          para_length / 8)) +
            4096);
    if (rc != 0) {
      check_error_status(rc);
      free(cfg);
      free(cfg_extra);
      free(para);
      free(para_extra);
      return;
    }

    result_sum = tmp_result;
    while (batch_size_max < cur_pen_dim1) {
      cfg->batch_size = batch_size_max;
      cfg->data1_size = (data1_length * cfg->batch_size) / 8;
      sum_length = (uint32_t)batch_size_max;
      memcpy(para + para_length / 8, &sum_length, 4);

      batch_num_per_row = (size_t)ceil((double)cur_pen_dim1 / batch_size_max);
      batch_size_extra = cur_pen_dim1 % batch_size_max == 0
                             ? batch_size_max
                             : cur_pen_dim1 % batch_size_max;
      // printf("batch_size_max: %ld, batch_num_per_row: %ld, batch_size_extra:
      // %ld\n", batch_size_max, batch_num_per_row , batch_size_extra);
      sum_length = (uint32_t)batch_size_extra;
      memcpy(para_extra + para_length / 8, &sum_length, 4);

      cfg_extra->batch_size = batch_size_extra;
      cfg_extra->data1_size = (data1_length * cfg_extra->batch_size) / 8;

      for (i = 0; i < pen_dim0; i++) {
        for (j = 0; j < batch_num_per_row; j++) {
          if (j != batch_num_per_row - 1) {
            rc = fpga_fedai_operator_accl_split_task(cfg, para, data1, NULL,
                                                     NULL, result_sum);
            data1 = data1 + cfg->data1_size;
          } else {
            rc = fpga_fedai_operator_accl_split_task(
                cfg_extra, para_extra, data1, NULL, NULL, result_sum);
            data1 = data1 + cfg_extra->data1_size;
          }
          result_sum = result_sum + para_length / 8;
          if (rc != 0) {
            check_error_status(rc);
            free(cfg);
            free(cfg_extra);
            free(para);
            free(para_extra);
            free(tmp_result);
            return;
          }
        }
      }
      data1 = data1 - pen_dim0 * cur_pen_dim1 * data1_length / 8;
      result_sum = result_sum - pen_dim0 * batch_num_per_row * para_length / 8;
      pointer_swap = data1;
      data1 = result_sum;
      result_sum = pointer_swap;
      cur_pen_dim1 = batch_num_per_row;
    }
    free(cfg_extra);
    free(para_extra);
  }

  max_row_per_batch = floor(batch_size_max / cur_pen_dim1);
  sum_length = (uint32_t)cur_pen_dim1;
  memcpy(para + para_length / 8, &sum_length, 4);
  for (i = 0; i < pen_dim0; i += max_row_per_batch) {
    if (i + max_row_per_batch > pen_dim0) {
      cur_row = pen_dim0 - i;
    } else {
      cur_row = max_row_per_batch;
    }

    cfg->pisum_block_num = cur_row;
    cfg->batch_size = cur_row * cur_pen_dim1;
    cfg->data1_size = (data1_length * cfg->batch_size) / 8;

    rc = fpga_fedai_operator_accl_split_task(cfg, para, data1, NULL, NULL,
                                             result);
    if (rc != 0) {
      check_error_status(rc);
      free(cfg);
      free(para);
      return;
    }

    data1 = data1 + cfg->data1_size;
    result = result + cur_row * para_length / 8;
  }

  if (tmp_result != NULL) {
    free(tmp_result);
    tmp_result = NULL;
  }
  free(para);
  free(cfg);
}

void encrypt_without_obf(char *fpn_encode, void *fpn_base_void,
                         void *fpn_exp_void, char *res_cipher,
                         void *res_base_void, void *res_exp_void, char *n,
                         char * /*g*/, char *nsquare, char * /*max_int*/,
                         size_t /*encode_bitlength*/, size_t cipher_bitlength,
                         size_t vector_size, size_t device_num) {
  int rc;
  size_t i, j;

  uint32_t *fpn_base = (uint32_t *)fpn_base_void;
  uint32_t *fpn_exp = (uint32_t *)fpn_exp_void;
  uint32_t *res_base = (uint32_t *)res_base_void;
  uint32_t *res_exp = (uint32_t *)res_exp_void;

  size_t para_length = cipher_bitlength;
  size_t data1_length = cipher_bitlength / 2;
  size_t data2_length = cipher_bitlength / 2;
  size_t data3_length = 0;

  size_t batch_size_res = vector_size;
  size_t batch_size_max = floor(MAX_MEMSPACE / (double)(data1_length));
  size_t batch_size_cur;

  char *para, *data1, *result;
  result = res_cipher;

  fpga_config *cfg;
  cfg = (fpga_config *)malloc(sizeof(fpga_config));
  memset(cfg, 0, sizeof(fpga_config));
  cfg->operate_mode =
      15;  // call encrypt without obfucation function of FPGA to calculate
  cfg->para_data_size = (para_length + data2_length) / 8;
  cfg->data2_size = 0;
  cfg->data3_size = 0;
  cfg->para_bitlen = get_data_width(para_length);
  cfg->data1_bitlen = get_data_width(data1_length);
  cfg->data2_bitlen = get_data_width(data2_length);
  cfg->data3_bitlen = get_data_width(data3_length);
  cfg->data1_memtype = 0;
  cfg->data2_memtype = 255;
  cfg->data3_memtype = 255;
  cfg->result_memtype = 0;
  cfg->srcdata_buf_hold = 0;
  cfg->bypass_computing = 0;
  cfg->fpga_dev_id = device_num;
  cfg->task_space_size_req = FPGA_TASK_SIZE;

  rc = posix_memalign((void **)&para, 4096,
                      (sizeof(char) * cfg->para_data_size) + 4096);
  if (rc != 0) {
    check_error_status(rc);
    free(cfg);
    return;
  }

  memcpy(para, nsquare, para_length / 8);
  memcpy(para + para_length / 8, n, data2_length / 8);

  size_t malloc_size =
      batch_size_res > batch_size_max ? batch_size_max : batch_size_res;
  rc = posix_memalign((void **)&data1, 4096,
                      (sizeof(char) * malloc_size * data1_length / 8) + 4096);
  if (rc != 0) {
    check_error_status(rc);
    free(cfg);
    free(para);
    return;
  }

  for (i = 0; i < batch_size_res; i += batch_size_max) {
    // printf("Loop Time is %lu\n", i / batch_size_max);
    if ((i + batch_size_max) > batch_size_res)
      batch_size_cur = batch_size_res - i;
    else
      batch_size_cur = batch_size_max;

    cfg->batch_size = batch_size_cur;
    cfg->data1_size = (data1_length * batch_size_cur) / 8;

    for (j = 0; j < batch_size_cur; j++) {
      memcpy(data1 + j * data1_length / 8,
             fpn_encode + (i + j) * 2 * data1_length / 8, data1_length / 8);
    }

    rc = fpga_fedai_operator_accl_split_task(cfg, para, data1, NULL, NULL,
                                             result);
    if (rc != 0) {
      check_error_status(rc);
      free(cfg);
      free(para);
      free(data1);
      return;
    }

    result = result + batch_size_cur * para_length / 8;
  }

  memcpy(res_base, fpn_base, vector_size * sizeof(uint32_t));
  memcpy(res_exp, fpn_exp, vector_size * sizeof(uint32_t));

  free(data1);
  free(para);
  free(cfg);
}

//  compute modexp with montgomery multiplication for gen_obf_seed
//  res = randoms ^ n mod nsquare
void obf_modular_exponentiation(char *randoms, size_t random_bitlength, char *n,
                                char * /*g*/, char *nsquare, char * /*max_int*/,
                                char *res, size_t res_bitlength,
                                size_t vector_size, size_t device_num) {
  int rc;
  size_t i;

  size_t para_length = res_bitlength;
  size_t data1_length = random_bitlength;
  size_t data2_length = res_bitlength / 2;
  size_t data3_length = 0;

  size_t batch_size_res = vector_size;
  size_t batch_size_max = floor(MAX_MEMSPACE / (double)(data1_length));
  size_t batch_size_cur;

  char *para, *data1, *result;
  data1 = randoms;
  result = res;

  fpga_config *cfg;
  cfg = (fpga_config *)malloc(sizeof(fpga_config));
  memset(cfg, 0, sizeof(fpga_config));
  cfg->operate_mode = 1;  // call modexp function of FPGA to calulate
  cfg->para_data_size = (para_length + data2_length) / 8;
  cfg->data2_size = 0;
  cfg->data3_size = 0;
  cfg->para_bitlen = get_data_width(para_length);
  cfg->data1_bitlen = get_data_width(data1_length);
  cfg->data2_bitlen = get_data_width(data2_length);
  cfg->data3_bitlen = get_data_width(data3_length);
  cfg->data1_memtype = 0;
  cfg->data2_memtype = 255;
  cfg->data3_memtype = 255;
  cfg->result_memtype = 0;
  cfg->srcdata_buf_hold = 0;
  cfg->bypass_computing = 0;
  cfg->fpga_dev_id = device_num;
  cfg->task_space_size_req = FPGA_TASK_SIZE;

  rc = posix_memalign((void **)&para, 4096,
                      (sizeof(char) * cfg->para_data_size) + 4096);
  if (rc != 0) {
    check_error_status(rc);
    free(cfg);
    return;
  }

  memcpy(para, nsquare, para_length / 8);
  memcpy(para + para_length / 8, n, data2_length / 8);

  for (i = 0; i < batch_size_res; i += batch_size_max) {
    // printf("Loop Time is %lu\n", i / batch_size_max);
    if ((i + batch_size_max) > batch_size_res)
      batch_size_cur = batch_size_res - i;
    else
      batch_size_cur = batch_size_max;

    cfg->batch_size = batch_size_cur;
    cfg->data1_size = (data1_length * batch_size_cur) / 8;

    rc = fpga_fedai_operator_accl_split_task(cfg, para, data1, NULL, NULL,
                                             result);
    if (rc != 0) {
      check_error_status(rc);
      free(cfg);
      free(para);
      return;
    }

    data1 = data1 + cfg->data1_size;
    result = result + batch_size_cur * para_length / 8;
  }

  free(para);
  free(cfg);
}

//  compute mulmod for obfuscator
//  res_cipher = pen_cipher * obf_seeds mod nsquare
void obf_modular_multiplication(char *pen_cipher, void *pen_base_void,
                                void *pen_exp_void, char *obf_seeds,
                                char *res_cipher, void *res_base_void,
                                void *res_exp_void, char * /*n*/, char * /*g*/,
                                char *nsquare, char * /*max_int*/,
                                size_t /*cipher_bitlength*/,
                                size_t res_bitlength, size_t vector_size,
                                size_t device_num) {
  int rc;
  size_t i;

  uint32_t *pen_base = (uint32_t *)pen_base_void;
  uint32_t *pen_exp = (uint32_t *)pen_exp_void;
  uint32_t *res_base = (uint32_t *)res_base_void;
  uint32_t *res_exp = (uint32_t *)res_exp_void;

  size_t para_length = res_bitlength;
  size_t data1_length = res_bitlength;
  size_t data2_length = res_bitlength;
  size_t data3_length = 0;

  size_t batch_size_res = vector_size;
  size_t batch_size_max =
      floor(MAX_MEMSPACE / (double)(data1_length + data2_length));
  size_t batch_size_cur;

  char *para, *data1, *data2, *result;
  data1 = pen_cipher;
  data2 = obf_seeds;
  result = res_cipher;

  fpga_config *cfg;
  cfg = (fpga_config *)malloc(sizeof(fpga_config));
  memset(cfg, 0, sizeof(fpga_config));
  cfg->operate_mode = 2;  // call mulmod function of FPGA to calulate
  cfg->para_data_size = para_length / 8;
  cfg->data3_size = 0;
  cfg->para_bitlen = get_data_width(para_length);
  cfg->data1_bitlen = get_data_width(data1_length);
  cfg->data2_bitlen = get_data_width(data2_length);
  cfg->data3_bitlen = get_data_width(data3_length);
  cfg->data1_memtype = 0;
  cfg->data2_memtype = 0;
  cfg->data3_memtype = 255;
  cfg->result_memtype = 0;
  cfg->srcdata_buf_hold = 0;
  cfg->bypass_computing = 0;
  cfg->fpga_dev_id = device_num;
  cfg->task_space_size_req = FPGA_TASK_SIZE;

  rc = posix_memalign((void **)&para, 4096,
                      (sizeof(char) * cfg->para_data_size) + 4096);
  if (rc != 0) {
    check_error_status(rc);
    free(cfg);
    return;
  }

  memcpy(para, nsquare, para_length / 8);

  for (i = 0; i < batch_size_res; i += batch_size_max) {
    // printf("Loop Time is %lu\n", i / batch_size_max);
    if ((i + batch_size_max) > batch_size_res)
      batch_size_cur = batch_size_res - i;
    else
      batch_size_cur = batch_size_max;

    cfg->batch_size = batch_size_cur;
    cfg->data1_size = data1_length * batch_size_cur / 8;
    cfg->data2_size = data2_length * batch_size_cur / 8;

    rc = fpga_fedai_operator_accl_split_task(cfg, para, data1, data2, NULL,
                                             result);
    if (rc != 0) {
      check_error_status(rc);
      free(cfg);
      free(para);
      return;
    }

    data1 = data1 + cfg->data1_size;
    data2 = data2 + cfg->data2_size;
    result = result + batch_size_cur * para_length / 8;
  }

  memcpy(res_base, pen_base, vector_size * sizeof(uint32_t));
  memcpy(res_exp, pen_exp, vector_size * sizeof(uint32_t));

  free(para);
  free(cfg);
}

void decrypt(char *pen_cipher, void *pen_base_void, void *pen_exp_void,
             char *res_encode, void *res_base_void, void *res_exp_void, char *n,
             char * /*g*/, char * /*nsquare*/, char * /*max_int*/, char *p,
             char *q, char *psquare, char *qsquare, char *q_inverse, char *hp,
             char *hq, size_t /*encode_bitlength*/, size_t cipher_bitlength,
             size_t vector_size, size_t device_num) {
  int rc;
  size_t i, j;

  // change the pointer types
  uint32_t *pen_base = (uint32_t *)pen_base_void;
  uint32_t *pen_exp = (uint32_t *)pen_exp_void;
  uint32_t *res_base = (uint32_t *)res_base_void;
  uint32_t *res_exp = (uint32_t *)res_exp_void;

  size_t para_length =
      cipher_bitlength / 4;  // special treatment in FPGA, bitlength of q
  size_t data1_length = cipher_bitlength;
  size_t data2_length = 0;
  size_t data3_length = 0;

  size_t batch_size_res = vector_size;
  size_t batch_size_max = floor(MAX_MEMSPACE / (double)data1_length);
  size_t batch_size_cur;
  size_t malloc_size;

  char *para, *data1, *result;
  data1 = pen_cipher;

  fpga_config *cfg;
  cfg = (fpga_config *)malloc(sizeof(fpga_config));
  memset(cfg, 0, sizeof(fpga_config));
  cfg->operate_mode = 10;  // call decrypt function of FPGA to calulate
  cfg->para_data_size = (para_length * 11) / 8;
  cfg->data2_size = 0;
  cfg->data3_size = 0;
  cfg->para_bitlen = get_data_width(para_length);
  cfg->data1_bitlen = get_data_width(data1_length);
  cfg->data2_bitlen = get_data_width(data2_length);
  cfg->data3_bitlen = get_data_width(data3_length);
  cfg->data1_memtype = 0;
  cfg->data2_memtype = 255;
  cfg->data3_memtype = 255;
  cfg->result_memtype = 0;
  cfg->srcdata_buf_hold = 0;
  cfg->bypass_computing = 0;
  cfg->fpga_dev_id = device_num;
  cfg->task_space_size_req = FPGA_TASK_SIZE;

  rc = posix_memalign((void **)&para, 4096,
                      (sizeof(char) * cfg->para_data_size) + 4096);
  if (rc != 0) {
    check_error_status(rc);
    free(cfg);
    return;
  }

  malloc_size =
      batch_size_res > batch_size_max ? batch_size_max : batch_size_res;
  rc = posix_memalign(
      (void **)&result, 4096,
      (sizeof(char) * malloc_size * cipher_bitlength / 8) + 4096);
  if (rc != 0) {
    check_error_status(rc);
    free(cfg);
    free(para);
    return;
  }

  memcpy(para, n, para_length * 2 / 8);
  memcpy(para + para_length * 2 / 8, hp, para_length / 8);
  memcpy(para + para_length * 3 / 8, hq, para_length / 8);
  memcpy(para + para_length * 4 / 8, q_inverse, para_length / 8);
  memcpy(para + para_length * 5 / 8, psquare, para_length * 2 / 8);
  memcpy(para + para_length * 7 / 8, qsquare, para_length * 2 / 8);
  memcpy(para + para_length * 9 / 8, p, para_length / 8);
  memcpy(para + para_length * 10 / 8, q, para_length / 8);

  for (i = 0; i < batch_size_res; i += batch_size_max) {
    // printf("Loop Time is %lu\n", i / batch_size_max);
    if ((i + batch_size_max) > batch_size_res)
      batch_size_cur = batch_size_res - i;
    else
      batch_size_cur = batch_size_max;

    cfg->batch_size = batch_size_cur;
    cfg->data1_size = (data1_length * batch_size_cur) / 8;

    rc = fpga_fedai_operator_accl_split_task(cfg, para, data1, NULL, NULL,
                                             result);
    if (rc != 0) {
      check_error_status(rc);
      free(para);
      free(cfg);
      free(result);
      return;
    }
    data1 = data1 + cfg->data1_size;
    for (j = 0; j < batch_size_cur; j++) {
      memcpy(res_encode + (i + j) * para_length * 4 / 8,
             result + j * para_length * 2 / 8, para_length * 2 / 8);
      memset(res_encode + ((2 * (i + j)) + 1) * para_length * 2 / 8, 0,
             para_length * 2 / 8);
    }
  }

  memcpy(res_base, pen_base, vector_size * sizeof(uint32_t));
  memcpy(res_exp, pen_exp, vector_size * sizeof(uint32_t));

  free(para);
  free(cfg);
  free(result);
}

// Calculate pen1 + pen2, where pen1's exp == pen2's exp
void pen_add_with_same_exp(char *pen1_cipher, void *pen1_base_void,
                           void *pen1_exp_void, char *pen2_cipher,
                           void * /*pen2_base_void*/, void * /*pen2_exp_void*/,
                           char *res_cipher, void *res_base_void,
                           void *res_exp_void, size_t pen1_dim0,
                           size_t pen1_dim1, size_t pen2_dim0, size_t pen2_dim1,
                           char *nsquare, size_t cipher_bitlength,
                           size_t device_num) {
  int rc;
  size_t i, j;

  // change the pointer types
  uint32_t *pen1_base = (uint32_t *)pen1_base_void;
  uint32_t *pen1_exp = (uint32_t *)pen1_exp_void;
  uint32_t *res_base = (uint32_t *)res_base_void;
  uint32_t *res_exp = (uint32_t *)res_exp_void;

  size_t para_length = cipher_bitlength;
  size_t data1_length = cipher_bitlength;
  size_t data2_length = cipher_bitlength;

  size_t res_dim0 = pen1_dim0 > pen2_dim0 ? pen1_dim0 : pen2_dim0;
  size_t res_dim1 = pen1_dim1 > pen2_dim1 ? pen1_dim1 : pen2_dim1;
  size_t batch_size_res = res_dim0 * res_dim1;

  size_t batch_size_cur;
  size_t batch_size_max =
      floor(MAX_MEMSPACE / (double)(data1_length + data2_length));

  char *para, *data1, *data2, *result;
  result = res_cipher;

  size_t src, op1_line, op1_col, op2_line, op2_col, src_1, src_2;

  fpga_config *cfg;
  cfg = (fpga_config *)malloc(sizeof(fpga_config));
  memset(cfg, 0, sizeof(fpga_config));
  cfg->operate_mode = 2;
  cfg->para_data_size = para_length / 8;
  cfg->para_bitlen = get_data_width(para_length);
  cfg->data1_bitlen = get_data_width(data1_length);
  cfg->data2_bitlen = get_data_width(data2_length);
  cfg->data3_bitlen = 0;
  cfg->data3_size = 0;
  cfg->data1_memtype = 0;
  cfg->data2_memtype = 0;
  cfg->data3_memtype = 255;
  cfg->result_memtype = 0;
  cfg->srcdata_buf_hold = 0;
  cfg->bypass_computing = 0;
  cfg->fpga_dev_id = device_num;
  cfg->task_space_size_req = FPGA_TASK_SIZE;

  rc = posix_memalign((void **)&para, 4096,
                      (sizeof(char) * cfg->para_data_size) + 4096);
  if (rc != 0) {
    check_error_status(rc);
    free(cfg);
    return;
  }

  size_t malloc_size =
      batch_size_res > batch_size_max ? batch_size_max : batch_size_res;
  rc = posix_memalign((void **)&data1, 4096,
                      (sizeof(char) * malloc_size * data1_length / 8) + 4096);
  if (rc != 0) {
    check_error_status(rc);
    free(cfg);
    free(para);
    return;
  }
  rc = posix_memalign((void **)&data2, 4096,
                      (sizeof(char) * malloc_size * data2_length / 8) + 4096);
  if (rc != 0) {
    check_error_status(rc);
    free(cfg);
    free(para);
    free(data1);
    return;
  }

  memcpy(para, nsquare, para_length / 8);

  for (i = 0; i < batch_size_res; i += batch_size_max) {
    // printf("Loop time %lu\n", i / batch_size_max + 1);
    if ((i + batch_size_max) > batch_size_res)
      batch_size_cur = batch_size_res - i;
    else
      batch_size_cur = batch_size_max;

    cfg->batch_size = batch_size_cur;
    cfg->data1_size = data1_length * batch_size_cur / 8;
    cfg->data2_size = data2_length * batch_size_cur / 8;

    for (j = 0; j < batch_size_cur; j++) {
      src = i + j;
      op1_line = src / res_dim1;
      op1_col = src - res_dim1 * (src / res_dim1);
      op2_line = op1_line;
      op2_col = op1_col;

      op1_line = pen1_dim0 == 1 ? 0 : op1_line;
      op1_col = pen1_dim1 == 1 ? 0 : op1_col;
      op2_line = pen2_dim0 == 1 ? 0 : op2_line;
      op2_col = pen2_dim1 == 1 ? 0 : op2_col;

      src_1 = op1_line * pen1_dim1 + op1_col;
      src_2 = op2_line * pen2_dim1 + op2_col;
      memcpy(data1 + j * data1_length / 8,
             pen1_cipher + src_1 * data1_length / 8, data1_length / 8);
      memcpy(data2 + j * data2_length / 8,
             pen2_cipher + src_2 * data2_length / 8, data2_length / 8);
      res_exp[src] = pen1_exp[src_1];
      res_base[src] = pen1_base[0];
    }

    rc = fpga_fedai_operator_accl_split_task(cfg, para, data1, data2, NULL,
                                             result);
    if (rc != 0) {
      check_error_status(rc);
      free(para);
      free(data1);
      free(data2);
      free(cfg);
      return;
    }
    result = result + batch_size_cur * para_length / 8;
  }

  free(para);
  free(data1);
  free(data2);
  free(cfg);
}

struct para_encode {
  double *doubles;
  int64_t *ints;
  char *res_encode;
  uint32_t *res_base;
  uint32_t *res_exp;
  size_t bitlength;
  mpint_numbers *keys;
  int32_t precision;
  size_t s_index;
  size_t e_index;
  int error_status;
};

void cpu_encode_int(void *th_para) {
  para_encode *para = (para_encode *)th_para;

  mpint_numbers *keys = para->keys;
  size_t i;
  uint32_t log2_base;
  int exp, positive;
  unsigned long res_encode;
  MPInt res_fpga;
  res_fpga.SetZero();
  for (i = para->s_index; i < para->e_index; i++) {
    log2_base = lrint(log2f(16.0));
    if (para->precision == -1)
      exp = 0;
    else
      exp = floor(log2f((float)para->precision) / log2_base);
    if (para->ints[i] < 0)
      res_encode = -para->ints[i] * lrint(pow(16, exp));
    else
      res_encode = para->ints[i] * lrint(pow(16, exp));
    positive = para->ints[i] >= 0 ? 1 : 0;
    para->res_exp[i] = exp;
    if (positive == 1) {
      memcpy(para->res_encode + (uint64_t)i * para->bitlength / 8, &res_encode,
             sizeof(unsigned long));
    } else {
      res_fpga.Set(res_encode);
      res_fpga = res_fpga - keys->n_cal;
      CMPIntWrapper::MPIntToBytes(
          res_fpga, para->res_encode + (uint64_t)i * para->bitlength / 8,
          para->bitlength / 8);
    }
    para->res_base[i] = 16;
  }
}

void encode_int(void *ints_void, char *res_encode, void *res_base_void,
                void *res_exp_void, int32_t precision, char *n,
                char * /*max_int*/, size_t encode_bitlength, size_t vector_size,
                size_t /*device_num*/) {
  // change the pointer types
  int64_t *ints = (int64_t *)ints_void;
  uint32_t *res_base = (uint32_t *)res_base_void;
  uint32_t *res_exp = (uint32_t *)res_exp_void;

  std::shared_ptr<mpint_numbers> keys_sptr = std::make_shared<mpint_numbers>();
  mpint_numbers *keys = keys_sptr.get();
  keys->n_cal.SetZero();
  memset(res_encode, 0, (uint64_t)vector_size * encode_bitlength / 8);
  keys->n_cal.FromMagBytes({n, encode_bitlength / 8}, Endian::little);

  //
  para_encode th_para[CPU_CORE_NUM];
  for (size_t i = 0; i < CPU_CORE_NUM; i++) {
    th_para[i].ints = ints;
    th_para[i].keys = keys;
    th_para[i].res_encode = res_encode;
    th_para[i].res_exp = res_exp;
    th_para[i].res_base = res_base;
    th_para[i].bitlength = encode_bitlength;
    th_para[i].precision = precision;
    th_para[i].s_index = (uint64_t)i * (vector_size / CPU_CORE_NUM);
    th_para[i].e_index = ((uint64_t)i + 1) * (vector_size / CPU_CORE_NUM);
  }
  th_para[CPU_CORE_NUM - 1].e_index = vector_size;

  std::vector<std::future<void>> fut_vec;
  fut_vec.reserve(CPU_CORE_NUM);
  for (size_t i = 0; i < CPU_CORE_NUM; i++) {
    auto fut = std::async(std::launch::async, cpu_encode_int, &th_para[i]);
    fut_vec.emplace_back(std::move(fut));
  }

  std::exception_ptr eptr;
  for (auto &fut : fut_vec) {
    try {
      fut.get();
    } catch (...) {
      eptr = std::current_exception();
    }
  }

  if (eptr) {
    raise_error("encode_int throw an exception");
  }
}

struct para_decode {
  double *doubles;
  int64_t *ints;
  char *numbers_encode;
  uint32_t *numbers_base;
  uint32_t *numbers_exp;
  size_t bitlength;
  struct mpint_numbers *keys;
  size_t s_index;
  size_t e_index;
  int error_status;
};

void cpu_decode_int(void *th_para) {
  para_decode *para = (para_decode *)th_para;
  mpint_numbers *keys = para->keys;
  uint32_t j, k, decimal;
  size_t i;
  int positive;
  double power;
  int64_t exp;
  MPInt numbers_fpga;
  numbers_fpga.SetZero();
  size_t res_len = sizeof(char) * para->bitlength / 8;
  std::shared_ptr<char[]> res_char_sptr(new char[res_len]);
  char *res_char = res_char_sptr.get();
  for (i = para->s_index; i < para->e_index; i++) {
    numbers_fpga.FromMagBytes(
        {para->numbers_encode + (uint64_t)i * para->bitlength / 8,
         para->bitlength / 8},
        Endian::little);
    para->ints[i] = 0;
    positive = 1;
    if (numbers_fpga >= keys->n_cal) {  // Attempted to decode corrupted number
      para->error_status = 21;
      return;
    }

    if (numbers_fpga > keys->maxint_cal &&
        numbers_fpga < keys->tmp) {  // Overflow detected in decode number
      para->error_status = 22;
      return;
    }

    if (numbers_fpga >= keys->tmp) {
      positive = -1;
      numbers_fpga = numbers_fpga - keys->n_cal;
    }

    CMPIntWrapper::MPIntToBytes(
        numbers_fpga, res_char,
        para->bitlength / 8);  // res_char set to 0 in wrapper
    for (j = 0; j < 1024 / 8; j++) {
      decimal = (uint32_t)(unsigned char)res_char[j];
      exp = decimal;
      for (k = 0; k < j; k++) {
        exp *= 256;
      }
      para->ints[i] += exp;
    }
    para->ints[i] *= positive;
    power = pow((double)para->numbers_base[i], (double)para->numbers_exp[i]);
    para->ints[i] /= (int64_t)power;
  }
}

void decode_int(char *numbers_encode, void *numbers_base_void,
                void *numbers_exp_void, char *n, char *max_int,
                size_t encode_bitlength, void *res_void, size_t vector_size) {
  uint32_t *numbers_base = (uint32_t *)numbers_base_void;
  uint32_t *numbers_exp = (uint32_t *)numbers_exp_void;
  int64_t *res = (int64_t *)res_void;

  std::shared_ptr<mpint_numbers> keys_sptr = std::make_shared<mpint_numbers>();
  mpint_numbers *keys = keys_sptr.get();
  keys->n_cal.SetZero();
  keys->maxint_cal.SetZero();
  keys->tmp.SetZero();
  keys->n_cal.FromMagBytes({n, encode_bitlength / 8}, Endian::little);
  keys->maxint_cal.FromMagBytes({max_int, encode_bitlength / 8},
                                Endian::little);
  keys->tmp = keys->n_cal - keys->maxint_cal;

  para_decode th_para[CPU_CORE_NUM];
  for (size_t i = 0; i < CPU_CORE_NUM; i++) {
    th_para[i].ints = res;
    th_para[i].keys = keys;
    th_para[i].numbers_encode = numbers_encode;
    th_para[i].numbers_exp = numbers_exp;
    th_para[i].numbers_base = numbers_base;
    th_para[i].bitlength = encode_bitlength;
    th_para[i].s_index = (uint64_t)i * (vector_size / CPU_CORE_NUM);
    th_para[i].e_index = ((uint64_t)i + 1) * (vector_size / CPU_CORE_NUM);
    th_para[i].error_status = 0;
  }
  th_para[CPU_CORE_NUM - 1].e_index = vector_size;

  std::vector<std::future<void>> fut_vec;
  fut_vec.reserve(CPU_CORE_NUM);
  for (size_t i = 0; i < CPU_CORE_NUM; i++) {
    auto fut = std::async(std::launch::async, cpu_decode_int, &th_para[i]);
    fut_vec.emplace_back(std::move(fut));
  }

  size_t fuc_vec_size = fut_vec.size();
  for (size_t i = 0; i < fuc_vec_size; i++) {
    fut_vec[i].get();
    if (th_para[i].error_status != 0) {
      check_error_status(th_para[i].error_status);
    }
  }
}

void mpint_random(char *res, size_t plain_bitlength, size_t vec_size,
                  char *max_num) {
  size_t output_byte_len = plain_bitlength / 8;
  MPInt n;
  n.FromMagBytes({max_num, plain_bitlength / 8}, Endian::little);
  for (size_t i = 0; i < vec_size; i++) {
    MPInt cur_rd;
    MPInt::RandomLtN(n, &cur_rd);
    cur_rd.ToBytes(
        reinterpret_cast<unsigned char *>(res + i * plain_bitlength / 8),
        output_byte_len, Endian::little);
  }
}

void raise_error(const char *error_info) {
  fprintf(stderr, "%s\n", error_info);
  YACL_THROW(fmt::format("FPGA error [{}]", error_info));
}

void check_error_status(int rc) {
  switch (rc) {
    case FPGA_BUSY_FLAG:
      raise_error("FPGA is in Busy state, and calculation is in progress");
      break;
    case ERROR_FPGA_INTERNAL:
      raise_error("FPGA internal error occured. Device reset is required.");
      break;
    case ERROR_FPGA_TIMEOUT:
      raise_error("Time out error detected by FPGA. Device reset is required.");
      break;
    case ERROR_FPGA_LICENSE:
      raise_error("LicenseCheck error detected by FPGA.");
      break;
    case ERROR_FPGA_SPACESIZE_CFG:
      raise_error("FPGA task space size setting error.");
      break;
    case 12:
      printf("Memory allocation failed!!!\n");
      raise_error("Memory allocation failed.");
      break;
    case 20:
      raise_error("Encoding number is larger than max_int.");
      break;
    case 21:
      raise_error("Try to decode corrupted number.");
      break;
    case 22:
      raise_error("Decode number is overflow.");
      break;
    case ERROR_BUFFER_LIST:
      raise_error("Input buffer_id_list is illegal.");
      break;
    case ERROR_CLEAN_BUF:
      raise_error(
          "Buffer clean error. The corresponding task_id is under operation or "
          "there's no buffer data on the task_id.");
      break;
    case ERROR_BUF_EXCEEDED:
      raise_error("There is no enough task id left to calculate buffer tasks.");
      break;
    case ERROR_DATA_MEMTYPE:
      raise_error("Memtypes of input data do not match the operate_mode.");
      break;
    case ERROR_RES_MEMTYPE:
      raise_error(
          "Memtype of result data is not supported. It equals to those of "
          "input data or is being used by other processes.");
      break;
    case ERROR_SRCDAT_BUFINFO:
      raise_error(
          "Information buffered in FPGA contradicts config of input data");
      break;
    case ERROR_SRCDAT_BUFSTATE:
      raise_error("There is no data stored on buffering task id.");
      break;
    case ERROR_BUFF_FLAG:
      raise_error("The configuration of buffer flag is wrong.");
      break;
    case ERROR_OPEN_DRIVER:
      raise_error("Error detected when opening driver files.");
      break;
    case ERROR_CLOSE_DRIVER:
      raise_error("Error detected when closing driver files.");
      break;
    case ERROR_EVEN:
      raise_error("N is even.");
      break;
    case ERROR_SEND_CMD:
      raise_error("Error detected when sending commands.");
      break;
    case ERROR_SEND_PARA:
      raise_error("Error detected when sending parameters.");
      break;
    case ERROR_SEND_DATA:
      raise_error("Error detected when sending datas.");
      break;
    case ERROR_CMD_NUMBER:
      raise_error("Number of commands is incorrect.");
      break;
    case ERROR_PARA_SIZE:
      raise_error("Size of parameters is incorrect.");
      break;
    case ERROR_RECV_DATA:
      raise_error("Error detected when receiving datas");
      break;
    case ERROR_DATASIZE:
      raise_error(
          "Input data size exceeds the maximum storage space or equals 0.");
      break;
    case ERROR_REG_OPERATION:
      raise_error(
          "Unexpected interaction process detected when setting FPGA "
          "registers' value.");
      break;
    case ERROR_OPERATEMODE:
      raise_error("Unsupported operation mode.");
      break;
    case ERROR_LENGTH:
      raise_error(
          "Invalid bitlength of key. We currently support 128, 256, 512, 768, "
          "1024, 2048, 3072, 4096.");
      break;
    case ERROR_BATCHSIZE:
      raise_error("Batch size of data is smaller than 0.");
      break;
    case ERROR_TASK_ID:
      raise_error("Unsupported task id. It should lie within [0, 15].");
      break;
    case ERROR_TIMEOUT_CAL:
      raise_error(
          "Time out error detected during calculation. Device reset is "
          "required.");
      break;
    case ERROR_TIMEOUT_MAX:
      raise_error(
          "Calculation time exceeds maximum waiting time. Device reset is "
          "required.");
      break;
    case ERROR_GETBACKDATA:
      raise_error(
          "Result data is somehow not retrieved, keeping this task id busy. "
          "Register initiation is required.");
      break;
    case ERROR_FPGA_SRC_FLAG:
      raise_error(
          "Unexpected interaction process detected when launching the task.");
      break;
    case ERROR_FPGA_BACK_FLAG:
      raise_error(
          "Unexpected interaction process detected when launching the task. "
          "There are other result data stored in this task id.");
      break;
    case ERROR_PISUM_MODE:
      raise_error(
          "In Pisum mode, the Pisum_block_num or the Pisum_cfg is a wrong "
          "configure");
      break;
    case ERROR_PISUM_CFG:
      raise_error(
          "In Pisum mode, when Pisum_block_num > 1 and the Pisum_cfg = 1, the "
          "batch_size is not the Integer multiple of pisum_block_num");
      break;
    case ERROR_NODEVICE_SPACESIZE_MATCHED:
      raise_error("No device with the same space size was found.");
      break;
    case ERROR_TASK_ASSIGN_AND_DEVICE_BUSY:
      raise_error("No available device with the same space size at this time.");
      break;
    default:
      raise_error("Unknown errors occured!!!");
  }
}

}  // namespace heu::lib::algorithms::paillier_clustar_fpga::fpga_engine
