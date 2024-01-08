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

#include <exception>
#include <future>
#include <memory>
#include <vector>

#include "driver.h"
#include "mpint_wrapper.h"

namespace heu::lib::algorithms::paillier_clustar_fpga::fpga_engine {

#define MODEXP_THRESHOLD 5000
#define MODMULT_THRESHOLD 10000

struct para_task {
  fpga_config *cfg;
  char *para;
  char *data1;
  char *data2;
  char *data3;
  char *result;
  int error;  // Returned by child-thread to detect errors in different threads.
};

void task_split(void *th_para) {
  int rc;
  struct para_task *task_para = (struct para_task *)th_para;
  rc = fpga_fedai_operator_accl(task_para->cfg, task_para->para,
                                task_para->data1, task_para->data2,
                                task_para->data3, task_para->result);
  task_para->error = rc;
}

int fpga_fedai_operator_accl_split_task(fpga_config *cfg, char *para,
                                        char *data1, char *data2, char *data3,
                                        char *result) {
  int rc = 0;
  uint8_t operate_mode = cfg->operate_mode;
  size_t i, j, total_row, row_num, card_per_row, used_card_num, card_num;
  size_t row_per_card, row_last_card;
  size_t size_per_card, size_last_card;
  uint32_t data1_length, data2_length, data3_length, para_length;

  if (operate_mode == 0 || operate_mode > 16) {
    return ERROR_OPERATEMODE;
  }

  cfg->fpga_dev_id = 0;

  if (cfg->batch_size < MODEXP_THRESHOLD) {
    rc = fpga_fedai_operator_accl(cfg, para, data1, data2, data3, result);
    return rc;
  }

  fpga_config *cfg_first = (fpga_config *)malloc(
      sizeof(fpga_config));  // cfg for the cards except for the last one
  fpga_config *cfg_last =
      (fpga_config *)malloc(sizeof(fpga_config));  // cfg for the last cards
  memcpy(cfg_first, cfg,
         sizeof(fpga_config));  // copy original cfg into cfg_first
  memcpy(cfg_last, cfg,
         sizeof(fpga_config));  // copy original cfg into cfg_last

  card_num = fpga_dev_number_get();  // number of available cards
  if (card_num == 0) {
    return -1;  // Updated by Ant Group
  }

  data1_length =
      getdatalength(cfg->data1_bitlen);  // get the real bitlength of data1
  data2_length =
      getdatalength(cfg->data2_bitlen);  // get the real bitlength of data2
  data3_length =
      getdatalength(cfg->data3_bitlen);  // get the real bitlength of data3
  para_length =
      getdatalength(cfg->para_bitlen);  // get the real bitlength of parameter

  switch (operate_mode) {
    case 8: {
      size_per_card =
          cfg->batch_size / card_num;  // Average batch size for each card
      if (size_per_card < MODEXP_THRESHOLD) {
        card_num = cfg->batch_size / MODEXP_THRESHOLD + 1;
        size_per_card = cfg->batch_size / card_num;
      }
      size_last_card = cfg->batch_size - (card_num - 1) * size_per_card;

      struct para_task *th_para =
          (struct para_task *)malloc(sizeof(struct para_task) * card_num);
      char *result_tmp;
      rc = posix_memalign(
          (void **)&result_tmp, 4096,
          (sizeof(uint8_t) * size_per_card * para_length / 8) + 4096);
      if (rc != 0) {
        free(result_tmp);
        return rc;
      }

      cfg_first->batch_size = size_per_card;
      cfg_last->batch_size = size_last_card;
      cfg_first->data1_size = size_per_card * data1_length / 8;
      cfg_last->data1_size = size_last_card * data1_length / 8;
      cfg_first->data2_size = size_per_card * data2_length / 8;
      cfg_last->data2_size = size_last_card * data2_length / 8;

      for (i = 0; i < card_num; i++) {
        if (i == card_num - 1)
          th_para[i].cfg = cfg_last;
        else
          th_para[i].cfg = cfg_first;
        th_para[i].cfg->fpga_dev_id = 128 + i;
        th_para[i].data1 = data1 + i * size_per_card * data1_length / 8;
        th_para[i].data2 = data2 + i * size_per_card * data2_length / 8;
        th_para[i].data3 = NULL;
        th_para[i].para = para;
        th_para[i].result = result_tmp + i * para_length / 8;
        th_para[i].error = 0;
      }

      std::vector<std::future<void>> fut_vec;
      fut_vec.reserve(card_num);
      for (i = 0; i < card_num; i++) {
        auto fut = std::async(std::launch::async, task_split, &th_para[i]);
        fut_vec.emplace_back(std::move(fut));
      }
      for (i = 0; i < card_num; i++) {
        fut_vec[i].get();
        if (th_para[i].error != 0) {
          int error = th_para[i].error;
          free(th_para);
          return error;
        }
      }

      MPInt nsquare;
      nsquare.SetZero();
      MPInt resu_tmp;
      resu_tmp.SetZero();
      MPInt resu;
      resu.SetZero();

      nsquare.FromMagBytes({para, para_length / 8}, Endian::little);
      for (i = 0; i < card_num; i++) {
        resu_tmp.FromMagBytes(
            {result_tmp + i * para_length / 8, para_length / 8},
            Endian::little);
        if (i == 0) {
          resu = resu_tmp;
        } else {
          resu = resu * resu_tmp;
          MPInt resu_mod;
          MPInt::Mod(resu, nsquare, &resu_mod);
          resu = std::move(resu_mod);
        }
      }

      CMPIntWrapper::MPIntToBytes(resu, result, para_length / 8);
      free(th_para);
      free(result_tmp);
      break;
    }
    case 16: {
      if ((cfg->pisum_cfg == 1) && (cfg->pisum_block_num == 1)) {
        // Currently only support split over summation of a single data block

        size_per_card = cfg->batch_size /
                        card_num;  // calculate average batch size for each card

        if (size_per_card <
            MODEXP_THRESHOLD) {  // batch size for each card is so small that we
                                 // can save some cards
          card_num = cfg->batch_size / MODEXP_THRESHOLD +
                     1;  // appropriate number of cards
          size_per_card =
              cfg->batch_size /
              card_num;  // Batch size for the cards except for the last one
        }

        size_last_card =
            cfg->batch_size -
            (card_num - 1) * size_per_card;  // Batch size for the last card

        struct para_task *th_para =
            (struct para_task *)malloc(sizeof(struct para_task) * card_num);

        char *result_tmp;
        rc = posix_memalign(
            (void **)&result_tmp, 4096,
            (sizeof(uint8_t) * card_num * para_length / 8) + 4096);
        if (rc != 0) {
          free(result_tmp);
          return rc;
        }

        cfg_first->batch_size = size_per_card;
        cfg_last->batch_size = size_last_card;
        cfg_first->data1_size = size_per_card * data1_length / 8;
        cfg_last->data1_size = size_last_card * data1_length / 8;
        for (i = 0; i < card_num; i++) {
          if (i == card_num - 1) {
            th_para[i].cfg = cfg_last;
          } else {
            th_para[i].cfg = cfg_first;
          }
          th_para[i].cfg->fpga_dev_id = 128 + i;
          th_para[i].data1 = data1 + i * size_per_card * data1_length / 8;
          th_para[i].data2 = NULL;
          th_para[i].data3 = NULL;
          th_para[i].para = para;
          th_para[i].result = result_tmp + i * para_length / 8;
        }

        std::vector<std::future<void>> fut_vec;
        fut_vec.reserve(card_num);
        for (i = 0; i < card_num; i++) {
          auto fut = std::async(std::launch::async, task_split, &th_para[i]);
          fut_vec.emplace_back(std::move(fut));
        }
        for (i = 0; i < card_num; i++) {
          fut_vec[i].get();
          if (th_para[i].error != 0) {
            int error = th_para[i].error;
            free(cfg_last);
            free(cfg_first);
            free(th_para);
            return error;
          }
        }

        // Aggregate results from different cards
        MPInt nsquare;
        nsquare.SetZero();
        MPInt resu_tmp;
        resu_tmp.SetZero();
        MPInt resu;
        resu.SetZero();

        nsquare.FromMagBytes(
            {para, para_length / 8},
            Endian::little);  // Extract parameter from byte stream
        for (i = 0; i < card_num; i++) {
          resu_tmp.FromMagBytes(
              {result_tmp + i * para_length / 8, para_length / 8},
              Endian::little);
          if (i == 0) {
            resu = resu_tmp;
          } else {
            resu = resu * resu_tmp;
            MPInt resu_mod;
            MPInt::Mod(resu, nsquare, &resu_mod);
            resu = std::move(resu_mod);
          }
        }
        CMPIntWrapper::MPIntToBytes(resu, result, para_length / 8);
        free(th_para);
        free(result_tmp);
      }

      else {
        rc = fpga_fedai_operator_accl(cfg, para, data1, data2, data3, result);
        if (rc != 0) return rc;
      }
      break;
    }
    case 9: {
      row_num = 0;  // memset
      memcpy(&row_num, para, 32 / 8);
      total_row = cfg->batch_size /
                  row_num;  // Calculate total number of rows in this matmul.
      if (total_row == 0) {
        return -1;  // Updated by Ant Group
      }
      // card_num = 8; //debugcxd
      if (total_row >= card_num) {
        row_per_card =
            total_row /
            card_num;  // Average rows of matmuls each card needs to calculate
        size_per_card =
            row_per_card *
            row_num;  // Average number of modexps each card needs to calculate

        if (size_per_card < MODEXP_THRESHOLD) {  //
          card_num = cfg->batch_size / MODEXP_THRESHOLD + 1;
          row_per_card =
              total_row / card_num;  // Rows of matmuls each card needs to
                                     // calculate except for the last one
          size_per_card =
              row_per_card * row_num;  // Number of modexps each card needs to
                                       // calculate except for the last one
        }
        row_last_card =
            row_per_card +
            total_row %
                card_num;  // Rows of matmul the last card needs to calculate
        size_last_card =
            row_last_card *
            row_num;  // Number of modexps the last card needs to calculate

        struct para_task *th_para =
            (struct para_task *)malloc(sizeof(struct para_task) * card_num);

        cfg_first->batch_size = size_per_card;
        cfg_last->batch_size = size_last_card;
        cfg_first->data1_size = size_per_card * data1_length / 8;
        cfg_last->data1_size = size_last_card * data1_length / 8;
        cfg_first->data2_size = size_per_card * data2_length / 8;
        cfg_last->data2_size = size_last_card * data2_length / 8;

        for (i = 0; i < card_num; i++) {
          if (i == card_num - 1)
            th_para[i].cfg = cfg_last;
          else
            th_para[i].cfg = cfg_first;
          th_para[i].cfg->fpga_dev_id = 128 + i;
          th_para[i].data1 =
              data1 + i * row_per_card * row_num * data1_length / 8;
          th_para[i].data2 =
              data2 + i * row_per_card * row_num * data2_length / 8;
          th_para[i].data3 = NULL;
          th_para[i].para = para;
          th_para[i].result = result + i * row_per_card * para_length / 8;
        }

        std::vector<std::future<void>> fut_vec;
        fut_vec.reserve(card_num);
        for (i = 0; i < card_num; i++) {
          auto fut = std::async(std::launch::async, task_split, &th_para[i]);
          fut_vec.emplace_back(std::move(fut));
        }

        for (i = 0; i < card_num; i++) {
          fut_vec[i].get();
          if (th_para[i].error != 0) {
            int error = th_para[i].error;
            free(th_para);
            return error;
          }
        }

        free(th_para);
      } else {  // total_row < card_num
        card_per_row =
            card_num / total_row;  // Average number of cards to calculate a
                                   // single row cooperatively
        used_card_num = card_per_row * total_row;  // Number of cards to use

        struct para_task *th_para =
            (struct para_task *)malloc(sizeof(struct para_task) * card_num);

        char *result_tmp, *para_first, *para_last;
        rc = posix_memalign((void **)&result_tmp, 4096,
                            (sizeof(char) * used_card_num * para_length / 8) +
                                4096);  // Store temporary matmul results
        if (rc != 0) {
          free(result_tmp);
          return rc;
        }
        rc = posix_memalign((void **)&para_first, 4096,
                            (sizeof(char) * cfg->para_data_size) +
                                4096);  // Parameter to be used by each card
                                        // except for the last one
        if (rc != 0) {
          free(para_first);
          return rc;
        }
        rc = posix_memalign((void **)&para_last, 4096,
                            (sizeof(char) * cfg->para_data_size) +
                                4096);  // Parameter to be used by the last card
        if (rc != 0) {
          free(para_last);
          return rc;
        }

        cfg_first->batch_size = row_num / card_per_row;
        cfg_last->batch_size =
            cfg->batch_size - cfg_first->batch_size * (used_card_num - 1);

        cfg_first->data1_size = cfg_first->batch_size * data1_length / 8;
        cfg_last->data1_size = cfg_last->batch_size * data1_length / 8;
        cfg_first->data2_size = cfg_first->batch_size * data2_length / 8;
        cfg_last->data2_size = cfg_last->batch_size * data2_length / 8;

        memcpy(para_first, &(cfg_first->batch_size), 32 / 8);
        memcpy(para_last, &(cfg_last->batch_size), 32 / 8);
        memcpy(para_first + 32 / 8, para + 32 / 8,
               (para_length + 256 - 32) / 8);
        memcpy(para_last + 32 / 8, para + 32 / 8, (para_length + 256 - 32) / 8);

        for (i = 0; i < total_row; i++) {       // Loop over different rows
          for (j = 0; j < card_per_row; j++) {  // Loop over different cards
            size_t index = i * card_per_row + j;
            if (j == card_per_row - 1) {
              th_para[index].cfg = cfg_last;
              th_para[index].para = para_last;
            } else {
              th_para[index].cfg = cfg_first;
              th_para[index].para = para_first;
            }
            th_para[index].cfg->fpga_dev_id = 0;
            th_para[index].data1 =
                data1 +
                (i * row_num + j * cfg_first->batch_size) * data1_length / 8;
            th_para[index].data2 =
                data2 +
                (i * row_num + j * cfg_first->batch_size) * data2_length / 8;
            th_para[index].result = result_tmp + (i * card_per_row + j) *
                                                     para_length /
                                                     8;  // 每张卡计算出一个值
          }
        }

        std::vector<std::future<void>> fut_vec;
        fut_vec.reserve(used_card_num);
        for (i = 0; i < used_card_num; i++) {
          auto fut = std::async(std::launch::async, task_split, &th_para[i]);
          fut_vec.emplace_back(std::move(fut));
        }
        for (i = 0; i < used_card_num; i++) {
          fut_vec[i].get();
          if (th_para[i].error != 0) {
            int error = th_para[i].error;
            free(para_last);
            free(para_first);
            free(result_tmp);
            free(th_para);
            return error;
          }
        }

        MPInt sum_tmp;
        sum_tmp.SetZero();
        MPInt sum_row;
        sum_row.SetZero();
        MPInt nsquare;
        nsquare.SetZero();
        nsquare.FromMagBytes({para + 256 / 8, para_length / 8}, Endian::little);
        for (i = 0; i < total_row;
             i++) {  // Loop to aggregate summation for each row
          sum_row.FromMagBytes(
              {result_tmp + (i * card_per_row) * para_length / 8,
               para_length / 8},
              Endian::little);
          for (j = 1; j < card_per_row; j++) {
            sum_tmp.FromMagBytes(
                {result_tmp + (i * card_per_row + j) * para_length / 8,
                 para_length / 8},
                Endian::little);
            sum_row = sum_row * sum_tmp;

            MPInt sum_row_mod;
            MPInt::Mod(sum_row, nsquare, &sum_row_mod);
            sum_row = std::move(sum_row_mod);
          }
          CMPIntWrapper::MPIntToBytes(sum_row, result + i * para_length / 8,
                                      para_length / 8);
        }
        free(para_last);
        free(para_first);
        free(result_tmp);
        free(th_para);
      }
      break;
    }
    default: {
      size_per_card = cfg->batch_size /
                      card_num;  // calculate average batch size for each card

      if (size_per_card <
          MODEXP_THRESHOLD) {  // batch size for each card is so small that we
                               // can save some cards
        card_num = cfg->batch_size / MODEXP_THRESHOLD +
                   1;  // appropriate number of cards
        size_per_card =
            cfg->batch_size /
            card_num;  // Batch size for the cards except for the last one
      }

      size_last_card =
          cfg->batch_size -
          (card_num - 1) * size_per_card;  // Batch size for the last card

      struct para_task *th_para =
          (struct para_task *)malloc(sizeof(struct para_task) * card_num);

      cfg_first->batch_size = size_per_card;
      cfg_last->batch_size = size_last_card;

      cfg_first->data1_size =
          (cfg->data1_size == 0) ? 0 : size_per_card * data1_length / 8;
      cfg_last->data1_size =
          (cfg->data1_size == 0) ? 0 : size_last_card * data1_length / 8;

      cfg_first->data2_size =
          (cfg->data2_size == 0) ? 0 : size_per_card * data2_length / 8;
      cfg_last->data2_size =
          (cfg->data2_size == 0) ? 0 : size_last_card * data2_length / 8;

      cfg_first->data3_size =
          (cfg->data3_size == 0) ? 0 : size_per_card * data3_length / 8;
      cfg_last->data3_size =
          (cfg->data3_size == 0) ? 0 : size_last_card * data3_length / 8;

      // printf("%zu, %zu\n%zu, %zu\n%zu, %zu\n", cfg_first->data1_size,
      // cfg_last->data1_size, cfg_first->data2_size, cfg_last->data2_size,
      // cfg_first->data3_size, cfg_last->data3_size);

      for (i = 0; i < card_num; i++) {
        if (i == card_num - 1)
          th_para[i].cfg = cfg_last;
        else
          th_para[i].cfg = cfg_first;
        th_para[i].cfg->fpga_dev_id = 128 + i;
        th_para[i].data1 = (data1 == NULL)
                               ? NULL
                               : data1 + i * size_per_card * data1_length / 8;
        th_para[i].data2 = (data2 == NULL)
                               ? NULL
                               : data2 + i * size_per_card * data2_length / 8;
        th_para[i].data3 = (data3 == NULL)
                               ? NULL
                               : data3 + i * size_per_card * data3_length / 8;
        th_para[i].para = para;
        if (operate_mode != 10)  // bitlength of the result of decryption mode
                                 // is different from others
          th_para[i].result = result + (i * size_per_card * para_length / 8);
        else
          th_para[i].result = result + (i * size_per_card * para_length / 4);
      }

      std::vector<std::future<void>> fut_vec;
      fut_vec.reserve(card_num);
      for (i = 0; i < card_num; i++) {
        auto fut = std::async(std::launch::async, task_split, &th_para[i]);
        fut_vec.emplace_back(std::move(fut));
      }
      for (i = 0; i < card_num; i++) {
        fut_vec[i].get();
        if (th_para[i].error != 0) {
          int error = th_para[i].error;
          free(cfg_last);
          free(cfg_first);
          free(th_para);
          return error;
        }
      }

      free(th_para);
      break;
    }
  }

  free(cfg_last);
  free(cfg_first);
  return rc;
}

}  // namespace heu::lib::algorithms::paillier_clustar_fpga::fpga_engine
