// Copyright 2023 Ant Group Co., Ltd.
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

#include "heu/library/algorithms/paillier_gpu/decryptor.h"

#include "heu/library/algorithms/util/he_assert.h"

namespace heu::lib::algorithms::paillier_g {

std::vector<Plaintext> Decryptor::Decrypt(ConstSpan<Ciphertext> cts) const {
  // a. pubkey;
  h_paillier_pubkey_t g_pk;
  pk_.n_.ToBytes(g_pk.n, 512, algorithms::Endian::little);
  pk_.n_square_.ToBytes(g_pk.n_squared, 512, algorithms::Endian::little);
  pk_.n_plus_.ToBytes(g_pk.n_plusone, 512, algorithms::Endian::little);

  // b. prikey;
  h_paillier_prvkey_t g_sk;
  sk_.lambda_.ToBytes(g_sk.lambda, 512, algorithms::Endian::little);
  sk_.mu_.ToBytes(g_sk.x, 512, algorithms::Endian::little);

  // c. batch size;
  unsigned int count = cts.size();

  // d. Host memory to receive the data
  auto gcts = std::make_unique<h_paillier_ciphertext_t[]>(count);
  auto gpts = std::make_unique<h_paillier_plaintext_t[]>(count);
  for (unsigned int i = 0; i < count; i++) {
    gcts[i] = cts[i]->ct_;
  }

  // e. GPU do dec
  gpu_paillier_dec(gpts.get(), &g_pk, &g_sk, gcts.get(), count);

  // f. res->std::vector<Ciphertext>
  std::vector<Plaintext> ptx_res(count);
  for (unsigned int i = 0; i < count; i++) {
    ptx_res[i] = Plaintext(0, 512);
    ptx_res[i].FromMagBytes(yacl::ByteContainerView((uint8_t*)(gpts[i].m), 512),
                            algorithms::Endian::little);

    // if the value is negative (the judgment condition is greater than n/2),
    // then -n
    if (ptx_res[i] > pk_.n_half_) {
      ptx_res[i] -= pk_.n_;
    }
  }

  return ptx_res;
}

void Decryptor::Decrypt(ConstSpan<Ciphertext> in_cts,
                        Span<Plaintext> out_pts) const {
  std::vector<Plaintext> res = Decrypt(in_cts);
  for (unsigned int i = 0; i < res.size(); i++) {
    *out_pts[i] = res[i];
  }
}

}  // namespace heu::lib::algorithms::paillier_g
