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

#include "heu/library/algorithms/paillier_gpu/encryptor.h"

namespace heu::lib::algorithms::paillier_g {

int GetRdrand8Bytes(unsigned char* rand, int multiple) {
  __asm__(
      "movq %0, %%rcx         \n\t"
      "mov %1, %%edx          \n\t"

      "1:             		\n\t"
      "rdrand %%rax      	\n\t"
      "jnc 1b         		\n\t"  // retry

      "movq %%rax, (%%rcx)	\n\t"
      "addq $8, %%rcx		\n\t"
      "sub $1, %%edx		\n\t"
      "jne 1b			\n\t"  // next 8 bytes
      :
      : "r"(rand), "r"(multiple)
      : "memory", "cc", "%rax", "%rcx", "%edx");

  return 0;
}

int GetRdrand(unsigned char* rand, int randlen) {
  int multiple, left;
  unsigned char buffer[8];
  // check parameters
  if (rand == NULL) {
    return 1;
  }
  if (randlen < 1) {
    return 2;
  }
  left = randlen % 8;
  multiple = (randlen - left) / 8;
  // exact multiples of 8
  if (multiple) {
    GetRdrand8Bytes(rand, multiple);
  }
  // less than 8
  if (left) {
    GetRdrand8Bytes(buffer, 1);
    memcpy(rand + 8 * multiple, buffer, left);
  }
  return 0;
}

Encryptor::Encryptor(PublicKey pk) : pk_(std::move(pk)) {}

Encryptor::Encryptor(const Encryptor& from) : Encryptor(from.pk_) {}

MPInt Encryptor::GetRn() const {
  MPInt r;
  MPInt::RandomExactBits(pk_.key_size_ / 2, &r);

  // (h_s_)^r
  MPInt out;
  pk_.m_space_->PowMod(*pk_.hs_table_, r, &out);
  return out;
}

std::vector<Ciphertext> Encryptor::EncryptZero(int64_t size) const {
  std::vector<Ciphertext> res(size);
  for (unsigned int i = 0; i < size; i++) {
    Plaintext p1(0);
    Plaintext* ppts[]{&p1};
    ConstSpan<Plaintext> pts = absl::MakeConstSpan(ppts);
    std::vector<Ciphertext> oneRes = Encrypt(pts);
    res[i] = oneRes[0];
  }
  return res;
}

std::pair<std::vector<Ciphertext>, std::vector<std::string>>
Encryptor::EncryptWithAudit(ConstSpan<Plaintext> pts) const {
  std::vector<std::string> auditStrings;
  auditStrings.resize(pts.size(), "");
  auto c = EncryptImpl<true>(pts, &auditStrings);
  return {c, auditStrings};
}

std::vector<Ciphertext> Encryptor::Encrypt(ConstSpan<Plaintext> pts) const {
  return EncryptImpl(pts);
}

template <bool audit>
std::vector<Ciphertext> Encryptor::EncryptImpl(
    ConstSpan<Plaintext> pts, std::vector<std::string>* audit_strs) const {
  // a. pubkey
  h_paillier_pubkey_t g_pk;
  pk_.n_.ToBytes(g_pk.n, 512, algorithms::Endian::little);
  pk_.n_square_.ToBytes(g_pk.n_squared, 512, algorithms::Endian::little);
  pk_.n_plus_.ToBytes(g_pk.n_plusone, 512, algorithms::Endian::little);

  // b. batch size;
  unsigned int count = pts.size();
  if constexpr (audit) {
    for (unsigned int i = 0; i < count; i++) {
      (*audit_strs)[i] = "p:{" + pts[i]->ToHexString() + "}";
    }
  }

  // c. random data;
  auto scalar = std::make_unique<h_paillier_random_t[]>(count);
  for (unsigned int i = 0; i < count; i++) {
    GetRdrand((unsigned char*)((unsigned char*)&scalar[i]),
              pk_.key_size_ / 2 / 8);  // key_size/2->get bytes need divide 8
    if constexpr (audit) {
      Plaintext randr = Plaintext(0, 512);  // init with 4096bit
      randr.FromMagBytes(yacl::ByteContainerView((uint8_t*)(scalar[i].r), 512),
                         algorithms::Endian::little);

      Plaintext out;
      pk_.m_space_->PowMod(*pk_.hs_table_, randr, &out);
      (*audit_strs)[i] += ",rn:{" + out.ToHexString() + "}";
    }
  }

  // d. Host memory to receive the data
  auto res = std::make_unique<h_paillier_ciphertext_t[]>(count);
  auto gpts = std::make_unique<h_paillier_plaintext_t[]>(count);

  Plaintext temp;
  for (unsigned int i = 0; i < count; i++) {
    YACL_ENFORCE(pts[i]->CompareAbs(pk_.PlaintextBound()) <= 0,
                 "message number out of range, message={}, max (abs)={}",
                 *pts[i], pk_.PlaintextBound());

    if (pts[i]->IsNegative()) {
      temp = (Plaintext)(*pts[i] + pk_.n_);
      temp.ToBytes(gpts[i].m, 512, algorithms::Endian::little);
    } else {
      pts[i]->ToBytes(gpts[i].m, 512, algorithms::Endian::little);
    }
  }
  // e. GPU do enc
  gpu_paillier_enc(res.get(), &g_pk, gpts.get(), scalar.get(), count);

  // f. GPU data to vector
  std::vector<Ciphertext> ctx_res(count);
  for (unsigned int i = 0; i < count; i++) {
    ctx_res[i].ct_ = res[i];
    if constexpr (audit) {
      (*audit_strs)[i] += ",c:{" + ctx_res[i].ToHexString() + "}";
    }
  }
  return ctx_res;
}

}  // namespace heu::lib::algorithms::paillier_g
