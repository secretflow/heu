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

#include "heu/library/algorithms/paillier_clustar_fpga/utils/secr_key_helper.h"
#include "heu/library/algorithms/paillier_clustar_fpga/fpga_engine/paillier_operators/fpga_types.h"

namespace heu::lib::algorithms::paillier_clustar_fpga {

CSecrKeyHelper::CSecrKeyHelper(SecretKey *secr_key, size_t key_len) : secr_key_(secr_key) {
    CreateBytesStore(key_len);
}

CSecrKeyHelper::~CSecrKeyHelper() {
    secr_key_ = nullptr;
}

void CSecrKeyHelper::CreateBytesStore(size_t key_len) {
    fpga_engine::CKeyLenConfig key_conf(key_len);
    cipher_byte_ = key_conf.cipher_byte_;

    //
    std::shared_ptr<char[]> loc_bytes_p(new char[cipher_byte_]);
    bytes_p_ = std::move(loc_bytes_p);

    //
    std::shared_ptr<char[]> loc_bytes_q(new char[cipher_byte_]);
    bytes_q_ = std::move(loc_bytes_q);

    //
    std::shared_ptr<char[]> loc_bytes_p_square(new char[cipher_byte_]);
    bytes_p_square_ = std::move(loc_bytes_p_square);

    //
    std::shared_ptr<char[]> loc_bytes_q_square(new char[cipher_byte_]);
    bytes_q_square_ = std::move(loc_bytes_q_square);

    //
    std::shared_ptr<char[]> loc_bytes_q_inverse(new char[cipher_byte_]);
    bytes_q_inverse_ = std::move(loc_bytes_q_inverse);

    //
    std::shared_ptr<char[]> loc_bytes_hp(new char[cipher_byte_]);
    bytes_hp_ = std::move(loc_bytes_hp);

    //
    std::shared_ptr<char[]> loc_bytes_hq(new char[cipher_byte_]);
    bytes_hq_ = std::move(loc_bytes_hq);
}

// Transform secret key members to bytes:
// 1) p
// 2) q
// 3) p_square
// 4) q_square
// 5) q_inverse
// 6) hp
// 7) hq
void CSecrKeyHelper::TransformToBytes() const {
    // 1) p
    ToBytes(secr_key_->p_, byte_p_flag_, bytes_p_.get());

    // 2) q
    ToBytes(secr_key_->q_, byte_q_flag_, bytes_q_.get());

    // 3) p_square
    ToBytes(secr_key_->p_square_, byte_p_square_flag_, bytes_p_square_.get());

    // 4) q_square
    ToBytes(secr_key_->q_square_, byte_q_square_flag_, bytes_q_square_.get());

    // 5) q_inverse
    ToBytes(secr_key_->q_inverse_, byte_q_inverse_flag_, bytes_q_inverse_.get());

    // 6) hp
    ToBytes(secr_key_->hp_, hp_flag_, bytes_hp_.get());

    // 7) hq
    ToBytes(secr_key_->hq_, hq_flag_, bytes_hq_.get());
}

char* CSecrKeyHelper::GetBytesP() const {
    if (!byte_p_flag_) {
        YACL_THROW("secret_key p not transformed to bytes yet");
    }

    return bytes_p_.get();
}

char* CSecrKeyHelper::GetBytesQ() const {
    if (!byte_q_flag_) {
        YACL_THROW("secret_key q not transformed to bytes yet");
    }

    return bytes_q_.get();
}

char* CSecrKeyHelper::GetBytesPSquare() const {
    if (!byte_p_square_flag_) {
        YACL_THROW("secret_key p_square not transformed to bytes yet");
    }

    return bytes_p_square_.get();
}

char* CSecrKeyHelper::GetBytesQSquare() const {
    if (!byte_q_square_flag_) {
        YACL_THROW("secret_key q_square not transformed to bytes yet");
    }

    return bytes_q_square_.get();
}

char* CSecrKeyHelper::GetBytesQInverse() const {
    if (!byte_q_inverse_flag_) {
        YACL_THROW("secret_key q_inverse not transformed to bytes yet");
    }

    return bytes_q_inverse_.get();
}

char* CSecrKeyHelper::GetBytesHP() const {
    if (!hp_flag_) {
        YACL_THROW("secret_key hp not transformed to bytes yet");
    }

    return bytes_hp_.get();
}

char* CSecrKeyHelper::GetBytesHQ() const {
    if (!hq_flag_) {
        YACL_THROW("secret_key hq not transformed to bytes yet");
    }

    return bytes_hq_.get();
}

void CSecrKeyHelper::ToBytes(const MPInt& input, bool& exe_flag, char* result_arr) const {
    memset(result_arr, 0, cipher_byte_);
    input.ToBytes(reinterpret_cast<unsigned char*>(result_arr), cipher_byte_, Endian::little);
    exe_flag = true;
}

} // heu::lib::algorithms::paillier_clustar_fpga