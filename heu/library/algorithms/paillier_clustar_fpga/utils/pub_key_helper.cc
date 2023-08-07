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

#include "heu/library/algorithms/paillier_clustar_fpga/utils/pub_key_helper.h"
#include "heu/library/algorithms/paillier_clustar_fpga/fpga_engine/paillier_operators/fpga_types.h"

namespace heu::lib::algorithms::paillier_clustar_fpga {

CPubKeyHelper::CPubKeyHelper(PublicKey *pub_key) : pub_key_(pub_key) {
    CreateBytesStore(pub_key_->GetN().BitCount());
}

CPubKeyHelper::~CPubKeyHelper() {
    pub_key_ = nullptr;
}

void CPubKeyHelper::CreateBytesStore(size_t key_len) {
    fpga_engine::CKeyLenConfig key_conf(key_len);
    cipher_byte_ = key_conf.cipher_byte_;

    //
    std::shared_ptr<char[]> loc_bytes_g(new char[cipher_byte_]);
    bytes_g_ = std::move(loc_bytes_g);

    //
    std::shared_ptr<char[]> loc_bytes_n(new char[cipher_byte_]);
    bytes_n_ = std::move(loc_bytes_n);

    // 
    std::shared_ptr<char[]> loc_bytes_n_square(new char[cipher_byte_]);
    bytes_n_square_ = std::move(loc_bytes_n_square);

    //
    std::shared_ptr<char[]> loc_bytes_max_int(new char[cipher_byte_]);
    bytes_max_int_ = std::move(loc_bytes_max_int);
}

// Transform public key to bytes:
// 1) g
// 2) n
// 3) n_square
// 4) max_int
void CPubKeyHelper::TransformToBytes() const {
    // 1) g
    ToBytes(pub_key_->g_, byte_g_flag_, bytes_g_.get());

    // 2) n
    ToBytes(pub_key_->n_, byte_n_flag_, bytes_n_.get());

    // 3) n_square
    ToBytes(pub_key_->n_square_, byte_n_square_flag_, bytes_n_square_.get());
    
    // 4) max_int
    ToBytes(pub_key_->max_int_, byte_max_int_flag_, bytes_max_int_.get());
}

char* CPubKeyHelper::GetBytesG() const {
    if (!byte_g_flag_) {
        YACL_THROW("public_key g not transformed to bytes yet");
    }

    return bytes_g_.get();
}

char* CPubKeyHelper::GetBytesN() const {
    if (!byte_n_flag_) {
        YACL_THROW("public_key n not transformed to bytes yet");
    }

    return bytes_n_.get();
}

char* CPubKeyHelper::GetBytesNSquare() const {
    if (!byte_n_square_flag_) {
        YACL_THROW("public_key n_square not transformed to bytes yet");
    }

    return bytes_n_square_.get();
}

char* CPubKeyHelper::GetBytesMaxInt() const {
    if (!byte_max_int_flag_) {
        YACL_THROW("public_key max_int not transformed to bytes yet");
    }

    return bytes_max_int_.get();
}

} // heu::lib::algorithms::paillier_clustar_fpga
