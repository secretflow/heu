// Copyright 2023 Polar Bear Tech (Xi 'an) Co., LTD.
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

#include "heu/library/algorithms/leichi_paillier/vector_encryptor.h"
#include "heu/library/algorithms/leichi_paillier/runtime.h"
namespace heu::lib::algorithms::leichi_paillier {

    std::vector<Ciphertext> Encryptor::EncryptZero(int64_t size) const {
        Runtime _runtime;
        uint8_t *r_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits())*size];
        uint8_t *m_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits())*size];
        uint8_t *ct_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits()*2)*size];
        uint32_t r_offset = 0;
        uint32_t m_offset = 0;
        uint32_t ct_offset = 0;
        uint32_t ct_len =0;
        
        struct _paillier_key paillier_key;
        paillier_key.public_key.n = Tobin(pk_.n_);
        paillier_key.public_key.g = Tobin(pk_.g_);
        paillier_key.public_key.n_bitcount = pk_.n_.numBits();

        std::vector<Ciphertext> result(size);
        Plaintext pt_neg_zero;
        pt_neg_zero.Set(0);

        std::vector<uint8_t> m_flg;
        for (int64_t i = 0;i<size;i++) 
        {
                m_flg.push_back(0);
        }
        for (int64_t i = 0;i<size;i++) {
            BN_bn2binpad(Plaintext::generateRandom(pk_.n_).bn_,r_bytes+r_offset,BYTECOUNT(pk_.n_.numBits()));
            r_offset += BYTECOUNT(pk_.n_.numBits());
            BN_bn2binpad(pt_neg_zero.bn_,m_bytes+m_offset,BYTECOUNT(pk_.n_.numBits()));
            m_offset += BYTECOUNT(pk_.n_.numBits());
        }

         if(_runtime.dev_connect())
        {
            // _runtime.dev_reset();
            _runtime.paillier_encrypt(m_bytes,r_bytes,m_flg,size,paillier_key.public_key,ct_bytes,ct_len);
            for (int64_t i = 0; i < size; i++) {
                BN_bin2bn(ct_bytes+ct_offset,BYTECOUNT(pk_.n_.numBits()*2),result[i].bn_);
                ct_offset +=BYTECOUNT(pk_.n_.numBits()*2);
            }
        }
        _runtime.dev_close();
        delete []r_bytes;
        delete []m_bytes;
        delete []ct_bytes;
        m_flg.clear();
        return result;
    }
    int CompareBignum(const BIGNUM* bn1, const BIGNUM* bn2) {
        return BN_cmp(bn1, bn2);
    }

    std::vector<Ciphertext> Encryptor::Encrypt(ConstSpan<Plaintext> pts) const {
        std::vector<Ciphertext> result(pts.size());
        Runtime _runtime;
        uint8_t *r_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits())*pts.size()];
        uint8_t *m_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits())*pts.size()];
        uint8_t *ct_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits()*2)*pts.size()];
        uint32_t r_offset = 0;
        uint32_t m_offset = 0;
        uint32_t ct_offset = 0;
        uint32_t ct_len =0;
        std::vector<uint8_t> m_flg;
        struct _paillier_key paillier_key;
        paillier_key.public_key.n = Tobin(pk_.n_);
        paillier_key.public_key.g = Tobin(pk_.g_);
        paillier_key.public_key.n_bitcount = pk_.n_.numBits();

        for (auto item : pts) {
            YACL_ENFORCE(CompareBignum(item->bn_, max_plaintext.bn_) < 0,
                        "Plaintext out of range");
            BN_bn2binpad(Plaintext::generateRandom(pk_.n_).bn_,r_bytes+r_offset,BYTECOUNT(pk_.n_.numBits()));
            r_offset += BYTECOUNT(pk_.n_.numBits());
            BN_bn2binpad(item->bn_,m_bytes+m_offset,BYTECOUNT(pk_.n_.numBits()));
            m_offset += BYTECOUNT(pk_.n_.numBits());
        }

        for (auto item : pts) 
        {
            if(BN_is_negative(item->bn_))
            {
                m_flg.push_back(1);
            }
            else
            {
                m_flg.push_back(0);
            }
        }

        if(_runtime.dev_connect())
        {
            // _runtime.dev_reset();
            _runtime.paillier_encrypt(m_bytes,r_bytes,m_flg,pts.size(),paillier_key.public_key,ct_bytes,ct_len);
            for (std::size_t i = 0; i < pts.size(); i++) {
                BN_bin2bn(ct_bytes+ct_offset,BYTECOUNT(pk_.n_.numBits()*2),result[i].bn_);
                ct_offset +=BYTECOUNT(pk_.n_.numBits()*2);
            }
        }
        _runtime.dev_close();
        delete []r_bytes;
        delete []m_bytes;
        delete []ct_bytes;
        m_flg.clear();
        return result;
    }
}