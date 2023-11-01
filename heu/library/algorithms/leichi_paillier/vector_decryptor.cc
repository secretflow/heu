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

#include "heu/library/algorithms/leichi_paillier/vector_decryptor.h"
#include "heu/library/algorithms/leichi_paillier/runtime.h"
namespace heu::lib::algorithms::leichi_paillier {
void Decryptor::Decrypt(ConstSpan<Ciphertext> in_cts, Span<Plaintext> out_pts) const {

    Runtime _runtime;
    std::vector<Plaintext> _pts(in_cts.size());
    uint8_t *ct_bytes = new uint8_t[in_cts.size()*BYTECOUNT(pk_.n_.numBits()*2)];
    uint8_t *pt_bytes = new uint8_t[in_cts.size()*BYTECOUNT(pk_.n_.numBits())];
    memset(pt_bytes,0,in_cts.size()*BYTECOUNT(pk_.n_.numBits()));
    uint8_t *pt_flg = new uint8_t[in_cts.size()*BYTECOUNT(pk_.n_.numBits())];
    memset(pt_flg,0,in_cts.size());
    uint32_t ct_offset = 0;
    uint32_t pt_offset = 0;
    struct _paillier_key paillier_key;
    paillier_key.private_key.p = Tobin(sk_.p_);
    paillier_key.private_key.q = Tobin(sk_.q_);
    paillier_key.private_key.n_bitcount = pk_.n_.numBits();

    for (auto item : in_cts) {
        BN_bn2binpad(item->bn_,ct_bytes+ct_offset,BYTECOUNT(pk_.n_.numBits()*2));
        ct_offset += BYTECOUNT(pk_.n_.numBits()*2);
    }

    if(_runtime.dev_connect())
    {
        _runtime.paillier_decrypt(ct_bytes,in_cts.size(),paillier_key.private_key,pt_bytes,pt_flg);
        for (size_t i = 0; i < _pts.size(); i++) {
            BN_bin2bn(pt_bytes+pt_offset,BYTECOUNT(pk_.n_.numBits()),_pts[i].bn_);
            pt_offset +=BYTECOUNT(pk_.n_.numBits());
            if(pt_flg[i]  == 1)
            {
                BN_set_negative(_pts[i].bn_,1);
            }
        }

        std::reverse(_pts.begin(),_pts.end());
        for (size_t i = 0; i < _pts.size(); i++) {
            *out_pts[i] = Plaintext(_pts[i]);
        }
    }
    _runtime.dev_close();
    delete []pt_bytes;
    delete []ct_bytes;
    delete []pt_flg;
}

std::vector<Plaintext> Decryptor::Decrypt(ConstSpan<Ciphertext> cts) const 
{
    Runtime _runtime;
    std::vector<Plaintext> _pts(cts.size());
    uint8_t *ct_bytes = new uint8_t[cts.size()*BYTECOUNT(pk_.n_.numBits()*2)];
    uint8_t *pt_bytes = new uint8_t[cts.size()*BYTECOUNT(pk_.n_.numBits())];
    memset(pt_bytes,0,cts.size()*BYTECOUNT(pk_.n_.numBits()));
    uint8_t *pt_flg = new uint8_t[cts.size()*BYTECOUNT(pk_.n_.numBits())];
    memset(pt_flg,0,cts.size());
    uint32_t ct_offset = 0;
    uint32_t pt_offset = 0;
    struct _paillier_key paillier_key;
    paillier_key.private_key.p = Tobin(sk_.p_);
    paillier_key.private_key.q = Tobin(sk_.q_);
    paillier_key.private_key.n_bitcount = pk_.n_.numBits();

    for (auto item : cts) {
        BN_bn2binpad(item->bn_,ct_bytes+ct_offset,BYTECOUNT(pk_.n_.numBits()*2));
        ct_offset += BYTECOUNT(pk_.n_.numBits()*2);
    }

    if(_runtime.dev_connect())
    {
        _runtime.paillier_decrypt(ct_bytes,cts.size(),paillier_key.private_key,pt_bytes,pt_flg);
        for (std::size_t i = 0; i < _pts.size(); i++) {
            BN_bin2bn(pt_bytes+pt_offset,BYTECOUNT(pk_.n_.numBits()),_pts[i].bn_);
            pt_offset +=BYTECOUNT(pk_.n_.numBits());
            if(pt_flg[i]  == 1)
            {
                BN_set_negative(_pts[i].bn_,1);
            }
        }
        std::reverse(_pts.begin(),_pts.end());
    }
    _runtime.dev_close();
    delete []pt_bytes;
    delete []ct_bytes;
    delete []pt_flg;
  return _pts;
}

}  // namespace heu::lib::algorithms::leichi_paillier