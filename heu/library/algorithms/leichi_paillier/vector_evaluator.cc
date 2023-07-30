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

#include "heu/library/algorithms/leichi_paillier/vector_evaluator.h"
#include "heu/library/algorithms/leichi_paillier/vector_encryptor.h"
#include "heu/library/algorithms/util/he_assert.h"
#include "heu/library/algorithms/leichi_paillier/runtime.h"
namespace heu::lib::algorithms::leichi_paillier {
    void Evaluator::Randomize(Span<Ciphertext> ct) const {

    }
    std::vector<Ciphertext> Evaluator::Add(ConstSpan<Ciphertext> a,
                                        ConstSpan<Ciphertext> b) const {
        std::vector<Ciphertext> result(a.size());
        struct _paillier_key paillier_key;
        paillier_key.public_key.n = Tobin(pk_.n_);
        paillier_key.public_key.g = Tobin(pk_.g_);
        paillier_key.public_key.n_bitcount = pk_.n_.numBits();

        uint8_t *a_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits()*2)*a.size()];
        uint8_t *b_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits()*2)*a.size()];
        uint8_t *out_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits()*2)*a.size()];
        uint32_t a_len = a.size()*BYTECOUNT(pk_.n_.numBits()*2);
        uint32_t b_len = b.size()*BYTECOUNT(pk_.n_.numBits()*2);
        uint32_t vec_size = a.size();
        uint32_t output_len = 0;
        uint32_t a_offset = 0;
        uint32_t b_offset = 0;
        uint32_t out_offset = 0;

        for (auto item : a) {
            BN_bn2binpad(item->bn_,a_bytes+a_offset,BYTECOUNT(pk_.n_.numBits()*2));
            a_offset += BYTECOUNT(pk_.n_.numBits()*2);
        }

        for (auto item : b) {
            BN_bn2binpad(item->bn_,b_bytes+b_offset,BYTECOUNT(pk_.n_.numBits()*2));
            b_offset += BYTECOUNT(pk_.n_.numBits()*2);
        }
        Runtime _runtime;
        if(_runtime.dev_connect())
        {
            _runtime.paillier_add(a_bytes,a_len,b_bytes,b_len,vec_size,out_bytes,output_len,paillier_key.public_key);
            for (std::size_t i = 0; i < a.size(); i++) {
                BN_bin2bn(out_bytes+out_offset,BYTECOUNT(pk_.n_.numBits()*2),result[i].bn_);
                out_offset +=BYTECOUNT(pk_.n_.numBits()*2);
            }
        }
        _runtime.dev_close();
        
        delete [] a_bytes;
        delete [] b_bytes;
        delete [] out_bytes;
        return result;
    }

    std::vector<Ciphertext> Evaluator::Add(ConstSpan<Ciphertext> a,
                                        ConstSpan<Plaintext> b) const {
        std::vector<Ciphertext> result(a.size());
        struct _paillier_key paillier_key;
        paillier_key.public_key.n = Tobin(pk_.n_);
        paillier_key.public_key.g = Tobin(pk_.g_);
        paillier_key.public_key.n_bitcount = pk_.n_.numBits();

        uint8_t *a_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits()*2)*a.size()];
        uint8_t *b_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits())*a.size()];
        uint8_t *out_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits()*2)*a.size()];
        uint32_t a_len = a.size()*BYTECOUNT(pk_.n_.numBits()*2);
        uint32_t vec_size = a.size();
        uint32_t output_len = 0;
        uint32_t a_offset = 0;
        uint32_t b_offset = 0;
        uint32_t out_offset = 0;

        for (auto item : a) {
            BN_bn2binpad(item->bn_,a_bytes+a_offset,BYTECOUNT(pk_.n_.numBits()*2));
            a_offset += BYTECOUNT(pk_.n_.numBits()*2);
        }
        uint8_t *r_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits())*b.size()];
        uint32_t r_offset = 0;
        uint8_t *ct_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits()*2)*b.size()];
        uint32_t ct_len =0;
        std::vector<uint8_t> b_flg;

        for (auto item_b : b) {
            BN_bn2binpad(Plaintext::generateRandom(pk_.n_).bn_,r_bytes+r_offset,BYTECOUNT(pk_.n_.numBits()));
            r_offset += BYTECOUNT(pk_.n_.numBits());
            BN_bn2binpad(item_b->bn_,b_bytes+b_offset,BYTECOUNT(pk_.n_.numBits()));
            b_offset += BYTECOUNT(pk_.n_.numBits());
        }
        
        for (auto item : b) 
        {
            if(BN_is_negative(item->bn_))
            {
                b_flg.push_back(1);
            }
            else
            {
                b_flg.push_back(0);
            }
        }
        Runtime _runtime;
        if(_runtime.dev_connect())
        {

            _runtime.paillier_encrypt(b_bytes,r_bytes,b_flg,b.size(),paillier_key.public_key,ct_bytes,ct_len);
            _runtime.paillier_add(a_bytes,a_len,ct_bytes,ct_len,vec_size,out_bytes,output_len,paillier_key.public_key);
            for (std::size_t i = 0; i < a.size(); i++) {
                BN_bin2bn(out_bytes+out_offset,BYTECOUNT(pk_.n_.numBits()*2),result[i].bn_);
                out_offset +=BYTECOUNT(pk_.n_.numBits()*2);
            }
        }
        _runtime.dev_close();
        
        delete [] a_bytes;
        delete [] b_bytes;
        delete [] out_bytes;
        delete [] r_bytes;
        delete [] ct_bytes;
        b_flg.clear();
        return result;
    }

    std::vector<Ciphertext> Evaluator::Add(ConstSpan<Plaintext> a,
                                        ConstSpan<Ciphertext> b) const {
        return Add(b, a);
    }

    std::vector<Plaintext> Evaluator::Add(ConstSpan<Plaintext> a,
                                        ConstSpan<Plaintext> b) const {
        HE_ASSERT(a.size() == b.size(), "PT + PT error: size mismatch.");
        std::vector<Plaintext> sum;
        size_t vec_size = a.size();
        for (size_t i = 0; i < vec_size; i++) {
            sum.push_back(*a[i] + *b[i]);
        }
        return sum;
    }

    void Evaluator::AddInplace(Span<Ciphertext> a, ConstSpan<Ciphertext> b) const {
        auto sum = Add(a, b);
        size_t vec_size = sum.size();
        for (size_t i = 0; i < vec_size; i++) {
            *a[i] = sum[i];
        }
    }

    void Evaluator::AddInplace(Span<Ciphertext> a, ConstSpan<Plaintext> b) const {
        auto sum = Add(a, b);
        size_t vec_size = sum.size();
        for (size_t i = 0; i < vec_size; i++) {
            *a[i] = sum[i];
        }
    }

    void Evaluator::AddInplace(Span<Plaintext> a, ConstSpan<Plaintext> b) const {
        auto sum = Add(a, b);
        size_t vec_size = sum.size();
        for (size_t i = 0; i < vec_size; i++) {
            *a[i] = sum[i];
        }
    }

    std::vector<Ciphertext> Evaluator::Sub(ConstSpan<Ciphertext> a,
                                        ConstSpan<Ciphertext> b) const {
        std::vector<Ciphertext> result(a.size());
        HE_ASSERT(a.size() == b.size(), "CT - CT error: size mismatch.");
        struct _paillier_key paillier_key;
        paillier_key.public_key.n = Tobin(pk_.n_);
        paillier_key.public_key.g = Tobin(pk_.g_);
        paillier_key.public_key.n_bitcount = pk_.n_.numBits();
        uint8_t *a_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits()*2)*a.size()];
        uint8_t *b_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits())*2*a.size()];
        uint8_t *out_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits()*2)*a.size()];
        uint32_t a_len = a.size()*BYTECOUNT(pk_.n_.numBits()*2);
        uint32_t b_len = b.size()*BYTECOUNT(pk_.n_.numBits()*2);
        uint32_t vec_size = a.size();
        uint32_t output_len = 0;
        uint32_t a_offset = 0;
        uint32_t b_offset = 0;
        uint32_t out_offset = 0;

        for (auto item : a) {
            BN_bn2binpad(item->bn_,a_bytes+a_offset,BYTECOUNT(pk_.n_.numBits()*2));
            a_offset += BYTECOUNT(pk_.n_.numBits()*2);
        }

        for (auto item : b) {
            BN_bn2binpad(item->bn_,b_bytes+b_offset,BYTECOUNT(pk_.n_.numBits()*2));
            b_offset += BYTECOUNT(pk_.n_.numBits()*2);
        }

        Runtime _runtime;
        if(_runtime.dev_connect())
        {
            _runtime.paillier_sub(a_bytes,a_len,b_bytes,b_len,vec_size,out_bytes,output_len,paillier_key.public_key);
            for (std::size_t i = 0; i < a.size(); i++) {
                BN_bin2bn(out_bytes+out_offset,BYTECOUNT(pk_.n_.numBits()*2),result[i].bn_);
                out_offset +=BYTECOUNT(pk_.n_.numBits()*2);
            }
        }
        
        _runtime.dev_close();
        delete [] a_bytes;
        delete [] b_bytes;
        delete [] out_bytes;
        return result;
    }

    std::vector<Ciphertext> Evaluator::Sub(ConstSpan<Ciphertext> a,
                                        ConstSpan<Plaintext> b) const {
        HE_ASSERT(a.size() == b.size(), "CT - PT error: size mismatch.");
        std::vector<Ciphertext> result(a.size());
        struct _paillier_key paillier_key;
        paillier_key.public_key.n = Tobin(pk_.n_);
        paillier_key.public_key.g = Tobin(pk_.g_);
        paillier_key.public_key.n_bitcount = pk_.n_.numBits();
        uint8_t *a_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits()*2)*a.size()];
        uint8_t *b_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits())*2*a.size()];
        uint8_t *out_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits()*2)*a.size()];
        uint32_t a_len = a.size()*BYTECOUNT(pk_.n_.numBits()*2);
        uint32_t vec_size = a.size();
        uint32_t output_len = 0;
        uint32_t a_offset = 0;
        uint32_t b_offset = 0;
        uint32_t out_offset = 0;

        for (auto item : a) {
            BN_bn2binpad(item->bn_,a_bytes+a_offset,BYTECOUNT(pk_.n_.numBits()*2));
            a_offset += BYTECOUNT(pk_.n_.numBits()*2);
        }

        uint8_t *r_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits())*b.size()];
        uint32_t r_offset = 0;
        uint8_t *ct_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits()*2)*b.size()];
        uint32_t ct_len =0;
        std::vector<uint8_t> b_flg;

        for (auto item : b) {
            BN_bn2binpad(Plaintext::generateRandom(pk_.n_).bn_,r_bytes+r_offset,BYTECOUNT(pk_.n_.numBits()));
            r_offset += BYTECOUNT(pk_.n_.numBits());
            BN_bn2binpad(item->bn_,b_bytes+b_offset,BYTECOUNT(pk_.n_.numBits()));
            b_offset += BYTECOUNT(pk_.n_.numBits());
        }

        for (auto item : b) 
        {
            if(BN_is_negative(item->bn_))
            {
                b_flg.push_back(1);
            }
            else
            {
                b_flg.push_back(0);
            }
        }

        Runtime _runtime;
        if(_runtime.dev_connect())
        {
            _runtime.paillier_encrypt(b_bytes,r_bytes,b_flg,b.size(),paillier_key.public_key,ct_bytes,ct_len);
            _runtime.paillier_sub(a_bytes,a_len,ct_bytes,ct_len,vec_size,out_bytes,output_len,paillier_key.public_key);
            for (std::size_t i = 0; i < a.size(); i++) {
                BN_bin2bn(out_bytes+out_offset,BYTECOUNT(pk_.n_.numBits()*2),result[i].bn_);
                out_offset +=BYTECOUNT(pk_.n_.numBits()*2);
            }
        }
        _runtime.dev_close();
        delete [] a_bytes;
        delete [] b_bytes;
        delete [] out_bytes;
        delete [] r_bytes;
        delete [] ct_bytes;
        b_flg.clear();
        return result;
    }

    std::vector<Ciphertext> Evaluator::Sub(ConstSpan<Plaintext> a,
                                        ConstSpan<Ciphertext> b) const {
        HE_ASSERT(a.size() == b.size(), "CT - PT error: size mismatch.");
        std::vector<Ciphertext> result(a.size());
        struct _paillier_key paillier_key;
        paillier_key.public_key.n = Tobin(pk_.n_);
        paillier_key.public_key.g = Tobin(pk_.g_);
        paillier_key.public_key.n_bitcount = pk_.n_.numBits();
        uint8_t *a_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits()*2)*a.size()];
        uint8_t *b_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits())*2*a.size()];
        uint8_t *out_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits()*2)*a.size()];
        uint32_t b_len = b.size()*BYTECOUNT(pk_.n_.numBits()*2);
        uint32_t vec_size = a.size();
        uint32_t output_len = 0;
        uint32_t a_offset = 0;
        uint32_t b_offset = 0;
        uint32_t out_offset = 0;

        for (auto item : b) {
            BN_bn2binpad(item->bn_,b_bytes+b_offset,BYTECOUNT(pk_.n_.numBits()*2));
            b_offset += BYTECOUNT(pk_.n_.numBits()*2);
        }

        uint8_t *r_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits())*b.size()];
        uint32_t r_offset = 0;
        uint8_t *ct_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits()*2)*b.size()];
        uint32_t ct_len =0;

        for (auto item : a) {
            BN_bn2binpad(Plaintext::generateRandom(pk_.n_).bn_,r_bytes+r_offset,BYTECOUNT(pk_.n_.numBits()));
            r_offset += BYTECOUNT(pk_.n_.numBits());
            BN_bn2binpad(item->bn_,a_bytes+a_offset,BYTECOUNT(pk_.n_.numBits()));
            a_offset += BYTECOUNT(pk_.n_.numBits());
        }
        std::vector<uint8_t> a_flg;
        for (auto item : a) 
        {
            if(BN_is_negative(item->bn_))
            {
                a_flg.push_back(1);
            }
            else
            {
                a_flg.push_back(0);
            }
        }

        Runtime _runtime;
        if(_runtime.dev_connect())
        {
            _runtime.paillier_encrypt(a_bytes,r_bytes,a_flg,b.size(),paillier_key.public_key,ct_bytes,ct_len);
            _runtime.paillier_sub(ct_bytes,ct_len,b_bytes,b_len,vec_size,out_bytes,output_len,paillier_key.public_key);
            for (std::size_t i = 0; i < a.size(); i++) {
                BN_bin2bn(out_bytes+out_offset,BYTECOUNT(pk_.n_.numBits()*2),result[i].bn_);
                out_offset +=BYTECOUNT(pk_.n_.numBits()*2);
            }
        }
        _runtime.dev_close();
        delete [] a_bytes;
        delete [] b_bytes;
        delete [] out_bytes;
        delete [] r_bytes;
        delete [] ct_bytes;
        return result;
    }

    std::vector<Plaintext> Evaluator::Sub(ConstSpan<Plaintext> a,
                                        ConstSpan<Plaintext> b) const {
        HE_ASSERT(a.size() == b.size(), "PT - PT error: size mismatch.");
        size_t size = a.size();
        std::vector<Plaintext> result;
        for (size_t i = 0; i < size; i++) {
            result.push_back(*a[i] - *b[i]);
        }
        return result;
    }

    void Evaluator::SubInplace(Span<Ciphertext> a, ConstSpan<Ciphertext> b) const {
        auto res = Sub(a, b);
        size_t vec_size = res.size();
        for (size_t i = 0; i < vec_size; i++) {
            *a[i] = res[i];
        }
    }
    void Evaluator::SubInplace(Span<Ciphertext> a, ConstSpan<Plaintext> p) const {
        auto res = Sub(a, p);
        size_t vec_size = res.size();
        for (size_t i = 0; i < vec_size; i++) {
            *a[i] = res[i];
        }
    }
    void Evaluator::SubInplace(Span<Plaintext> a, ConstSpan<Plaintext> b) const {
        auto res = Sub(a, b);
        size_t vec_size = res.size();
        for (size_t i = 0; i < vec_size; i++) {
            *a[i] = res[i];
        }
    }

    std::vector<Ciphertext> Evaluator::Mul(ConstSpan<Ciphertext> a,
                                        ConstSpan<Plaintext> b) const {
        HE_ASSERT((a.size() == b.size() || b.size() == 1),
                    "CT * PT error: size mismatch.");
        std::vector<Ciphertext> result(a.size());

        struct _paillier_key paillier_key;
        paillier_key.public_key.n = Tobin(pk_.n_);
        paillier_key.public_key.g = Tobin(pk_.g_);
        paillier_key.public_key.n_bitcount = pk_.n_.numBits();

        uint8_t *a_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits()*2)*a.size()];
        uint8_t *b_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits())*a.size()];
        uint8_t *out_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits()*2)*a.size()];
        uint32_t a_len = a.size()*BYTECOUNT(pk_.n_.numBits()*2);
        uint32_t b_len = b.size();
        uint32_t vec_size = a.size();
        uint32_t output_len = 0;
        uint32_t a_offset = 0;
        uint32_t b_offset = 0;
        uint32_t out_offset = 0;

        for (auto item : a) {
            BN_bn2binpad(item->bn_,a_bytes+a_offset,BYTECOUNT(pk_.n_.numBits()*2));
            a_offset += BYTECOUNT(pk_.n_.numBits()*2);
        }

        for (auto item : b) {
            BN_bn2binpad(item->bn_,b_bytes+b_offset,BYTECOUNT(pk_.n_.numBits()));
            b_offset += BYTECOUNT(pk_.n_.numBits());
        }

        Runtime _runtime;
        if(_runtime.dev_connect())
        {
            _runtime.paillier_mul(a_bytes,a_len,b_bytes,b_len,vec_size,out_bytes,output_len,paillier_key.public_key);
            for (std::size_t i = 0; i < a.size(); i++) {
                BN_bin2bn(out_bytes+out_offset,BYTECOUNT(pk_.n_.numBits()*2),result[i].bn_);
                out_offset +=BYTECOUNT(pk_.n_.numBits()*2);
            }
        }
        _runtime.dev_close();
        
        delete [] a_bytes;
        delete [] b_bytes;
        delete [] out_bytes;
        return result;
    }

    std::vector<Ciphertext> Evaluator::Mul(ConstSpan<Plaintext> a,
                                        ConstSpan<Ciphertext> b) const {
        return Mul(b, a);
    }

    std::vector<Plaintext> Evaluator::Mul(ConstSpan<Plaintext> a,
                                        ConstSpan<Plaintext> b) const {
        HE_ASSERT((a.size() == b.size() || b.size() == 1),
                    "PT * PT error: size mismatch.");
        std::vector<Plaintext> product;
        size_t vec_size = a.size();
        if (b.size() == 1) {
            for (size_t i = 0; i < vec_size; i++) {
            product.push_back(*a[i] * *b[0]);
            }
        } else {
            for (size_t i = 0; i < vec_size; i++) {
            product.push_back(*a[i] * *b[i]);
            }
        }
        return product;
    }

    void Evaluator::MulInplace(Span<Ciphertext> a, ConstSpan<Plaintext> b) const {
        auto product = Mul(a, b);
        size_t vec_size = product.size();
        for (size_t i = 0; i < vec_size; i++) {
            *a[i] = product[i];
        }
    }

    void Evaluator::MulInplace(Span<Plaintext> a, ConstSpan<Plaintext> b) const {
        auto product = Mul(a, b);
        size_t vec_size = product.size();
        for (size_t i = 0; i < vec_size; i++) {
            *a[i] = product[i];
        }
    }

    std::vector<Ciphertext> Evaluator::Negate(ConstSpan<Ciphertext> a) const {
        std::vector<Plaintext> b_pt_vec;
        std::vector<Ciphertext> result(a.size());
        struct _paillier_key paillier_key;
        paillier_key.public_key.n = Tobin(pk_.n_);
        paillier_key.public_key.g = Tobin(pk_.g_);
        paillier_key.public_key.n_bitcount = pk_.n_.numBits();
        uint8_t *a_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits()*2)*a.size()];
        uint8_t *b_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits())*2*a.size()];
        uint8_t *out_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits()*2)*a.size()];
        uint32_t a_len = a.size()*BYTECOUNT(pk_.n_.numBits()*2);
        uint32_t vec_size = a.size();
        uint32_t output_len = 0;
        uint32_t a_offset = 0;
        uint32_t b_offset = 0;
        uint32_t out_offset = 0;


        for (auto item : a) {
            BN_bn2binpad(item->bn_,a_bytes+a_offset,BYTECOUNT(pk_.n_.numBits()*2));
            a_offset += BYTECOUNT(pk_.n_.numBits()*2);
        }

        uint8_t *r_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits())*a.size()];
        uint32_t r_offset = 0;
        uint8_t *ct_bytes = new uint8_t[BYTECOUNT(pk_.n_.numBits()*2)*a.size()];
        uint32_t ct_len =0;

        for (size_t i = 0; i < vec_size; i++) {
            Plaintext zero;
            zero.Set(0);
            b_pt_vec.push_back(zero);
        }

        for (auto item : b_pt_vec) {
            BN_bn2binpad(Plaintext::generateRandom(pk_.n_).bn_,r_bytes+r_offset,BYTECOUNT(pk_.n_.numBits()));
            r_offset += BYTECOUNT(pk_.n_.numBits());
            BN_bn2binpad(item.bn_,b_bytes+b_offset,BYTECOUNT(pk_.n_.numBits()));
            b_offset += BYTECOUNT(pk_.n_.numBits());
        }
        std::vector<uint8_t> b_flg;
        for (auto item : b_pt_vec) 
        {
            if(BN_is_negative(item.bn_))
            {
                b_flg.push_back(1);
            }
            else
            {
                b_flg.push_back(0);
            }
        }

        Runtime _runtime;
        if(_runtime.dev_connect())
        {
            _runtime.paillier_encrypt(b_bytes,r_bytes,b_flg,a.size(),paillier_key.public_key,ct_bytes,ct_len);
            _runtime.paillier_sub(ct_bytes,ct_len,a_bytes,a_len,vec_size,out_bytes,output_len,paillier_key.public_key);
            for (std::size_t i = 0; i < a.size(); i++) {
                BN_bin2bn(out_bytes+out_offset,BYTECOUNT(pk_.n_.numBits()*2),result[i].bn_);
                out_offset +=BYTECOUNT(pk_.n_.numBits()*2);
            }
        }
        _runtime.dev_close();
        delete [] a_bytes;
        delete [] b_bytes;
        delete [] out_bytes;
        delete [] r_bytes;
        delete [] ct_bytes;
        return result;
    }

    void Evaluator::NegateInplace(Span<Ciphertext> a) const {
        auto neg_a = Negate(a);
        size_t vec_size = neg_a.size();
        for (size_t i = 0; i < vec_size; i++) {
            *a[i] = neg_a[i];
        }
    }
}