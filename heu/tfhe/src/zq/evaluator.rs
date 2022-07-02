// Copyright 2022 Ant Group Co., Ltd.
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

use concrete::CryptoAPIError;

use super::key_generator::PublicKey;
use super::Ciphertext;

pub struct Evaluator<'a> {
    pk: Option<&'a PublicKey>,

    encoder: concrete::Encoder,
}

impl<'a> Evaluator<'a> {
    pub fn new_levelled_evaluator() -> Result<Evaluator<'a>, CryptoAPIError> {
        let encoder = concrete::Encoder::new_rounding_context(
            0.,
            (1i64 << super::MAX_CLEARTEXT_BITS) as f64 - 1.,
            super::MAX_CLEARTEXT_BITS,
            super::ENCODING_PADDING,
        )?;
        Ok(Evaluator { pk: None, encoder })
    }

    pub fn new_fully_evaluator(pk: &'a PublicKey) -> Result<Evaluator<'a>, CryptoAPIError> {
        let encoder = concrete::Encoder::new_rounding_context(
            0.,
            (1i64 << super::MAX_CLEARTEXT_BITS) as f64 - 1.,
            super::MAX_CLEARTEXT_BITS,
            super::ENCODING_PADDING,
        )?;
        Ok(Evaluator { pk: Some(pk), encoder })
    }

    pub fn add(&self, a: &Ciphertext, b: &Ciphertext) -> Result<Ciphertext, CryptoAPIError> {
        Ok(Ciphertext { lwe: a.lwe.add_with_new_min(&b.lwe, 0.)? })
    }

    pub fn add_inplace(&self, a: &mut Ciphertext, b: &Ciphertext) -> Result<(), CryptoAPIError> {
        a.lwe.add_with_new_min_inplace(&b.lwe, 0.)
    }

    pub fn add_u32(&self, a: &Ciphertext, b: u32) -> Result<Ciphertext, CryptoAPIError> {
        Ok(Ciphertext { lwe: a.lwe.add_constant_static_encoder(b as f64)? })
    }

    pub fn add_u32_inplace(&self, a: &mut Ciphertext, b: u32) -> Result<(), CryptoAPIError> {
        a.lwe.add_constant_static_encoder_inplace(b as f64)
    }

    pub fn mul_u32(&self, a: &Ciphertext, b: u32) -> Result<Ciphertext, CryptoAPIError> {
        Ok(Ciphertext { lwe: a.lwe.mul_constant_static_encoder(b as i32)? })
    }

    pub fn mul_u32_inplace(&self, a: &mut Ciphertext, b: u32) -> Result<(), CryptoAPIError> {
        a.lwe.mul_constant_static_encoder_inplace(b as i32)
    }

    pub fn bootstrap_with_function<F>(
        &self,
        a: &Ciphertext,
        f: F,
    ) -> Result<Ciphertext, CryptoAPIError>
    where
        F: Fn(f64) -> f64,
    {
        Ok(Ciphertext {
            lwe: a.lwe.bootstrap_with_function(
                &self.pk.unwrap().bootstrapping_key,
                f,
                &self.encoder,
            )?,
        })
    }

    // 近似计算 mul
    // 当前的算法下，两个 Torus 无法直接相乘，必须通过构造查找多项式（LUT）实现
    pub fn mul_and_bootstrap(
        &self,
        a: &Ciphertext,
        b: &Ciphertext,
    ) -> Result<Ciphertext, CryptoAPIError> {
        Ok(Ciphertext {
            lwe: a.lwe.mul_from_bootstrap(&b.lwe, &self.pk.unwrap().bootstrapping_key)?,
        })
    }

    // relu(x)
    // 因为当前仅支持 unsigned 数，所以 relu 没什么作用
    pub fn relu(&self, x: &mut Ciphertext) -> Result<Ciphertext, CryptoAPIError> {
        self.bootstrap_with_function(x, |x| f64::max(x, 0.))
    }
}
