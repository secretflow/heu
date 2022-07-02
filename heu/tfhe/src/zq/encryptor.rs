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

use super::key_generator::SecretKey;
use super::Ciphertext;

pub struct Encryptor<'a> {
    sk: &'a SecretKey, // concrete 当前版本还未实现公私钥，只支持对称加密

    encoder: concrete::Encoder,
}

// TFHE 加密原理 http://lab.algonics.net/slides_ac16/index-asiacrypt.html#/9
impl<'a> Encryptor<'a> {
    pub fn new(sk: &'a SecretKey) -> Result<Encryptor<'a>, CryptoAPIError> {
        let encoder = concrete::Encoder::new_rounding_context(
            0.,
            (1i64 << super::MAX_CLEARTEXT_BITS) as f64 - 1.,
            super::MAX_CLEARTEXT_BITS,
            super::ENCODING_PADDING,
        )?;
        Ok(Encryptor { sk, encoder })
    }

    pub fn encoder(&self) -> &concrete::Encoder {
        &self.encoder
    }

    pub fn encrypt(&self, m: u32) -> Result<Ciphertext, CryptoAPIError> {
        Ok(Ciphertext {
            lwe: concrete::LWE::encode_encrypt(&self.sk.lwe_key, m as f64, &self.encoder)?,
        })
    }
}
