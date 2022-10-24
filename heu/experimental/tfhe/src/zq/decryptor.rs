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

pub struct Decryptor<'a> {
    sk: &'a SecretKey,
}

impl<'a> Decryptor<'a> {
    pub fn new(sk: &'a SecretKey) -> Decryptor<'a> {
        Decryptor { sk }
    }

    pub fn decrypt(&self, a: &Ciphertext) -> Result<u32, CryptoAPIError> {
        let p = a.lwe.decrypt_decode_round(&self.sk.lwe_key)?;
        Ok(p as u32)
    }
}
