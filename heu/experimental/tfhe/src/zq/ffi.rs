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

extern crate cxx;

use super::decryptor::Decryptor;
use super::encryptor::Encryptor;
use super::evaluator::Evaluator;
use super::key_generator::{KeyGenerator, PublicKey, SecretKey};
use super::Ciphertext;

//// KeyGen ///
struct CxxKeyGenerator {
    key_generator: KeyGenerator,
}

fn new_cxx_key_generator(
    security: ffi::SecurityParams,
    bs_base_log: usize,
    bs_level: usize,
) -> Box<CxxKeyGenerator> {
    Box::new(CxxKeyGenerator {
        key_generator: KeyGenerator::new(
            concrete::RLWEParams {
                dimension: 1,
                polynomial_size: security.dimension,
                log2_std_dev: security.log2_std_dev,
            },
            concrete::LWEParams {
                dimension: security.dimension,
                log2_std_dev: security.log2_std_dev,
            },
            bs_base_log,
            bs_level,
        ),
    })
}

impl CxxKeyGenerator {
    pub fn generate(&self) -> ffi::TFheKeys {
        let (sk, pk) = self.key_generator.generate();
        ffi::TFheKeys { public_key: Box::new(pk), secret_key: Box::new(sk) }
    }

    pub fn generate_with_cache(&self, cache_path: &str) -> ffi::TFheKeys {
        let (sk, pk) = self.key_generator.generate_with_cache(cache_path);
        ffi::TFheKeys { public_key: Box::new(pk), secret_key: Box::new(sk) }
    }

    pub fn generate_only_sk(&self) -> Box<SecretKey> {
        let sk = self.key_generator.generate_only_sk();
        Box::new(sk)
    }
}

//// 加密 ////
struct CxxEncryptor<'a> {
    encryptor: Encryptor<'a>,
}

fn new_cxx_encryptor(sk: &SecretKey) -> Box<CxxEncryptor> {
    Box::new(CxxEncryptor { encryptor: Encryptor::new(sk).unwrap() })
}

impl<'a> CxxEncryptor<'a> {
    fn encrypt(&self, m: u32) -> Box<Ciphertext> {
        // Box::new 性能不高，待后续优化
        Box::new(self.encryptor.encrypt(m).unwrap())
    }
}

//// 解密 ////

struct CxxDecryptor<'a> {
    decryptor: Decryptor<'a>,
}

fn new_cxx_decryptor(sk: &SecretKey) -> Box<CxxDecryptor> {
    Box::new(CxxDecryptor { decryptor: Decryptor::new(sk) })
}

impl<'a> CxxDecryptor<'a> {
    pub fn decrypt(&self, a: &Ciphertext) -> u32 {
        self.decryptor.decrypt(a).unwrap()
    }
}

//// 运算 ////

struct CxxEvaluator<'a> {
    evaluator: Evaluator<'a>,
}

fn cxx_new_leveled_evaluator() -> Box<CxxEvaluator<'static>> {
    Box::new(CxxEvaluator { evaluator: Evaluator::new_levelled_evaluator().unwrap() })
}

fn cxx_new_full_evaluator(pk: &PublicKey) -> Box<CxxEvaluator> {
    Box::new(CxxEvaluator { evaluator: Evaluator::new_fully_evaluator(pk).unwrap() })
}

impl<'a> CxxEvaluator<'a> {
    // fast operations //

    pub fn add(&self, a: &Ciphertext, b: &Ciphertext) -> Box<Ciphertext> {
        Box::new(self.evaluator.add(a, b).unwrap())
    }

    pub fn add_inplace(&self, a: &mut Ciphertext, b: &Ciphertext) {
        self.evaluator.add_inplace(a, b).unwrap()
    }

    pub fn add_u32(&self, a: &Ciphertext, b: u32) -> Box<Ciphertext> {
        Box::new(self.evaluator.add_u32(a, b).unwrap())
    }

    pub fn add_u32_inplace(&self, a: &mut Ciphertext, b: u32) {
        self.evaluator.add_u32_inplace(a, b).unwrap()
    }

    pub fn mul_u32(&self, a: &Ciphertext, b: u32) -> Box<Ciphertext> {
        Box::new(self.evaluator.mul_u32(a, b).unwrap())
    }

    pub fn mul_u32_inplace(&self, a: &mut Ciphertext, b: u32) {
        self.evaluator.mul_u32_inplace(a, b).unwrap()
    }

    // fhe operations, need bootstrap key //

    pub fn mul_and_bootstrap(&self, a: &Ciphertext, b: &Ciphertext) -> Box<Ciphertext> {
        Box::new(self.evaluator.mul_and_bootstrap(a, b).unwrap())
    }
}

#[cxx::bridge(namespace = "heu::expt::tfhe")]
mod ffi {
    pub(crate) struct TFheKeys {
        public_key: Box<PublicKey>,
        secret_key: Box<SecretKey>,
    }

    pub(crate) struct SecurityParams {
        pub dimension: usize,
        pub log2_std_dev: i32,
    }

    extern "Rust" {
        type CxxKeyGenerator;
        type PublicKey;
        type SecretKey;

        type Ciphertext;
        type CxxEncryptor<'a>;
        type CxxDecryptor<'a>;

        type CxxEvaluator<'a>;

        //// KeyGen ////
        fn new_cxx_key_generator(
            security: SecurityParams,
            bs_base_log: usize,
            bs_level: usize,
        ) -> Box<CxxKeyGenerator>;
        unsafe fn generate(self: &CxxKeyGenerator) -> TFheKeys;
        unsafe fn generate_with_cache(self: &CxxKeyGenerator, cache_path: &str) -> TFheKeys;
        unsafe fn generate_only_sk(self: &CxxKeyGenerator) -> Box<SecretKey>;

        //// 加密 ////
        fn new_cxx_encryptor(sk: &SecretKey) -> Box<CxxEncryptor>;
        unsafe fn encrypt<'a>(self: &'a CxxEncryptor<'a>, m: u32) -> Box<Ciphertext>;

        //// 解密 ////
        fn new_cxx_decryptor(sk: &SecretKey) -> Box<CxxDecryptor>;
        unsafe fn decrypt<'a>(self: &'a CxxDecryptor<'a>, a: &Ciphertext) -> u32;

        //// 运算 ////
        fn cxx_new_leveled_evaluator() -> Box<CxxEvaluator<'static>>;
        fn cxx_new_full_evaluator(pk: &PublicKey) -> Box<CxxEvaluator>;

        unsafe fn add<'a>(
            self: &'a CxxEvaluator<'a>,
            a: &Ciphertext,
            b: &Ciphertext,
        ) -> Box<Ciphertext>;
        unsafe fn add_inplace<'a>(self: &'a CxxEvaluator<'a>, a: &mut Ciphertext, b: &Ciphertext);
        unsafe fn add_u32<'a>(
            self: &'a CxxEvaluator<'a>,
            a: &Ciphertext,
            b: u32,
        ) -> Box<Ciphertext>;
        unsafe fn add_u32_inplace<'a>(self: &'a CxxEvaluator<'a>, a: &mut Ciphertext, b: u32);
        unsafe fn mul_u32<'a>(
            self: &'a CxxEvaluator<'a>,
            a: &Ciphertext,
            b: u32,
        ) -> Box<Ciphertext>;
        unsafe fn mul_u32_inplace<'a>(self: &'a CxxEvaluator<'a>, a: &mut Ciphertext, b: u32);

        unsafe fn mul_and_bootstrap<'a>(
            self: &'a CxxEvaluator<'a>,
            a: &Ciphertext,
            b: &Ciphertext,
        ) -> Box<Ciphertext>;
    }
}
