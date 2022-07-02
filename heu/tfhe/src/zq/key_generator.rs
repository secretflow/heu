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

use std::path::Path;

const SECRET_KEY_FILE: &str = "secret_key";
const BOOTSTRAPPING_KEY_FILE: &str = "bootstrapping_key";

#[derive(Debug, PartialEq)]
pub struct PublicKey {
    pub bootstrapping_key: concrete::LWEBSK,
}

#[derive(Debug, PartialEq)]
pub struct SecretKey {
    pub lwe_key: concrete::LWESecretKey,
}

pub struct KeyGenerator {
    pub rlwe_setting: concrete::RLWEParams,
    pub lwe_setting: concrete::LWEParams,

    pub bs_base_log: usize,
    pub bs_level: usize,
}

impl KeyGenerator {
    pub fn new(
        rlwe_setting: concrete::RLWEParams,
        lwe_setting: concrete::LWEParams,
        bs_base_log: usize,
        bs_level: usize,
    ) -> KeyGenerator {
        KeyGenerator { rlwe_setting, lwe_setting, bs_base_log, bs_level }
    }

    // generate both sk and pk
    pub fn generate(&self) -> (SecretKey, PublicKey) {
        log::info!("Generate new key");
        let rlwe_sk = concrete::RLWESecretKey::new(&self.rlwe_setting);
        let lwe_sk = rlwe_sk.to_lwe_secret_key();
        let bsk = concrete::LWEBSK::new(&lwe_sk, &rlwe_sk, self.bs_base_log, self.bs_level);
        (SecretKey { lwe_key: lwe_sk }, PublicKey { bootstrapping_key: bsk })
    }

    pub fn generate_only_sk(&self) -> SecretKey {
        SecretKey { lwe_key: concrete::LWESecretKey::new(&self.lwe_setting) }
    }

    pub fn generate_with_cache(&self, cache_path: &str) -> (SecretKey, PublicKey) {
        let cache_path: String = cache_path.parse().unwrap();
        if cache_path.is_empty() {
            // cache not enabled
            return self.generate();
        }

        // get cache file path
        let prefix = format!(
            "{}/rlwe_{}_{}_bs_{}_{}",
            cache_path,
            self.rlwe_setting.polynomial_size,
            self.rlwe_setting.dimension,
            self.bs_base_log,
            self.bs_level
        );
        let sk_path = format!("{}/{}", prefix, SECRET_KEY_FILE);
        let bsk_path = format!("{}/{}", prefix, BOOTSTRAPPING_KEY_FILE);

        // check key_file exist
        if Path::new(&sk_path).exists() && Path::new(&bsk_path).exists() {
            log::info!("Load pk/sk from {}", prefix);
            return (
                SecretKey { lwe_key: concrete::LWESecretKey::load(&sk_path).unwrap() },
                PublicKey { bootstrapping_key: concrete::LWEBSK::load(&bsk_path) },
            );
        }

        // generate new key and save
        let create_parent_dir = |p| {
            let path = std::path::Path::new(p);
            let prefix = path.parent().unwrap();
            std::fs::create_dir_all(prefix).unwrap();
        };

        let keys = self.generate();
        log::info!("Save secret key to {}", sk_path);
        create_parent_dir(&sk_path);
        keys.0.lwe_key.save(&sk_path).unwrap();
        log::info!("Save public key to {}", bsk_path);
        create_parent_dir(&bsk_path);
        keys.1.bootstrapping_key.save(&bsk_path);
        return keys;
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Div;
    use std::time::Instant;

    use super::*;

    #[test]
    fn test_generate() {
        // case 1: test generate key
        let dir = tempfile::tempdir().unwrap();
        println!("temp dir is {}", dir.path().to_str().unwrap());
        let kg = KeyGenerator::new(concrete::RLWE80_256_1, concrete::LWE80_256, 5, 3);
        let start = Instant::now();
        kg.generate_with_cache(dir.path().to_str().unwrap());
        let t1 = start.elapsed();
        println!("Time for generate key is {} ms", t1.as_millis());
        // check file exist
        assert!(dir.path().join("rlwe_256_1_bs_5_3/secret_key").exists());
        assert!(dir.path().join("rlwe_256_1_bs_5_3/bootstrapping_key").exists());

        // case 2: test load key from cache
        let kg2 = KeyGenerator::new(concrete::RLWE80_256_1, concrete::LWE128_256, 5, 3);
        let start = Instant::now();
        kg2.generate_with_cache(dir.path().to_str().unwrap());
        let t2 = start.elapsed();
        println!("Time for generate key is {} ms (with cache)", t2.as_millis());
        assert!(t1.div(2) > t2, "t1 should be much larger than t2");
    }
}
