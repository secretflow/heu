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

extern crate colored;
extern crate simple_logger;
extern crate torus;

use colored::Colorize;
use simple_logger::SimpleLogger;

use torus::measure_duration;
use torus::zq::decryptor::Decryptor;
use torus::zq::encryptor::Encryptor;
use torus::zq::evaluator::Evaluator;
use torus::zq::key_generator::KeyGenerator;

fn main() -> Result<(), concrete::CryptoAPIError> {
    SimpleLogger::new().with_colors(true).init().unwrap();

    // create an encoder
    let kg = KeyGenerator::new(concrete::RLWE128_1024_1, concrete::LWE128_1024, 5, 3);
    measure_duration!("Generate pk/sk", {
        let (sk, pk) = kg.generate_with_cache("./cache");
    });

    let encryptor = Encryptor::new(&sk)?;
    let decryptor = Decryptor::new(&sk);
    let evaluator = Evaluator::new_fully_evaluator(&pk)?;

    // encode and encrypt
    let c1 = encryptor.encrypt(11)?;

    // bootstrap
    let c2 = evaluator.bootstrap_with_function(&c1, |x| x * x)?;

    // decrypt
    let output = decryptor.decrypt(&c2)?;
    println!("before bootstrap: {}, after bootstrap: {}", 11, output);
    Ok(())
}
