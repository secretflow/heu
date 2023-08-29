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
extern crate concrete;
extern crate log;
extern crate simple_logger;
extern crate torus;

use colored::Colorize;
use simple_logger::SimpleLogger;

use torus::measure_duration;
use torus::zq::decryptor::Decryptor;
use torus::zq::encryptor::Encryptor;
use torus::zq::evaluator::Evaluator;
use torus::zq::key_generator::KeyGenerator;
use torus::zq::Ciphertext;

const TEST_SIZE: usize = 10000;

#[test]
fn test_add() {
    SimpleLogger::new().with_colors(true).init().unwrap();

    let kg = KeyGenerator::new(concrete::RLWE128_2048_1, concrete::LWE128_2048, 5, 3);
    measure_duration!("Generate sk", {
        let sk = kg.generate_only_sk();
    });

    let encryptor = Encryptor::new(&sk).unwrap();
    let decryptor = Decryptor::new(&sk);
    let evaluator = Evaluator::new_levelled_evaluator().unwrap();

    let mut cts: Vec<Ciphertext> = Vec::new();

    measure_duration!("Encrypt", {
        for i in 0usize..TEST_SIZE {
            cts.push(encryptor.encrypt(i as u32).unwrap());
        }
    });

    // add
    let mut res = encryptor.encrypt(0).unwrap();
    measure_duration!("Add", {
        for i in 0..TEST_SIZE {
            evaluator.add_inplace(&mut res, &cts[i]).unwrap();
        }
    });
    assert_eq!(decryptor.decrypt(&res).unwrap(), (TEST_SIZE * (TEST_SIZE - 1) / 2) as u32);

    // mul and add
    let mut res = encryptor.encrypt(0).unwrap();
    measure_duration!("Add", {
        for i in 0..TEST_SIZE {
            evaluator.mul_u32_inplace(&mut cts[i], 101).unwrap();
            evaluator.add_inplace(&mut res, &cts[i]).unwrap();
        }
    });

    assert_eq!(decryptor.decrypt(&res).unwrap(), (TEST_SIZE * 101 * (TEST_SIZE - 1) / 2) as u32);
}
