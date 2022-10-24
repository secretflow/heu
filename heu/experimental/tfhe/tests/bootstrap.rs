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

extern crate simple_logger;
extern crate torus;

use simple_logger::SimpleLogger;

use torus::zq::decryptor::Decryptor;
use torus::zq::encryptor::Encryptor;
use torus::zq::evaluator::Evaluator;
use torus::zq::key_generator::KeyGenerator;

// 超时，暂时禁用
// #[test]
fn test_bootstrap() {
    SimpleLogger::new().with_colors(true).init().unwrap();

    let kg = KeyGenerator::new(concrete::RLWE128_1024_1, concrete::LWE128_1024, 7, 3);
    let (sk, pk) = kg.generate(); // very slow
    let encryptor = Encryptor::new(&sk).unwrap();
    let decryptor = Decryptor::new(&sk);
    let evaluator = Evaluator::new_fully_evaluator(&pk).unwrap();

    let ct1 = encryptor.encrypt(10).unwrap();
    let ct2 = encryptor.encrypt(5).unwrap();
    let ct3 = evaluator.mul_and_bootstrap(&ct1, &ct2).unwrap();
    assert_eq!(decryptor.decrypt(&ct3).unwrap(), 50);
}
